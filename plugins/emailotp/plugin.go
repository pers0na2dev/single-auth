package emailotp

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	defaultOTPLength       = 6
	defaultExpiry          = 5 * time.Minute
	defaultAllowedAttempts = 3
	defaultRateWindow      = int64(60)
	defaultRateMax         = int64(3)
	defaultSecret          = "single-auth-secret-123456789"
)

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

type plugin struct {
	options Options
	clock   func() time.Time
	random  io.Reader
	locks   [64]sync.Mutex
	warnOld sync.Once
}

// New validates and snapshots a single-auth email-otp plugin.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	if implementation.options.OverrideDefaultEmailVerification {
		installer := implementation.options.Runtime.InstallDefaultVerification
		if installer == nil {
			return engine.Plugin{}, fmt.Errorf("emailotp: OverrideDefaultEmailVerification requires Runtime.InstallDefaultVerification because engine.Plugin has no init-option mutation hook")
		}
		if err := installer(implementation.defaultVerificationHandler); err != nil {
			return engine.Plugin{}, fmt.Errorf("emailotp: install default email verification: %w", err)
		}
	}

	return engine.Plugin{
		ID:      "email-otp",
		Version: Version,
		Schema:  Schema(),
		Endpoints: []engine.Endpoint{
			{Name: "sendVerificationOTP", Path: "/email-otp/send-verification-otp", Methods: []string{"POST"}, OperationID: "sendEmailVerificationOTP", Handler: implementation.sendVerificationOTP},
			{Name: "createVerificationOTP", ServerOnly: true, Methods: []string{"POST"}, OperationID: "createEmailVerificationOTP", Handler: implementation.createVerificationOTP},
			{Name: "getVerificationOTP", ServerOnly: true, Methods: []string{"GET"}, OperationID: "getEmailVerificationOTP", Handler: implementation.getVerificationOTP},
			{Name: "checkVerificationOTP", Path: "/email-otp/check-verification-otp", Methods: []string{"POST"}, OperationID: "verifyEmailWithOTP", Handler: implementation.checkVerificationOTP},
			{Name: "verifyEmailOTP", Path: "/email-otp/verify-email", Methods: []string{"POST"}, Handler: implementation.verifyEmailOTP},
			{Name: "signInEmailOTP", Path: "/sign-in/email-otp", Methods: []string{"POST"}, OperationID: "signInWithEmailOTP", Handler: implementation.signInEmailOTP},
			{Name: "requestPasswordResetEmailOTP", Path: "/email-otp/request-password-reset", Methods: []string{"POST"}, OperationID: "requestPasswordResetWithEmailOTP", Handler: implementation.requestPasswordResetEmailOTP},
			{Name: "forgetPasswordEmailOTP", Path: "/forget-password/email-otp", Methods: []string{"POST"}, OperationID: "forgetPasswordWithEmailOTP", Handler: implementation.forgetPasswordEmailOTP},
			{Name: "resetPasswordEmailOTP", Path: "/email-otp/reset-password", Methods: []string{"POST"}, OperationID: "resetPasswordWithEmailOTP", Handler: implementation.resetPasswordEmailOTP},
			{Name: "requestEmailChangeEmailOTP", Path: "/email-otp/request-email-change", Methods: []string{"POST"}, OperationID: "requestEmailChangeWithEmailOTP", Handler: implementation.requestEmailChangeEmailOTP},
			{Name: "changeEmailEmailOTP", Path: "/email-otp/change-email", Methods: []string{"POST"}, OperationID: "changeEmailWithEmailOTP", Handler: implementation.changeEmailEmailOTP},
		},
		Middleware: []engine.Middleware{
			{
				Name: "email-otp-send-csrf", Path: "/email-otp/send-verification-otp",
				Handler: implementation.sendCSRFMiddleware,
			},
			{
				Name: "email-otp-request-email-change-sensitive-session", Path: "/email-otp/request-email-change",
				Handler: implementation.sensitiveSessionMiddleware,
			},
			{
				Name: "email-otp-change-email-sensitive-session", Path: "/email-otp/change-email",
				Handler: implementation.sensitiveSessionMiddleware,
			},
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name: "email-otp-send-on-sign-up", Matcher: implementation.signUpHookMatcher,
			Handler: implementation.sendOnSignUp,
		}}},
		RateLimit:  implementation.rateLimitRules(),
		ErrorCodes: pluginErrorCodes(),
	}, nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

// NewFactory binds email-otp to the final root adapter, session/cookie
// lifecycle, hooks, password configuration, and security policy.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "email-otp" }

func (*rootFactory) Schema() (storage.Schema, error) { return Schema(), nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.Secret = host.Secret
	options.Runtime.ResolveSession = func(ctx *engine.Context, resolution SessionResolution) (*SessionState, error) {
		mode := singleauth.PluginSessionOptional
		if resolution == SessionAuthoritative {
			mode = singleauth.PluginSessionFresh
		}
		state, err := host.ResolveSession(ctx, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.IssueSession = func(ctx *engine.Context, user storage.Record) (*SessionState, error) {
		userID, ok := recordString(user, "id")
		if !ok || userID == "" {
			return nil, fmt.Errorf("emailotp: user id is invalid")
		}
		state, err := host.IssueSession(ctx, userID, false)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.RefreshSession = func(ctx *engine.Context, state SessionState) error {
		return host.RefreshSession(ctx, singleauth.PluginSessionState{
			Session: state.Session, User: state.User,
		}, false)
	}
	options.Runtime.CreateUser = func(ctx *engine.Context, input CreateUserInput) (storage.Record, error) {
		record := cloneRecord(input.Additional)
		if record == nil {
			record = storage.Record{}
		}
		record["email"] = input.Email
		record["emailVerified"] = true
		record["name"] = input.Name
		if input.Image != nil {
			record["image"] = *input.Image
		}
		return host.CreateUser(ctx, record)
	}
	options.Runtime.ParseUserInput = func(ctx *engine.Context, input map[string]any) (storage.Record, error) {
		filtered := make(map[string]any, len(input))
		for key, value := range input {
			filtered[key] = value
		}
		// single-auth's create parser applies a declared default before its
		// input:false rejection. Consequently a supplied value for an
		// input:false field with a default is ignored and the default wins.
		// The generic root parser also serves update endpoints, so preserve its
		// stricter behavior there and adapt only this create-only plugin path.
		if userSchema, ok := host.Options.Schema.Models["user"]; ok {
			for name, attribute := range userSchema.Fields {
				if !attribute.IsInput() && attribute.DefaultValue != nil {
					delete(filtered, name)
				}
			}
		}
		return host.ParseUserInput(ctx, filtered)
	}
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.RevokeUnproven = host.RevokeUnproven
	options.Runtime.RevokeSessions = host.RevokeSessions
	options.Runtime.BeforeEmailVerification = host.BeforeEmailVerification
	options.Runtime.AfterEmailVerification = host.AfterEmailVerification
	options.Runtime.RunInBackground = host.RunBackground
	options.Runtime.ValidateSendRequest = host.ValidateFormCSRF
	if options.Runtime.ValidateSendRequest == nil {
		options.Runtime.ValidateSendRequest = host.ValidateCSRF
	}
	options.Runtime.InstallDefaultVerification = func(handler DefaultVerificationHandler) error {
		return host.InstallDefaultEmailVerification(func(ctx context.Context, email string) error {
			return handler(ctx, email)
		})
	}
	options.Runtime.CreateVerification = func(ctx context.Context, identifier, value string, expiresAt time.Time) (storage.Record, error) {
		return host.CreateVerification(ctx, identifier, value, expiresAt)
	}
	options.Runtime.FindVerification = host.PeekVerification
	if options.Runtime.FindVerification == nil {
		options.Runtime.FindVerification = host.FindVerification
	}
	options.Runtime.ConsumeVerification = func(ctx context.Context, identifier string) (storage.Record, error) {
		return host.ConsumeVerification(ctx, identifier)
	}
	options.Runtime.UpdateVerification = func(ctx context.Context, identifier string, update storage.Record) error {
		return host.UpdateVerification(ctx, identifier, update)
	}
	options.Runtime.DeleteVerification = func(ctx context.Context, identifier string) error {
		return host.DeleteVerification(ctx, identifier)
	}
	if host.Logger != nil {
		options.Runtime.Warn = func(message string) { host.Logger.Warn(message) }
	}
	options.Password.MinLength = host.Options.EmailAndPassword.MinPasswordLength
	options.Password.MaxLength = host.Options.EmailAndPassword.MaxPasswordLength
	options.Password.Hash = host.Options.EmailAndPassword.Password.Hash
	options.Password.HashWithContext = host.HashPassword
	options.Password.OnReset = host.OnPasswordReset
	options.Password.RevokeSessions = host.Options.EmailAndPassword.RevokeSessionsOnReset
	options.AutoSignInAfterVerification = host.Options.EmailVerification.AutoSignInAfterVerification
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	if input.Runtime.Adapter == nil {
		return nil, fmt.Errorf("emailotp: Runtime.Adapter is required")
	}
	if input.SendVerificationOTP == nil {
		return nil, fmt.Errorf("emailotp: SendVerificationOTP is required")
	}
	if input.Runtime.ResolveSession == nil {
		return nil, fmt.Errorf("emailotp: Runtime.ResolveSession is required")
	}
	if input.Runtime.IssueSession == nil {
		return nil, fmt.Errorf("emailotp: Runtime.IssueSession is required")
	}
	if input.Runtime.RefreshSession == nil {
		return nil, fmt.Errorf("emailotp: Runtime.RefreshSession is required")
	}
	options := input
	options.TrustedOrigins = append([]string(nil), input.TrustedOrigins...)
	if options.OTPLength == 0 {
		options.OTPLength = defaultOTPLength
	}
	if options.OTPLength < 1 {
		return nil, fmt.Errorf("emailotp: OTPLength must be positive")
	}
	if options.ExpiresIn == 0 {
		options.ExpiresIn = defaultExpiry
	}
	if options.AllowedAttempts == 0 {
		options.AllowedAttempts = defaultAllowedAttempts
	}
	if options.ResendStrategy == "" {
		options.ResendStrategy = ResendRotate
	}
	if options.ResendStrategy != ResendRotate && options.ResendStrategy != ResendReuse {
		return nil, fmt.Errorf("emailotp: invalid ResendStrategy %q", options.ResendStrategy)
	}
	if options.Storage.Mode == "" {
		options.Storage.Mode = StorePlain
	}
	if err := validateOTPStorage(options.Storage); err != nil {
		return nil, err
	}
	if options.Password.MinLength == 0 {
		options.Password.MinLength = 8
	}
	if options.Password.MaxLength == 0 {
		options.Password.MaxLength = 128
	}
	if options.Password.MinLength < 0 || options.Password.MaxLength < options.Password.MinLength {
		return nil, fmt.Errorf("emailotp: invalid password length bounds")
	}
	if options.Password.Hash == nil {
		options.Password.Hash = baCrypto.HashPassword
	}
	if options.Runtime.Secret == "" {
		options.Runtime.Secret = defaultSecret
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	randomSource := options.Runtime.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &plugin{options: options, clock: clock, random: &lockedReader{r: randomSource}}, nil
}

func validateOTPStorage(options OTPStorage) error {
	customHash := options.CustomHash != nil
	customEncryption := options.CustomEncrypt != nil || options.CustomDecrypt != nil
	if customHash && customEncryption {
		return fmt.Errorf("emailotp: custom hash and encryption are mutually exclusive")
	}
	if customEncryption && (options.CustomEncrypt == nil || options.CustomDecrypt == nil) {
		return fmt.Errorf("emailotp: custom encryption requires both encrypt and decrypt")
	}
	if (customHash || customEncryption) && options.Mode != StorePlain {
		return fmt.Errorf("emailotp: custom transforms cannot be combined with StoreMode %q", options.Mode)
	}
	switch options.Mode {
	case StorePlain, StoreHashed, StoreEncrypted:
		return nil
	default:
		return fmt.Errorf("emailotp: invalid StoreMode %q", options.Mode)
	}
}

func (p *plugin) rateLimitRules() []ratelimit.MatcherRule {
	window := p.options.RateLimit.Window
	if window == 0 {
		window = defaultRateWindow
	}
	maximum := p.options.RateLimit.Max
	if maximum == 0 {
		maximum = defaultRateMax
	}
	paths := []string{
		"/email-otp/send-verification-otp",
		"/email-otp/check-verification-otp",
		"/email-otp/verify-email",
		"/sign-in/email-otp",
		"/email-otp/request-password-reset",
		"/email-otp/reset-password",
		"/forget-password/email-otp",
		"/email-otp/request-email-change",
		"/email-otp/change-email",
	}
	rules := make([]ratelimit.MatcherRule, 0, len(paths))
	for _, configuredPath := range paths {
		path := configuredPath
		rules = append(rules, ratelimit.MatcherRule{
			Match: func(candidate string) bool { return candidate == path },
			Rule:  ratelimit.Rule{Window: window, Max: maximum},
		})
	}
	return rules
}
