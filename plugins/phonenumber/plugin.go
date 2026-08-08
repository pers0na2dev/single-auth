package phonenumber

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
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
	schema  storage.Schema
	clock   func() time.Time
	random  io.Reader
	locks   [64]sync.Mutex
}

type rootFactory struct{ options Options }

// NewFactory binds phone-number to the final root adapter, password chain,
// session/cookie lifecycle, verification storage, and database hooks.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

func (*rootFactory) PluginID() string { return "phone-number" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return Schema(factory.options)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.ResolveSession = func(ctx *engine.Context) (*SessionState, error) {
		state, err := host.ResolveSession(ctx, singleauth.PluginSessionOptional)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.IssueSession = func(ctx *engine.Context, userID string, dontRemember bool) (*SessionState, error) {
		state, err := host.IssueSession(ctx, userID, dontRemember)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.CreateUser = host.CreateUser
	options.Runtime.ParseUserInput = host.ParseUserInput
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.HashPassword = func(ctx *engine.Context, password string) (string, error) {
		return host.HashPassword(ctx, password)
	}
	options.Runtime.VerifyPassword = host.Options.EmailAndPassword.Password.Verify
	options.Runtime.PasswordMinLength = host.Options.EmailAndPassword.MinPasswordLength
	options.Runtime.PasswordMaxLength = host.Options.EmailAndPassword.MaxPasswordLength
	options.Runtime.OnPasswordReset = host.OnPasswordReset
	options.Runtime.RevokeSessions = host.RevokeSessions
	options.Runtime.RevokeSessionsOnPasswordReset = host.Options.EmailAndPassword.RevokeSessionsOnReset
	options.Runtime.RunBackground = host.RunBackground
	options.Runtime.BackgroundTasksEnabled = host.Options.RunBackground != nil
	options.Runtime.CreateVerification = host.CreateVerification
	options.Runtime.FindVerification = host.FindVerification
	options.Runtime.ConsumeVerification = host.ConsumeVerification
	options.Runtime.DeleteVerification = host.DeleteVerification
	options.Runtime.RegisterDatabaseHooks = host.RegisterDatabaseHooks
	if host.Logger != nil {
		options.Runtime.Warn = func(message string) { host.Logger.Warn(message) }
		options.Runtime.LogError = func(message string, err error) {
			host.Logger.Error(message, err)
		}
	}
	// PeekVerification is an additive host primitive introduced for exact OTP
	// expiry classification. Keep the assignment isolated so older host builds
	// can be supported by the direct-adapter fallback in peekVerification.
	options.Runtime.PeekVerification = host.PeekVerification
	return New(options)
}

// New validates and snapshots a standalone phone-number plugin.
func New(input Options) (engine.Plugin, error) {
	implementation, err := compile(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	if err := implementation.options.Runtime.RegisterDatabaseHooks(implementation.databaseHooks()); err != nil {
		return engine.Plugin{}, fmt.Errorf("phonenumber: register database hooks: %w", err)
	}
	return implementation.descriptor(), nil
}

func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

func compile(input Options) (*plugin, error) {
	options := snapshotOptions(input)
	if options.Runtime.Adapter == nil {
		return nil, fmt.Errorf("phonenumber: Runtime.Adapter is required")
	}
	if options.Runtime.IssueSession == nil {
		return nil, fmt.Errorf("phonenumber: Runtime.IssueSession is required")
	}
	if options.Runtime.ResolveSession == nil {
		return nil, fmt.Errorf("phonenumber: Runtime.ResolveSession is required")
	}
	if options.Runtime.RegisterDatabaseHooks == nil {
		return nil, fmt.Errorf("phonenumber: Runtime.RegisterDatabaseHooks is required")
	}
	if options.OTPLength == 0 {
		options.OTPLength = defaultOTPLength
	}
	if options.OTPLength < 1 {
		return nil, fmt.Errorf("phonenumber: OTPLength must be positive")
	}
	if options.ExpiresIn == 0 {
		options.ExpiresIn = defaultExpiry
	}
	if options.AllowedAttempts == 0 {
		options.AllowedAttempts = defaultAllowedAttempts
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Random == nil {
		options.Runtime.Random = rand.Reader
	}
	if options.Runtime.HashPassword == nil {
		options.Runtime.HashPassword = func(_ *engine.Context, password string) (string, error) {
			return baCrypto.HashPassword(password)
		}
	}
	if options.Runtime.VerifyPassword == nil {
		options.Runtime.VerifyPassword = baCrypto.VerifyPassword
	}
	if options.Runtime.PasswordMinLength == 0 {
		options.Runtime.PasswordMinLength = 8
	}
	if options.Runtime.PasswordMaxLength == 0 {
		options.Runtime.PasswordMaxLength = 128
	}
	if options.Runtime.SerializeUser == nil {
		options.Runtime.SerializeUser = func(user storage.Record) any { return cloneRecord(user) }
	}
	if options.Runtime.RunBackground == nil {
		options.Runtime.RunBackground = func(ctx context.Context, work func(context.Context) error) error {
			return work(ctx)
		}
	}
	if options.Runtime.CreateUser == nil {
		options.Runtime.CreateUser = func(ctx *engine.Context, input storage.Record) (storage.Record, error) {
			return options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "user", Data: input})
		}
	}
	if options.Runtime.ParseUserInput == nil {
		options.Runtime.ParseUserInput = func(*engine.Context, map[string]any) (storage.Record, error) {
			return storage.Record{}, nil
		}
	}
	if options.Runtime.OnPasswordReset == nil {
		options.Runtime.OnPasswordReset = func(context.Context, *engine.Context, storage.Record) error { return nil }
	}
	if options.Runtime.RevokeSessions == nil {
		options.Runtime.RevokeSessions = func(ctx *engine.Context, userID string) error {
			_, err := options.Runtime.Adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
				Model: "session", Where: []storage.Where{{Field: "userId", Value: userID}},
			})
			return err
		}
	}
	if options.SignUpOnVerification != nil && options.SignUpOnVerification.GetTempEmail == nil {
		return nil, fmt.Errorf("phonenumber: SignUpOnVerification.GetTempEmail is required")
	}
	schema, err := schemaFor(options)
	if err != nil {
		return nil, err
	}
	clock := options.Runtime.Clock
	return &plugin{
		options: options, schema: schema, clock: clock,
		random: &lockedReader{r: options.Runtime.Random},
	}, nil
}

func snapshotOptions(source Options) Options {
	result := source
	if source.SignUpOnVerification != nil {
		copy := *source.SignUpOnVerification
		result.SignUpOnVerification = &copy
	}
	return result
}

func (p *plugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID: "phone-number", Version: Version, Schema: p.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "signInPhoneNumber", Path: "/sign-in/phone-number", Methods: []string{"POST"}, OperationID: "signInPhoneNumber", Handler: p.signInPhoneNumber},
			{Name: "sendPhoneNumberOTP", Path: "/phone-number/send-otp", Methods: []string{"POST"}, OperationID: "sendPhoneNumberOTP", Handler: p.sendPhoneNumberOTP},
			{Name: "verifyPhoneNumber", Path: "/phone-number/verify", Methods: []string{"POST"}, OperationID: "verifyPhoneNumber", Handler: p.verifyPhoneNumber},
			{Name: "requestPasswordResetPhoneNumber", Path: "/phone-number/request-password-reset", Methods: []string{"POST"}, OperationID: "requestPasswordResetPhoneNumber", Handler: p.requestPasswordResetPhoneNumber},
			{Name: "resetPasswordPhoneNumber", Path: "/phone-number/reset-password", Methods: []string{"POST"}, OperationID: "resetPasswordPhoneNumber", Handler: p.resetPasswordPhoneNumber},
		},
		Hooks: engine.Hooks{Before: []engine.BeforeHook{{
			Name: "phone-number-block-direct-update", Matcher: p.matchesForbiddenPhoneUpdate,
			Handler: p.blockForbiddenPhoneUpdate,
		}}},
		RateLimit: []ratelimit.MatcherRule{{
			Match: func(path string) bool { return strings.HasPrefix(path, "/phone-number") },
			Rule:  ratelimit.Rule{Window: 60, Max: 10},
		}},
		ErrorCodes: pluginErrorCodes(),
	}
}
