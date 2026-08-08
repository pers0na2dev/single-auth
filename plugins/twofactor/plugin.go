package twofactor

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
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
}

type rootFactory struct{ options Options }

func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

func (*rootFactory) PluginID() string { return "two-factor" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return Schema(factory.options)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.Secret = host.Secret
	options.Runtime.AppName = host.Options.AppName
	options.Runtime.EncryptSecret = host.EncryptSecret
	options.Runtime.DecryptSecret = host.DecryptSecret
	options.Runtime.ResolveSession = func(ctx *engine.Context, mode singleauth.PluginSessionMode) (*SessionState, error) {
		state, err := host.ResolveSession(ctx, mode)
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
	options.Runtime.DeleteSession = host.DeleteSession
	options.Runtime.NewSession = func(ctx *engine.Context) *SessionState {
		state := host.NewSession(ctx)
		if state == nil {
			return nil
		}
		return &SessionState{Session: state.Session, User: state.User}
	}
	options.Runtime.SetNewSession = func(ctx *engine.Context, state *SessionState) {
		if state == nil {
			host.SetNewSession(ctx, nil)
			return
		}
		host.SetNewSession(ctx, &singleauth.PluginSessionState{Session: state.Session, User: state.User})
	}
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.SessionCookie = func(request contract.Request) Cookie {
		name, attributes := host.SessionCookie(request)
		return Cookie{Name: name, Attributes: attributes}
	}
	options.Runtime.Cookie = func(request contract.Request, key, suffix string) Cookie {
		name, attributes := host.Cookie(request, key, suffix)
		return Cookie{Name: name, Attributes: attributes}
	}
	options.Runtime.AccountCookieEnabled = host.Options.Account.StoreAccountCookie != nil &&
		*host.Options.Account.StoreAccountCookie
	options.Runtime.OAuthStateCookieEnabled = host.Options.Account.StoreStateStrategy == "cookie"
	options.Runtime.VerifyPassword = host.Options.EmailAndPassword.Password.Verify
	options.Runtime.RunBackground = host.RunBackground
	options.Runtime.CreateVerification = host.CreateVerification
	options.Runtime.FindVerification = host.FindVerification
	options.Runtime.ConsumeVerification = host.ConsumeVerification
	options.Runtime.DeleteVerification = host.DeleteVerification
	return New(options)
}

func New(input Options) (engine.Plugin, error) {
	implementation, err := compile(input)
	if err != nil {
		return engine.Plugin{}, err
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
		return nil, errors.New("twofactor: Runtime.Adapter is required")
	}
	if options.Runtime.Secret == "" {
		return nil, errors.New("twofactor: Runtime.Secret is required")
	}
	if options.Runtime.AppName == "" {
		options.Runtime.AppName = "single-auth"
	}
	if options.Runtime.EncryptSecret == nil || options.Runtime.DecryptSecret == nil {
		return nil, errors.New("twofactor: secret encryption runtime is required")
	}
	if options.Runtime.ResolveSession == nil || options.Runtime.IssueSession == nil ||
		options.Runtime.DeleteSession == nil || options.Runtime.NewSession == nil ||
		options.Runtime.SetNewSession == nil {
		return nil, errors.New("twofactor: complete session runtime is required")
	}
	if options.Runtime.CreateVerification == nil || options.Runtime.FindVerification == nil ||
		options.Runtime.ConsumeVerification == nil || options.Runtime.DeleteVerification == nil {
		return nil, errors.New("twofactor: complete verification runtime is required")
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Random == nil {
		options.Runtime.Random = rand.Reader
	}
	if options.Runtime.SerializeUser == nil {
		options.Runtime.SerializeUser = func(record storage.Record) any { return cloneRecord(record) }
	}
	if options.Runtime.RunBackground == nil {
		options.Runtime.RunBackground = func(ctx context.Context, callback func(context.Context) error) error {
			return callback(ctx)
		}
	}
	if options.TwoFactorTable == "" {
		options.TwoFactorTable = "twoFactor"
	}
	if options.TOTP.Digits == 0 {
		options.TOTP.Digits = 6
	}
	if options.TOTP.Digits != 6 && options.TOTP.Digits != 8 {
		return nil, errors.New("twofactor: TOTP digits must be 6 or 8")
	}
	if options.TOTP.Period == 0 {
		options.TOTP.Period = 30 * time.Second
	}
	if options.TOTP.Period < time.Second {
		return nil, errors.New("twofactor: TOTP period must be at least one second")
	}
	if options.OTP.Digits == 0 {
		options.OTP.Digits = 6
	}
	if options.OTP.Digits < 1 {
		return nil, errors.New("twofactor: OTP digits must be positive")
	}
	if options.OTP.Period == 0 {
		options.OTP.Period = 3 * time.Minute
	}
	if options.OTP.AllowedAttempts == 0 {
		options.OTP.AllowedAttempts = DefaultAllowedAttempts
	}
	if options.OTP.AllowedAttempts < 1 {
		return nil, errors.New("twofactor: OTP allowed attempts must be positive")
	}
	if err := normalizeOTPStorage(&options.OTP.Storage, OTPStoragePlain, true); err != nil {
		return nil, fmt.Errorf("twofactor: OTP storage: %w", err)
	}
	if options.BackupCodes.Amount == 0 {
		options.BackupCodes.Amount = 10
	}
	if options.BackupCodes.Length == 0 {
		options.BackupCodes.Length = 10
	}
	if options.BackupCodes.Amount < 1 || options.BackupCodes.Length < 1 {
		return nil, errors.New("twofactor: backup code amount and length must be positive")
	}
	if err := normalizeOTPStorage(&options.BackupCodes.Storage, OTPStorageEncrypted, false); err != nil {
		return nil, fmt.Errorf("twofactor: backup code storage: %w", err)
	}
	if options.TwoFactorCookieMaxAge == 0 {
		options.TwoFactorCookieMaxAge = DefaultTwoFactorCookieMaxAge
	}
	if options.TrustDeviceMaxAge == 0 {
		options.TrustDeviceMaxAge = DefaultTrustDeviceMaxAge
	}
	if options.AccountLockout.MaxFailedAttempts == 0 {
		options.AccountLockout.MaxFailedAttempts = DefaultAccountLockoutLimit
	}
	if options.AccountLockout.Duration == 0 {
		options.AccountLockout.Duration = DefaultAccountLockoutWindow
	}
	if options.AccountLockout.MaxFailedAttempts < 1 || options.AccountLockout.Duration < time.Second {
		return nil, errors.New("twofactor: account lockout limit and duration must be positive")
	}
	if options.Runtime.SessionCookie == nil || options.Runtime.Cookie == nil {
		return nil, errors.New("twofactor: cookie runtime is required")
	}
	if options.Runtime.VerifyPassword == nil {
		return nil, errors.New("twofactor: password verifier is required")
	}
	schema, err := Schema(options)
	if err != nil {
		return nil, err
	}
	return &plugin{
		options: options, schema: schema, clock: options.Runtime.Clock,
		random: &lockedReader{r: options.Runtime.Random},
	}, nil
}

func normalizeOTPStorage(storageConfig *OTPStorage, fallback OTPStorageMode, allowHash bool) error {
	if storageConfig.Mode == "" && storageConfig.Hash == nil &&
		storageConfig.Encrypt == nil && storageConfig.Decrypt == nil {
		storageConfig.Mode = fallback
	}
	if storageConfig.Hash != nil {
		if !allowHash || storageConfig.Mode != "" || storageConfig.Encrypt != nil || storageConfig.Decrypt != nil {
			return errors.New("custom hash cannot be combined with another mode")
		}
		return nil
	}
	if storageConfig.Encrypt != nil || storageConfig.Decrypt != nil {
		if storageConfig.Mode != "" || storageConfig.Encrypt == nil || storageConfig.Decrypt == nil {
			return errors.New("custom encryption requires both Encrypt and Decrypt and no mode")
		}
		return nil
	}
	switch storageConfig.Mode {
	case OTPStoragePlain, OTPStorageEncrypted:
		return nil
	case OTPStorageHashed:
		if allowHash {
			return nil
		}
	}
	return errors.New("unsupported storage mode")
}

func snapshotOptions(input Options) Options {
	result := input
	if input.TOTP.AllowPasswordless != nil {
		value := *input.TOTP.AllowPasswordless
		result.TOTP.AllowPasswordless = &value
	}
	if input.BackupCodes.AllowPasswordless != nil {
		value := *input.BackupCodes.AllowPasswordless
		result.BackupCodes.AllowPasswordless = &value
	}
	if input.AccountLockout.Enabled != nil {
		value := *input.AccountLockout.Enabled
		result.AccountLockout.Enabled = &value
	}
	return result
}

func (p *plugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID: "two-factor", Version: Version, Schema: p.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "generateTOTP", Methods: []string{"POST"}, ServerOnly: true, OperationID: "generateTOTP", Handler: p.generateTOTP},
			{Name: "getTOTPURI", Path: "/two-factor/get-totp-uri", Methods: []string{"POST"}, OperationID: "getTOTPURI", Handler: p.getTOTPURI},
			{Name: "verifyTOTP", Path: "/two-factor/verify-totp", Methods: []string{"POST"}, OperationID: "verifyTOTP", Handler: p.verifyTOTP},
			{Name: "sendTwoFactorOTP", Path: "/two-factor/send-otp", Methods: []string{"POST"}, OperationID: "sendTwoFactorOTP", Handler: p.sendTwoFactorOTP},
			{Name: "verifyTwoFactorOTP", Path: "/two-factor/verify-otp", Methods: []string{"POST"}, OperationID: "verifyTwoFactorOTP", Handler: p.verifyTwoFactorOTP},
			{Name: "verifyBackupCode", Path: "/two-factor/verify-backup-code", Methods: []string{"POST"}, OperationID: "verifyBackupCode", Handler: p.verifyBackupCode},
			{Name: "generateBackupCodes", Path: "/two-factor/generate-backup-codes", Methods: []string{"POST"}, OperationID: "generateBackupCodes", Handler: p.generateBackupCodes},
			{Name: "viewBackupCodes", Methods: []string{"POST"}, ServerOnly: true, OperationID: "viewBackupCodes", Handler: p.viewBackupCodes},
			{Name: "enableTwoFactor", Path: "/two-factor/enable", Methods: []string{"POST"}, OperationID: "enableTwoFactor", Handler: p.enableTwoFactor},
			{Name: "disableTwoFactor", Path: "/two-factor/disable", Methods: []string{"POST"}, OperationID: "disableTwoFactor", Handler: p.disableTwoFactor},
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name: "two-factor-credential-sign-in", Matcher: func(ctx *engine.Context) (bool, error) {
				path := ctx.Path()
				return path == "/sign-in/email" || path == "/sign-in/username" || path == "/sign-in/phone-number", nil
			}, Handler: p.afterCredentialSignIn,
		}}},
		RateLimit: []ratelimit.MatcherRule{{
			Match: func(path string) bool { return strings.HasPrefix(path, "/two-factor/") },
			Rule:  ratelimit.Rule{Window: 10, Max: 3},
		}},
		ErrorCodes: pluginErrorCodes(),
	}
}
