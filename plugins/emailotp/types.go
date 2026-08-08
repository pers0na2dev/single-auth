package emailotp

import (
	"context"
	"io"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// OTPType is one upstream email-otp purpose.
type OTPType string

const (
	TypeSignIn            OTPType = "sign-in"
	TypeEmailVerification OTPType = "email-verification"
	TypeForgetPassword    OTPType = "forget-password"
	TypeChangeEmail       OTPType = "change-email"
)

// StoreMode controls the representation persisted in verification.value.
type StoreMode string

const (
	StorePlain     StoreMode = "plain"
	StoreHashed    StoreMode = "hashed"
	StoreEncrypted StoreMode = "encrypted"
)

type ResendStrategy string

const (
	ResendRotate ResendStrategy = "rotate"
	ResendReuse  ResendStrategy = "reuse"
)

type OTPData struct {
	Email string  `json:"email"`
	Type  OTPType `json:"type"`
}

type OTPMessage struct {
	Email string  `json:"email"`
	OTP   string  `json:"otp"`
	Type  OTPType `json:"type"`
}

type GenerateOTPFunc func(OTPData, *engine.Context) (string, error)
type SendOTPFunc func(context.Context, OTPMessage, *engine.Context) error
type HashOTPFunc func(context.Context, string) (string, error)
type EncryptOTPFunc func(context.Context, string) (string, error)
type DecryptOTPFunc func(context.Context, string) (string, error)

// OTPStorage configures built-in or custom persistence transforms. CustomHash
// corresponds to upstream {hash}; CustomEncrypt and CustomDecrypt correspond
// to upstream {encrypt,decrypt}.
type OTPStorage struct {
	Mode          StoreMode
	CustomHash    HashOTPFunc
	CustomEncrypt EncryptOTPFunc
	CustomDecrypt DecryptOTPFunc
}

type RateLimitOptions struct {
	Window int64
	Max    int64
}

type ChangeEmailOptions struct {
	Enabled            bool
	VerifyCurrentEmail bool
}

type PasswordOptions struct {
	MinLength       int
	MaxLength       int
	Hash            func(string) (string, error)
	HashWithContext func(*engine.Context, string) (string, error)
	OnReset         PasswordResetHookFunc
	RevokeSessions  bool
}

type SessionResolution uint8

const (
	SessionOptional SessionResolution = iota
	// SessionAuthoritative is used by sensitive email-change endpoints. The
	// host must bypass cookie-cache-only identity and enforce its freshness
	// policy before returning the session.
	SessionAuthoritative
)

type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type ResolveSessionFunc func(*engine.Context, SessionResolution) (*SessionState, error)

// IssueSession creates a session for user and writes all host session cookies
// to ctx. Returning nil is treated as a session creation failure.
type IssueSessionFunc func(*engine.Context, storage.Record) (*SessionState, error)

// RefreshSession rewrites the host cookie/cache for an existing session after
// the plugin changes the user record.
type RefreshSessionFunc func(*engine.Context, SessionState) error

type CreateUserInput struct {
	Email      string
	Name       string
	Image      *string
	Additional storage.Record
}

type CreateUserFunc func(*engine.Context, CreateUserInput) (storage.Record, error)
type ParseUserInputFunc func(*engine.Context, map[string]any) (storage.Record, error)
type SerializeUserFunc func(storage.Record) any
type UserHookFunc func(context.Context, *engine.Context, storage.Record) error
type PasswordResetHookFunc func(context.Context, *engine.Context, storage.Record) error
type RevokeUnprovenAccessFunc func(*engine.Context, string) error
type RevokeSessionsFunc func(*engine.Context, string) error
type BackgroundRunner func(context.Context, func(context.Context) error) error
type SendRequestValidator func(*engine.Context) error

// DefaultVerificationHandler is installed into the host's default email
// verification option when OverrideDefaultEmailVerification is enabled.
type DefaultVerificationHandler func(context.Context, string) error
type DefaultVerificationInstaller func(DefaultVerificationHandler) error

type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type FindVerificationFunc func(context.Context, string) (storage.Record, error)
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
type UpdateVerificationFunc func(context.Context, string, storage.Record) error
type DeleteVerificationFunc func(context.Context, string) error

// Runtime contains dependencies single-auth normally injects through its
// internal endpoint context. engine.Plugin intentionally has no root-runtime
// dependency, so session/cookie and init-option behavior is explicit here.
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader
	Secret  string

	ResolveSession ResolveSessionFunc
	IssueSession   IssueSessionFunc
	RefreshSession RefreshSessionFunc

	CreateUser     CreateUserFunc
	ParseUserInput ParseUserInputFunc
	SerializeUser  SerializeUserFunc
	RevokeUnproven RevokeUnprovenAccessFunc
	// RevokeSessions must invalidate both database and secondary-storage
	// sessions when the host enables secondary session storage. The default
	// implementation deletes core session rows through Adapter.
	RevokeSessions RevokeSessionsFunc

	BeforeEmailVerification UserHookFunc
	AfterEmailVerification  UserHookFunc

	RunInBackground            BackgroundRunner
	ValidateSendRequest        SendRequestValidator
	InstallDefaultVerification DefaultVerificationInstaller
	Warn                       func(string)

	CreateVerification  CreateVerificationFunc
	FindVerification    FindVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	UpdateVerification  UpdateVerificationFunc
	DeleteVerification  DeleteVerificationFunc
}

// Options configures the single-auth-compatible email-otp plugin.
type Options struct {
	SendVerificationOTP              SendOTPFunc
	OTPLength                        int
	ExpiresIn                        time.Duration
	GenerateOTP                      GenerateOTPFunc
	Storage                          OTPStorage
	ResendStrategy                   ResendStrategy
	SendVerificationOnSignUp         bool
	DisableSignUp                    bool
	AllowedAttempts                  int
	ChangeEmail                      ChangeEmailOptions
	OverrideDefaultEmailVerification bool
	AutoSignInAfterVerification      bool
	RateLimit                        RateLimitOptions
	Password                         PasswordOptions
	TrustedOrigins                   []string
	Runtime                          Runtime
}
