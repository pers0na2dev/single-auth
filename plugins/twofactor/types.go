// Package twofactor ports single-auth's built-in two-factor plugin.
package twofactor

import (
	"context"
	"io"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

const (
	DefaultTwoFactorCookieMaxAge = 10 * time.Minute
	DefaultTrustDeviceMaxAge     = 30 * 24 * time.Hour
	DefaultAllowedAttempts       = 5
	DefaultAccountLockoutLimit   = 10
	DefaultAccountLockoutWindow  = 15 * time.Minute
)

// OTPMessage is delivered to the configured out-of-band OTP sender.
type OTPMessage struct {
	User storage.Record
	OTP  string
}

type SendOTPFunc func(context.Context, OTPMessage, *engine.Context) error
type OTPHashFunc func(string) (string, error)
type OTPEncryptFunc func(string) (string, error)
type OTPDecryptFunc func(string) (string, error)
type BackupCodesGenerateFunc func() []string

type OTPStorageMode string

const (
	OTPStoragePlain     OTPStorageMode = "plain"
	OTPStorageHashed    OTPStorageMode = "hashed"
	OTPStorageEncrypted OTPStorageMode = "encrypted"
)

// OTPStorage configures either a built-in storage mode or a custom codec.
// Hash is one-way; Encrypt and Decrypt must be supplied together.
type OTPStorage struct {
	Mode    OTPStorageMode
	Hash    OTPHashFunc
	Encrypt OTPEncryptFunc
	Decrypt OTPDecryptFunc
}

type OTPOptions struct {
	Period          time.Duration
	Digits          int
	SendOTP         SendOTPFunc
	AllowedAttempts int
	Storage         OTPStorage
}

type TOTPOptions struct {
	Digits            int
	Period            time.Duration
	AllowPasswordless *bool
	Disable           bool
}

type BackupCodeOptions struct {
	Amount            int
	Length            int
	CustomGenerate    BackupCodesGenerateFunc
	Storage           OTPStorage
	AllowPasswordless *bool
}

type AccountLockoutOptions struct {
	Enabled           *bool
	MaxFailedAttempts int
	Duration          time.Duration
}

type TwoFactorSchemaOptions struct {
	ModelName               string
	Secret                  string
	BackupCodes             string
	UserID                  string
	Verified                string
	FailedVerificationCount string
	LockedUntil             string
}

type UserSchemaOptions struct {
	ModelName        string
	TwoFactorEnabled string
}

type SchemaOptions struct {
	User      UserSchemaOptions
	TwoFactor TwoFactorSchemaOptions
}

type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type Cookie struct {
	Name       string
	Attributes cookies.Options
}

type ResolveSessionFunc func(*engine.Context, singleauth.PluginSessionMode) (*SessionState, error)
type IssueSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type FindVerificationFunc func(context.Context, string) (storage.Record, error)
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
type DeleteVerificationFunc func(context.Context, string) error
type CookieResolver func(contract.Request, string, string) Cookie

// Runtime is normally bound by NewFactory. It remains public for adapter and
// protocol tests that instantiate the transport-neutral plugin directly.
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader
	Secret  string
	AppName string

	EncryptSecret func([]byte) (string, error)
	DecryptSecret func(string) ([]byte, error)

	ResolveSession ResolveSessionFunc
	IssueSession   IssueSessionFunc
	DeleteSession  func(context.Context, string) error
	NewSession     func(*engine.Context) *SessionState
	SetNewSession  func(*engine.Context, *SessionState)
	SerializeUser  func(storage.Record) any

	SessionCookie           func(contract.Request) Cookie
	Cookie                  CookieResolver
	AccountCookieEnabled    bool
	OAuthStateCookieEnabled bool

	VerifyPassword func(hash, password string) bool
	RunBackground  func(context.Context, func(context.Context) error) error

	CreateVerification  CreateVerificationFunc
	FindVerification    FindVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	DeleteVerification  DeleteVerificationFunc
}

// Options mirrors single-auth 1.6.26 twoFactor options. Durations use Go
// duration values while preserving the upstream defaults and wire behavior.
type Options struct {
	Issuer                   string
	TwoFactorTable           string
	TOTP                     TOTPOptions
	OTP                      OTPOptions
	BackupCodes              BackupCodeOptions
	SkipVerificationOnEnable bool
	AllowPasswordless        bool
	Schema                   SchemaOptions
	TwoFactorCookieMaxAge    time.Duration
	TrustDeviceMaxAge        time.Duration
	AccountLockout           AccountLockoutOptions
	Runtime                  Runtime
}
