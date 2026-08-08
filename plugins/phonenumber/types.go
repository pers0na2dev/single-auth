package phonenumber

import (
	"context"
	"io"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// OTPMessage is passed to phone OTP delivery and verification callbacks.
type OTPMessage struct {
	PhoneNumber string `json:"phoneNumber"`
	Code        string `json:"code"`
}

// VerificationEvent is delivered after a phone number has been associated
// with a user and marked verified.
type VerificationEvent struct {
	PhoneNumber string
	User        storage.Record
}

type SendOTPFunc func(context.Context, OTPMessage, *engine.Context) error
type VerifyOTPFunc func(context.Context, OTPMessage, *engine.Context) (bool, error)
type PhoneNumberValidator func(string) (bool, error)
type VerificationCallback func(context.Context, VerificationEvent, *engine.Context) error

// SignUpOnVerificationOptions configures user creation after a valid OTP for
// a phone number which is not associated with an existing user.
type SignUpOnVerificationOptions struct {
	GetTempEmail func(phoneNumber string) string
	GetTempName  func(phoneNumber string) string
}

// UserSchemaOptions maps canonical phone fields to physical database names.
type UserSchemaOptions struct {
	ModelName           string
	PhoneNumber         string
	PhoneNumberVerified string
}

type SchemaOptions struct{ User UserSchemaOptions }

// SessionState is the host session/user pair used by phone endpoints.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
type IssueSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
type CreateUserFunc func(*engine.Context, storage.Record) (storage.Record, error)
type ParseUserInputFunc func(*engine.Context, map[string]any) (storage.Record, error)
type SerializeUserFunc func(storage.Record) any
type HashPasswordFunc func(*engine.Context, string) (string, error)
type PasswordResetHookFunc func(context.Context, *engine.Context, storage.Record) error
type RevokeSessionsFunc func(*engine.Context, string) error
type BackgroundRunner func(context.Context, func(context.Context) error) error
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type FindVerificationFunc func(context.Context, string) (storage.Record, error)
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
type DeleteVerificationFunc func(context.Context, string) error

// Runtime contains services normally supplied by single-auth's endpoint
// context. NewFactory fills this structure from the final root runtime.
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	ResolveSession ResolveSessionFunc
	IssueSession   IssueSessionFunc
	CreateUser     CreateUserFunc
	ParseUserInput ParseUserInputFunc
	SerializeUser  SerializeUserFunc

	HashPassword                  HashPasswordFunc
	VerifyPassword                func(hash, password string) bool
	PasswordMinLength             int
	PasswordMaxLength             int
	OnPasswordReset               PasswordResetHookFunc
	RevokeSessions                RevokeSessionsFunc
	RevokeSessionsOnPasswordReset bool

	RunBackground          BackgroundRunner
	BackgroundTasksEnabled bool
	Warn                   func(string)
	LogError               func(string, error)

	CreateVerification CreateVerificationFunc
	// PeekVerification returns the newest verification without deleting an
	// expired row. This preserves single-auth's OTP_EXPIRED taxonomy.
	PeekVerification    FindVerificationFunc
	FindVerification    FindVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	DeleteVerification  DeleteVerificationFunc

	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}

// Options configures the single-auth-compatible phone-number plugin.
type Options struct {
	OTPLength              int
	SendOTP                SendOTPFunc
	VerifyOTP              VerifyOTPFunc
	SendPasswordResetOTP   SendOTPFunc
	ExpiresIn              time.Duration
	PhoneNumberValidator   PhoneNumberValidator
	RequireVerification    bool
	CallbackOnVerification VerificationCallback
	SignUpOnVerification   *SignUpOnVerificationOptions
	Schema                 SchemaOptions
	AllowedAttempts        int
	Runtime                Runtime
}
