package magiclink

import (
	"context"
	"io"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

type TokenStoreMode string

const (
	StorePlain  TokenStoreMode = "plain"
	StoreHashed TokenStoreMode = "hashed"
)

type TokenHashFunc func(context.Context, string) (string, error)

// TokenStorage is the Go representation of upstream's plain, hashed, or
// custom-hasher storeToken union.
type TokenStorage struct {
	Mode       TokenStoreMode
	CustomHash TokenHashFunc
}

type MagicLinkMessage struct {
	Email    string         `json:"email"`
	URL      string         `json:"url"`
	Token    string         `json:"token"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type GenerateTokenFunc func(context.Context, string) (string, error)

// SendMagicLink is awaited by the endpoint, matching upstream 1.6.26. A host
// that wants detached delivery should schedule durable work inside this
// callback rather than relying on request-context work after it returns.
type SendMagicLinkFunc func(context.Context, MagicLinkMessage, *engine.Context) error

type RateLimitOptions struct {
	Window int64
	Max    int64
}

type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// IssueSession creates a session for user and writes the host's session
// cookies to ctx. A nil state or session maps to failed_to_create_session.
type IssueSessionFunc func(*engine.Context, storage.Record) (*SessionState, error)

type CreateUserInput struct {
	Email string
	Name  string
}

type CreateUserFunc func(*engine.Context, CreateUserInput) (storage.Record, error)
type SerializeRecordFunc func(storage.Record) any
type RevokeUnprovenAccessFunc func(*engine.Context, string) error
type RevokeSessionsFunc func(*engine.Context, string) error
type BaseURLResolver func(*engine.Context) (string, error)
type TrustedOriginsResolver func(context.Context, contract.Request) ([]string, error)
type FormRequestValidator func(*engine.Context) error
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)

type RedirectKind string

const (
	RedirectCallback RedirectKind = "callbackURL"
	RedirectNewUser  RedirectKind = "newUserCallbackURL"
	RedirectError    RedirectKind = "errorCallbackURL"
)

type RedirectValidator func(*engine.Context, string, RedirectKind) error

// Runtime contains dependencies single-auth normally injects through its
// internal endpoint context. The host owns session cookies, user/session
// output filtering, dynamic base URLs, secondary-session invalidation, and
// canonical trusted-origin policy, so those dependencies are explicit.
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	BaseURL        string
	BasePath       string
	ResolveBaseURL BaseURLResolver

	TrustedOrigins        []string
	ResolveTrustedOrigins TrustedOriginsResolver
	ValidateFormRequest   FormRequestValidator
	ValidateRedirect      RedirectValidator

	CreateUser       CreateUserFunc
	IssueSession     IssueSessionFunc
	SerializeUser    SerializeRecordFunc
	SerializeSession SerializeRecordFunc
	RevokeUnproven   RevokeUnprovenAccessFunc
	// RevokeSessions must invalidate database and secondary-storage sessions.
	// The default implementation deletes core session rows through Adapter.
	RevokeSessions RevokeSessionsFunc
	Warn           func(string)

	CreateVerification  CreateVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
}

// Options configures the single-auth-compatible magic-link plugin.
type Options struct {
	ExpiresIn time.Duration
	// AllowedAttempts is deprecated and ignored. A non-nil value other than 1
	// emits the upstream compatibility warning. float64 preserves Infinity.
	AllowedAttempts *float64
	SendMagicLink   SendMagicLinkFunc
	DisableSignUp   bool
	RateLimit       RateLimitOptions
	GenerateToken   GenerateTokenFunc
	Storage         TokenStorage
	Runtime         Runtime
}

func Float64(value float64) *float64 { return &value }
