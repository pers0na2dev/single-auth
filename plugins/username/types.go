package username

import (
	"context"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	// Version is the frozen single-auth package version implemented here.
	Version = "1.6.26"

	defaultMinUsernameLength = 3
	defaultMaxUsernameLength = 30
	defaultSecret            = "single-auth-secret-123456789"
)

// ValidationOrder selects which representation is passed to a validator.
type ValidationOrder string

const (
	PreNormalization  ValidationOrder = "pre-normalization"
	PostNormalization ValidationOrder = "post-normalization"
)

// ValidationOrders independently configure username and display-username
// validation. Empty values select PreNormalization.
type ValidationOrders struct {
	Username        ValidationOrder
	DisplayUsername ValidationOrder
}

// Validator is the Go equivalent of single-auth's sync-or-async validator.
// Callback implementations must be safe for concurrent use.
type Validator func(string) (bool, error)

// Normalizer transforms a value before persistence or lookup. Callback
// implementations must be deterministic and safe for concurrent use.
type Normalizer func(string) string

type UserSchemaOptions struct {
	// ModelName is the physical database model name. Empty uses the canonical
	// user model name.
	ModelName string
	// Username and DisplayUsername are physical database field names. Empty
	// values use the canonical names.
	Username        string
	DisplayUsername string
}

type SchemaOptions struct{ User UserSchemaOptions }

// SessionState is the session/user pair issued by the host.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type IssueSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
type SerializeUserFunc func(storage.Record) any
type ResolveBaseURLFunc func(contract.Request) (string, error)
type ValidateRedirectFunc func(*engine.Context, string, string) error
type RunBackgroundFunc func(context.Context, func(context.Context) error) error
type HashPasswordContextFunc func(*engine.Context, string) (string, error)

// VerificationMessage is delivered when username sign-in is blocked by an
// unverified email and SendOnSignIn is enabled.
type VerificationMessage struct {
	User  model.User
	URL   string
	Token string
}

type SendVerificationEmailFunc func(context.Context, VerificationMessage) error

// Runtime contains dependencies injected by NewFactory. It remains public so
// focused descriptor tests can assemble the standalone plugin.
type Runtime struct {
	Adapter storage.Adapter
	Logger  *logger.Logger
	Clock   func() time.Time
	Secret  string

	HashPassword func(string) (string, error)
	// HashPasswordContext preserves request-scoped password wrapper semantics
	// when the plugin performs the timing-equalization hash for an unknown user.
	HashPasswordContext HashPasswordContextFunc
	VerifyPassword      func(hash, password string) bool

	IssueSession     IssueSessionFunc
	ResolveSession   ResolveSessionFunc
	SerializeUser    SerializeUserFunc
	ResolveBaseURL   ResolveBaseURLFunc
	ValidateRedirect ValidateRedirectFunc
	RunBackground    RunBackgroundFunc

	RequireEmailVerification bool
	SendOnSignIn             bool
	VerificationExpiresIn    time.Duration
	SendVerificationEmail    SendVerificationEmailFunc

	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}

// Options configures the single-auth-compatible username plugin.
type Options struct {
	Schema SchemaOptions

	MinUsernameLength int
	MaxUsernameLength int

	UsernameValidator        Validator
	DisplayUsernameValidator Validator

	// UsernameNormalization defaults to strings.ToLower. Set
	// DisableUsernameNormalization to preserve the submitted username.
	UsernameNormalization        Normalizer
	DisableUsernameNormalization bool
	// DisplayUsernameNormalization defaults to the identity function.
	DisplayUsernameNormalization Normalizer

	ValidationOrder ValidationOrders
	Runtime         Runtime
}
