package lastloginmethod

import (
	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	// Version is the frozen single-auth package version implemented here.
	Version = "1.6.26"

	DefaultCookieName = "single-auth.last_used_login_method"
	DefaultMaxAge     = 60 * 60 * 24 * 30
)

// HookContext is the Go view of single-auth's GenericEndpointContext fields
// used by this plugin. Path is the endpoint route pattern, not the concrete
// URL, and is normalized to an empty string for a pathless endpoint.
type HookContext struct {
	Endpoint *engine.Context
	Path     string
	Params   map[string]string
	Request  contract.Request
}

// ResolveMethodFunc returns a method override. Nil means the custom resolver
// declined to resolve and the built-in resolver must run, matching JavaScript
// nullish-coalescing. A pointer to an empty string is an explicit empty result
// and suppresses the built-in fallback.
type ResolveMethodFunc func(HookContext) (*string, error)

// BeforeStoreCookieFunc decides whether the readable method cookie may be
// written. Returning an error is equivalent to a rejected Promise upstream:
// the error is logged, the cookie is skipped, and authentication continues.
type BeforeStoreCookieFunc func(HookContext, string) (bool, error)

type UserSchemaOptions struct {
	// LastLoginMethod is the physical database field name for the canonical
	// lastLoginMethod field. Empty selects "lastLoginMethod".
	LastLoginMethod string
}

type SchemaOptions struct {
	User UserSchemaOptions
}

type SessionCookieResolver func(contract.Request) (string, cookies.Options)

// Runtime contains dependencies injected by NewFactory. It is public so a
// standalone engine plugin can be assembled in focused conformance tests.
type Runtime struct {
	Adapter               storage.Adapter
	Logger                *logger.Logger
	SessionCookie         SessionCookieResolver
	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}

// Options configures single-auth's last-login-method plugin.
type Options struct {
	// CookieName is used verbatim and is deliberately unaffected by the root
	// cookie prefix. Empty selects DefaultCookieName.
	CookieName string
	// MaxAge is expressed in seconds. Nil selects DefaultMaxAge; a pointer to
	// zero preserves single-auth's explicit Max-Age=0 behavior.
	MaxAge *int

	CustomResolveMethod ResolveMethodFunc
	StoreInDatabase     bool
	BeforeStoreCookie   BeforeStoreCookieFunc
	Schema              SchemaOptions
	Runtime             Runtime
}

// Int returns a pointer for options whose omitted and zero states differ.
func Int(value int) *int { return &value }

// Method returns a method pointer suitable for ResolveMethodFunc.
func Method(value string) *string { return &value }
