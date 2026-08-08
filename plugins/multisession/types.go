package multisession

import (
	"context"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// SessionState is single-auth's session/user pair.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// Cookie describes one request-resolved single-auth cookie.
type Cookie struct {
	Name       string
	Attributes cookies.Options
}

// SessionCookies is the cookie set touched by deleteSessionCookie. Optional
// cookies are nil when the corresponding root feature is disabled.
type SessionCookies struct {
	SessionToken Cookie
	SessionData  Cookie
	DontRemember Cookie
	AccountData  *Cookie
	OAuthState   *Cookie
}

type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
type FindSessionFunc func(context.Context, string) (*SessionState, error)
type FindSessionsFunc func(context.Context, []string, bool) ([]SessionState, error)
type RefreshSessionFunc func(*engine.Context, SessionState, bool) error
type DeleteSessionFunc func(context.Context, string) error
type DeleteSessionsFunc func(context.Context, []string) error
type NewSessionFunc func(*engine.Context) *SessionState
type ResolveSessionCookiesFunc func(contract.Request) SessionCookies
type SerializeRecordFunc func(storage.Record) any

// Runtime contains dependencies single-auth normally injects into endpoint
// context. NewFactory supplies the authoritative root implementations,
// including secondary-storage-aware batch session operations.
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Secret  string

	ResolveSession        ResolveSessionFunc
	FindSession           FindSessionFunc
	FindSessions          FindSessionsFunc
	RefreshSession        RefreshSessionFunc
	DeleteSession         DeleteSessionFunc
	DeleteSessions        DeleteSessionsFunc
	NewSession            NewSessionFunc
	ResolveSessionCookies ResolveSessionCookiesFunc
	SerializeSession      SerializeRecordFunc
	SerializeUser         SerializeRecordFunc
}

// Options configures single-auth's multi-session plugin. Nil selects the
// upstream default of five. A pointer preserves explicit zero and negative
// values, both of which upstream accepts.
type Options struct {
	MaximumSessions *int
	Runtime         Runtime
}

// Int returns a pointer suitable for MaximumSessions.
func Int(value int) *int { return &value }

// DefaultSessionCookies returns single-auth's ordinary non-secure defaults.
// Root integrations should use NewFactory so dynamic domains, secure prefixes,
// overrides, account cookies, and OAuth state strategy stay request scoped.
func DefaultSessionCookies() SessionCookies {
	sevenDays := 7 * 24 * 60 * 60
	fiveMinutes := 5 * 60
	base := cookies.Options{Path: "/", HTTPOnly: true, SameSite: "lax"}
	token := base
	token.MaxAge = &sevenDays
	data := base
	data.MaxAge = &fiveMinutes
	return SessionCookies{
		SessionToken: Cookie{Name: "single-auth.session_token", Attributes: token},
		SessionData:  Cookie{Name: "single-auth.session_data", Attributes: data},
		DontRemember: Cookie{Name: "single-auth.dont_remember", Attributes: base},
	}
}
