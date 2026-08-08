package anonymous

import (
	"io"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// SessionState is the session/user pair exposed by single-auth endpoint
// context session helpers.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// SessionResolution selects the authority required by an anonymous endpoint.
type SessionResolution uint8

const (
	SessionOptional SessionResolution = iota
	SessionRequired
	SessionAuthoritative
)

type ResolveSessionFunc func(*engine.Context, SessionResolution) (*SessionState, error)
type IssueSessionFunc func(*engine.Context, string) (*SessionState, error)
type NewSessionFunc func(*engine.Context) *SessionState
type SetNewSessionFunc func(*engine.Context, *SessionState)
type CreateUserFunc func(*engine.Context, storage.Record) (storage.Record, error)
type SerializeUserFunc func(storage.Record) any
type RevokeSessionsFunc func(*engine.Context, string) error

// Cookie describes one resolved single-auth cookie. Attributes are reused
// when the delete endpoint expires the cookie.
type Cookie struct {
	Name       string
	Attributes cookies.Options
}

// SessionCookies contains every cookie deleted by deleteSessionCookie in
// single-auth 1.6.26. AccountData and OAuthState are nil when their respective
// storage options are disabled.
type SessionCookies struct {
	SessionToken Cookie
	SessionData  Cookie
	DontRemember Cookie
	AccountData  *Cookie
	OAuthState   *Cookie
}

type ResolveSessionCookiesFunc func(contract.Request) SessionCookies

// LinkAccountData is passed before post-link cleanup. NewUser deliberately
// contains both the new user and its session, matching the upstream callback.
type LinkAccountData struct {
	AnonymousUser SessionState
	NewUser       SessionState
	Context       *engine.Context
}

type LinkAccountFunc func(LinkAccountData) error
type GenerateNameFunc func(*engine.Context) (string, error)
type GenerateRandomEmailFunc func() (string, error)
type LogErrorFunc func(string, ...any)

// Runtime contains dependencies single-auth normally injects into the
// endpoint context. NewFactory supplies all of them from PluginHost.
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	ResolveSession        ResolveSessionFunc
	IssueSession          IssueSessionFunc
	NewSession            NewSessionFunc
	SetNewSession         SetNewSessionFunc
	CreateUser            CreateUserFunc
	SerializeUser         SerializeUserFunc
	RevokeSessions        RevokeSessionsFunc
	ResolveSessionCookies ResolveSessionCookiesFunc
	Error                 LogErrorFunc
}

// Options configures the single-auth-compatible anonymous plugin.
type Options struct {
	EmailDomainName            string
	OnLinkAccount              LinkAccountFunc
	DisableDeleteAnonymousUser bool
	GenerateName               GenerateNameFunc
	GenerateRandomEmail        GenerateRandomEmailFunc
	Schema                     storage.Schema
	Runtime                    Runtime
}

// DefaultSessionCookies returns single-auth's non-secure default cookie set.
// Root integrations should prefer NewFactory so overrides, secure prefixes,
// dynamic domains, and optional account/OAuth cookies remain authoritative.
func DefaultSessionCookies() SessionCookies {
	base := cookies.Options{Path: "/", HTTPOnly: true, SameSite: "lax"}
	return SessionCookies{
		SessionToken: Cookie{Name: "single-auth.session_token", Attributes: base},
		SessionData:  Cookie{Name: "single-auth.session_data", Attributes: base},
		DontRemember: Cookie{Name: "single-auth.dont_remember", Attributes: base},
	}
}
