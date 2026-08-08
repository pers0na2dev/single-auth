// Package admin implements the single-auth 1.6.26 administration plugin.
package admin

import (
	"context"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	PluginID = "admin"
	Version  = "1.6.26"
)

const DefaultBannedUserMessage = "You have been banned from this application. Please contact support if you believe this is an error."

// SessionState is the transport-neutral session and user pair used by the
// administration runtime.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// Runtime contains the root services used by the plugin. NewFactory fills
// this structure from singleauth.PluginHost. It remains public for focused
// adapter and descriptor tests.
type Runtime struct {
	Adapter           storage.Adapter
	AdapterForContext func(context.Context) storage.TransactionAdapter
	Clock             func() time.Time
	Secret            string

	ResolveSession   func(*engine.Context, bool) (*SessionState, error)
	CreateUser       func(*engine.Context, storage.Record) (storage.Record, error)
	ParseUserInput   func(*engine.Context, map[string]any) (storage.Record, error)
	SerializeUser    func(storage.Record) any
	SerializeSession func(storage.Record) any

	UpdateUser       func(*engine.Context, string, storage.Record) (storage.Record, error)
	DeleteUser       func(*engine.Context, string) error
	ListUserSessions func(context.Context, string, bool) ([]storage.Record, error)

	CreateSession  func(*engine.Context, string, bool, storage.Record) (*SessionState, error)
	RefreshSession func(*engine.Context, SessionState, bool) error
	FindSession    func(context.Context, string) (*SessionState, error)
	DeleteSession  func(context.Context, string) error
	RevokeSessions func(*engine.Context, string) error

	SetCredentialPassword func(*engine.Context, string, string) error
	HashPassword          func(*engine.Context, string) (string, error)
	MinPasswordLength     int
	MaxPasswordLength     int

	SessionCookie func(contract.Request) (string, cookies.Options)
	Cookie        func(contract.Request, string, string) (string, cookies.Options)

	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}

// Options configures the single-auth administration plugin.
type Options struct {
	DefaultRole                  string
	AdminRoles                   []string
	DefaultBanReason             string
	DefaultBanExpiresIn          time.Duration
	ImpersonationSessionDuration time.Duration
	Schema                       storage.Schema
	Roles                        map[string]*authorization.Role
	AdminUserIDs                 []string
	BannedUserMessage            string
	AllowImpersonatingAdmins     bool
	Runtime                      Runtime
}
