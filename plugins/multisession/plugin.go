package multisession

import (
	"context"
	"fmt"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const defaultMaximumSessions = 5

type plugin struct {
	options         Options
	maximumSessions int
	clock           func() time.Time
}

// New validates and snapshots a transport-neutral multi-session descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "multi-session", Version: Version,
		Endpoints: []engine.Endpoint{
			{
				Name: "listDeviceSessions", Path: "/multi-session/list-device-sessions",
				Methods: []string{"GET"}, OperationID: "listDeviceSessions",
				Handler: implementation.listDeviceSessions,
			},
			{
				Name: "setActiveSession", Path: "/multi-session/set-active",
				Methods: []string{"POST"}, OperationID: "setActiveSession",
				Handler: implementation.setActiveSession,
			},
			{
				Name: "revokeDeviceSession", Path: "/multi-session/revoke",
				Methods: []string{"POST"}, OperationID: "revokeDeviceSession",
				Handler: implementation.revokeDeviceSession,
			},
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{
			{
				Name:    "multi-session-persist-new-session",
				Matcher: func(*engine.Context) (bool, error) { return true, nil },
				Handler: implementation.afterNewSession,
			},
			{
				Name: "multi-session-sign-out-cleanup",
				Matcher: func(ctx *engine.Context) (bool, error) {
					return ctx.Path() == "/sign-out", nil
				},
				Handler: implementation.afterSignOut,
			},
		}},
		ErrorCodes: pluginErrorCodes(),
	}, nil
}

// MustNew is New for static setup.
func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

// NewFactory binds the plugin to the final root adapter and request-scoped
// cookie configuration.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "multi-session" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Secret = host.Secret
	options.Runtime.ResolveSession = func(ctx *engine.Context) (*SessionState, error) {
		state, err := host.ResolveSession(ctx, singleauth.PluginSessionRequired)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.FindSession = func(ctx context.Context, token string) (*SessionState, error) {
		state, err := host.FindSession(ctx, token)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.FindSessions = func(ctx context.Context, tokens []string, onlyActive bool) ([]SessionState, error) {
		states, err := host.FindSessions(ctx, tokens, onlyActive)
		if err != nil {
			return nil, err
		}
		result := make([]SessionState, len(states))
		for index := range states {
			result[index] = SessionState{Session: states[index].Session, User: states[index].User}
		}
		return result, nil
	}
	options.Runtime.RefreshSession = func(ctx *engine.Context, state SessionState, dontRemember bool) error {
		return host.RefreshSession(ctx, singleauth.PluginSessionState{
			Session: state.Session, User: state.User,
		}, dontRemember)
	}
	options.Runtime.DeleteSession = host.DeleteSession
	options.Runtime.DeleteSessions = host.DeleteSessions
	options.Runtime.NewSession = func(ctx *engine.Context) *SessionState {
		state := host.NewSession(ctx)
		if state == nil {
			return nil
		}
		return &SessionState{Session: state.Session, User: state.User}
	}
	options.Runtime.ResolveSessionCookies = func(request contract.Request) SessionCookies {
		tokenName, tokenAttributes := host.SessionCookie(request)
		dataName, dataAttributes := host.Cookie(request, "session_data", "session_data")
		rememberName, rememberAttributes := host.Cookie(request, "dont_remember", "dont_remember")
		resolved := SessionCookies{
			SessionToken: Cookie{Name: tokenName, Attributes: tokenAttributes},
			SessionData:  Cookie{Name: dataName, Attributes: dataAttributes},
			DontRemember: Cookie{Name: rememberName, Attributes: rememberAttributes},
		}
		if host.Options.Account.StoreAccountCookie != nil && *host.Options.Account.StoreAccountCookie {
			name, attributes := host.Cookie(request, "account_data", "account_data")
			value := Cookie{Name: name, Attributes: attributes}
			resolved.AccountData = &value
		}
		if host.Options.Account.StoreStateStrategy == "cookie" {
			name, attributes := host.Cookie(request, "oauth_state", "oauth_state")
			value := Cookie{Name: name, Attributes: attributes}
			resolved.OAuthState = &value
		}
		return resolved
	}
	options.Runtime.SerializeSession = host.SerializeSession
	options.Runtime.SerializeUser = host.SerializeUser
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	options := snapshotOptions(input)
	maximum := defaultMaximumSessions
	if options.MaximumSessions != nil {
		maximum = *options.MaximumSessions
		value := maximum
		options.MaximumSessions = &value
	}
	if options.Runtime.Secret == "" {
		return nil, fmt.Errorf("multisession: Runtime.Secret is required")
	}
	if options.Runtime.ResolveSession == nil {
		return nil, fmt.Errorf("multisession: Runtime.ResolveSession is required")
	}
	if options.Runtime.RefreshSession == nil {
		return nil, fmt.Errorf("multisession: Runtime.RefreshSession is required")
	}
	if options.Runtime.NewSession == nil {
		return nil, fmt.Errorf("multisession: Runtime.NewSession is required")
	}
	if options.Runtime.Adapter == nil && (options.Runtime.FindSession == nil ||
		options.Runtime.FindSessions == nil || options.Runtime.DeleteSession == nil ||
		options.Runtime.DeleteSessions == nil) {
		return nil, fmt.Errorf("multisession: Runtime.Adapter or complete session callbacks are required")
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	if options.Runtime.ResolveSessionCookies == nil {
		defaults := DefaultSessionCookies()
		options.Runtime.ResolveSessionCookies = func(contract.Request) SessionCookies { return defaults }
	}
	if options.Runtime.SerializeSession == nil {
		options.Runtime.SerializeSession = func(record storage.Record) any { return cloneRecord(record) }
	}
	if options.Runtime.SerializeUser == nil {
		options.Runtime.SerializeUser = func(record storage.Record) any { return cloneRecord(record) }
	}
	implementation := &plugin{options: options, maximumSessions: maximum, clock: clock}
	implementation.installAdapterFallbacks()
	return implementation, nil
}

func snapshotOptions(input Options) Options {
	result := input
	if input.MaximumSessions != nil {
		value := *input.MaximumSessions
		result.MaximumSessions = &value
	}
	return result
}
