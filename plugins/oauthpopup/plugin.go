package oauthpopup

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type plugin struct {
	runtime Runtime
}

// New constructs a standalone popup server plugin from explicit runtime
// dependencies. Applications using singleauth.Auth should use NewFactory.
func New(options Options) (engine.Plugin, error) {
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "oauth-popup", Version: Version,
		Endpoints: []engine.Endpoint{{
			Name: "oauthPopupStart", Path: "/oauth-popup/start",
			Methods: []string{"GET"}, Handler: implementation.start,
		}},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    "oauth-popup-callback",
			Matcher: implementation.matchesCallback,
			Handler: implementation.afterCallback,
		}}},
		ErrorCodes: map[string]engine.ErrorDefinition{
			ErrorPopupSignInFailed: {Message: ErrorMessages[ErrorPopupSignInFailed]},
			ErrorPopupBlocked:      {Message: ErrorMessages[ErrorPopupBlocked]},
			ErrorPopupClosed:       {Message: ErrorMessages[ErrorPopupClosed]},
			ErrorPopupTimeout:      {Message: ErrorMessages[ErrorPopupTimeout]},
		},
	}, nil
}

func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

func NewFactory() singleauth.PluginFactory { return &rootFactory{} }

type rootFactory struct{}

func (*rootFactory) PluginID() string { return "oauth-popup" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (*rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	return New(Options{Runtime: Runtime{
		Secret: host.Secret, Logger: host.Logger,
		Cookie: host.Cookie, SessionCookie: host.SessionCookie,
		IsTrustedOrigin:  host.IsTrustedOrigin,
		ResolveBaseURL:   host.ResolveBaseURL,
		SocialProvider:   host.SocialProvider,
		CreateOAuthState: host.CreateOAuthState,
		HasPlugin:        host.HasPlugin,
	}})
}

func normalize(options Options) (*plugin, error) {
	runtime := options.Runtime
	switch {
	case runtime.Secret == "":
		return nil, fmt.Errorf("oauthpopup: Runtime.Secret is required")
	case runtime.Cookie == nil:
		return nil, fmt.Errorf("oauthpopup: Runtime.Cookie is required")
	case runtime.SessionCookie == nil:
		return nil, fmt.Errorf("oauthpopup: Runtime.SessionCookie is required")
	case runtime.IsTrustedOrigin == nil:
		return nil, fmt.Errorf("oauthpopup: Runtime.IsTrustedOrigin is required")
	case runtime.ResolveBaseURL == nil:
		return nil, fmt.Errorf("oauthpopup: Runtime.ResolveBaseURL is required")
	case runtime.SocialProvider == nil:
		return nil, fmt.Errorf("oauthpopup: Runtime.SocialProvider is required")
	case runtime.CreateOAuthState == nil:
		return nil, fmt.Errorf("oauthpopup: Runtime.CreateOAuthState is required")
	}
	if runtime.HasPlugin == nil {
		runtime.HasPlugin = func(string) bool { return false }
	}
	return &plugin{runtime: runtime}, nil
}
