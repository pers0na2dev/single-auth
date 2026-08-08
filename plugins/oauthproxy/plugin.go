package oauthproxy

import (
	"fmt"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type plugin struct {
	options Options
	runtime Runtime
	maxAge  time.Duration
}

// New constructs a standalone transport-neutral OAuth proxy plugin.
func New(options Options) (engine.Plugin, error) {
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "oauth-proxy", Version: Version,
		Endpoints: []engine.Endpoint{{
			Name: "oAuthProxy", Path: "/oauth-proxy-callback",
			Methods: []string{"GET"}, OperationID: "oauthProxyCallback",
			Handler: implementation.proxyCallback,
		}},
		Hooks: engine.Hooks{
			Before: []engine.BeforeHook{
				{Name: "oauth-proxy-sign-in", Matcher: matchSignIn, Handler: implementation.beforeSignIn},
				{Name: "oauth-proxy-callback", Matcher: matchCallback, Handler: implementation.beforeCallback},
			},
			After: []engine.AfterHook{
				{Name: "oauth-proxy-sign-in", Matcher: matchSignIn, Handler: implementation.afterSignIn},
				{Name: "oauth-proxy-callback", Matcher: matchCallback, Handler: implementation.afterCallback},
			},
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

func NewFactory(options ...Options) singleauth.PluginFactory {
	configured := Options{}
	if len(options) != 0 {
		configured = options[0]
	}
	return &rootFactory{options: configured}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "oauth-proxy" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime = Runtime{
		BaseURL: host.Options.BaseURL, BasePath: host.Options.BasePath,
		ErrorURL:      host.Options.OnAPIError.ErrorURL,
		StateStrategy: host.Options.Account.StoreStateStrategy,
		Clock:         host.Clock, Random: host.Random, Logger: host.Logger,
		ResolveBaseURL: host.ResolveBaseURL, IsTrustedOrigin: host.IsTrustedOrigin,
		Cookie: host.Cookie, EncryptSecret: host.EncryptSecret,
		DecryptSecret: host.DecryptSecret, SocialProvider: host.SocialProvider,
		HandleOAuthUser: host.HandleOAuthUser, RefreshSession: host.RefreshSession,
		FindVerification:    host.FindVerification,
		ConsumeVerification: host.ConsumeVerification,
	}
	return New(options)
}

func normalize(options Options) (*plugin, error) {
	runtime := options.Runtime
	if runtime.BasePath == "" {
		runtime.BasePath = "/api/auth"
	}
	if runtime.BasePath != "/" {
		runtime.BasePath = "/" + strings.Trim(strings.TrimSpace(runtime.BasePath), "/")
	} else {
		runtime.BasePath = ""
	}
	if runtime.Clock == nil {
		runtime.Clock = time.Now
	}
	switch {
	case runtime.Random == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.Random is required")
	case runtime.ResolveBaseURL == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.ResolveBaseURL is required")
	case runtime.IsTrustedOrigin == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.IsTrustedOrigin is required")
	case runtime.Cookie == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.Cookie is required")
	case runtime.EncryptSecret == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.EncryptSecret is required")
	case runtime.DecryptSecret == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.DecryptSecret is required")
	case runtime.SocialProvider == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.SocialProvider is required")
	case runtime.HandleOAuthUser == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.HandleOAuthUser is required")
	case runtime.RefreshSession == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.RefreshSession is required")
	case runtime.FindVerification == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.FindVerification is required")
	case runtime.ConsumeVerification == nil:
		return nil, fmt.Errorf("oauthproxy: Runtime.ConsumeVerification is required")
	}
	maxAge := options.MaxAge
	if maxAge == 0 {
		maxAge = defaultMaxAge
	}
	if maxAge < 0 {
		return nil, fmt.Errorf("oauthproxy: MaxAge must not be negative")
	}
	if options.SecretConfig != nil {
		clone := *options.SecretConfig
		clone.Keys = make(map[int]string, len(options.SecretConfig.Keys))
		for version, secret := range options.SecretConfig.Keys {
			clone.Keys[version] = secret
		}
		clone.Order = append([]int(nil), options.SecretConfig.Order...)
		options.SecretConfig = &clone
	}
	options.Runtime = runtime
	return &plugin{options: options, runtime: runtime, maxAge: maxAge}, nil
}

func matchSignIn(ctx *engine.Context) (bool, error) {
	path := ctx.Path()
	return strings.HasPrefix(path, "/sign-in/social") || strings.HasPrefix(path, "/sign-in/oauth2"), nil
}

func matchCallback(ctx *engine.Context) (bool, error) {
	return ctx.Path() == "/callback/:id", nil
}
