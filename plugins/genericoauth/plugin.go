package genericoauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

type plugin struct {
	options       Options
	runtime       Runtime
	configs       map[string]Config
	providers     map[string]*providers.Provider
	providerState map[string]*providerRuntime
}

func New(options Options) (engine.Plugin, error) {
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return implementation.descriptor(), nil
}

func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "generic-oauth" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime = Runtime{
		BaseURL: host.Options.BaseURL, BasePath: host.Options.BasePath,
		ErrorURL:             host.Options.OnAPIError.ErrorURL,
		StateStrategy:        host.Options.Account.StoreStateStrategy,
		Secret:               host.Secret,
		SkipStateCookieCheck: host.Options.Account.SkipStateCookieCheck,
		AllowDifferentEmails: host.Options.Account.AccountLinking.AllowDifferentEmails,
		Clock:                host.Clock, Random: host.Random, HTTPClient: host.Options.HTTPClient,
		Logger:         host.Logger,
		ResolveBaseURL: host.ResolveBaseURL, Cookie: host.Cookie,
		DecryptSecret:       host.DecryptSecret,
		CreateOAuthState:    host.CreateOAuthState,
		HandleOAuthUser:     host.HandleOAuthUser,
		LinkOAuthAccount:    host.LinkOAuthAccount,
		ResolveSession:      host.ResolveSession,
		RefreshSession:      host.RefreshSession,
		FindVerification:    host.FindVerification,
		ConsumeVerification: host.ConsumeVerification,
	}
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	if host.RegisterSocialProvider == nil {
		return engine.Plugin{}, fmt.Errorf("genericoauth: PluginHost.RegisterSocialProvider is required")
	}
	seen := make(map[string]struct{}, len(options.Config))
	for _, config := range options.Config {
		if _, exists := seen[config.ProviderID]; exists {
			continue
		}
		seen[config.ProviderID] = struct{}{}
		if err := host.RegisterSocialProvider(implementation.providers[config.ProviderID]); err != nil {
			return engine.Plugin{}, err
		}
	}
	return implementation.descriptor(), nil
}

func normalize(input Options) (*plugin, error) {
	options := cloneOptions(input)
	runtime := options.Runtime
	if runtime.Clock == nil {
		runtime.Clock = time.Now
	}
	if runtime.BasePath == "" {
		runtime.BasePath = "/api/auth"
	} else if runtime.BasePath == "/" {
		runtime.BasePath = ""
	} else {
		runtime.BasePath = "/" + strings.Trim(runtime.BasePath, "/")
	}
	if runtime.HTTPClient == nil {
		runtime.HTTPClient = http.DefaultClient
	}
	if runtime.StateStrategy == "" {
		runtime.StateStrategy = "database"
	}
	switch {
	case runtime.ResolveBaseURL == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.ResolveBaseURL is required")
	case runtime.Cookie == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.Cookie is required")
	case runtime.DecryptSecret == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.DecryptSecret is required")
	case runtime.CreateOAuthState == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.CreateOAuthState is required")
	case runtime.HandleOAuthUser == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.HandleOAuthUser is required")
	case runtime.LinkOAuthAccount == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.LinkOAuthAccount is required")
	case runtime.ResolveSession == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.ResolveSession is required")
	case runtime.RefreshSession == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.RefreshSession is required")
	case runtime.FindVerification == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.FindVerification is required")
	case runtime.ConsumeVerification == nil:
		return nil, fmt.Errorf("genericoauth: Runtime.ConsumeVerification is required")
	case runtime.StateStrategy == "cookie" && runtime.Secret == "":
		return nil, fmt.Errorf("genericoauth: Runtime.Secret is required for cookie state")
	case runtime.StateStrategy != "cookie" && runtime.StateStrategy != "database":
		return nil, fmt.Errorf("genericoauth: Runtime.StateStrategy must be database or cookie")
	}

	seen := make(map[string]struct{}, len(options.Config))
	reported := make(map[string]struct{})
	duplicates := make([]string, 0)
	configs := make(map[string]Config, len(options.Config))
	providerMap := make(map[string]*providers.Provider, len(options.Config))
	stateMap := make(map[string]*providerRuntime, len(options.Config))
	for _, config := range options.Config {
		if _, exists := seen[config.ProviderID]; exists {
			if _, alreadyReported := reported[config.ProviderID]; !alreadyReported {
				duplicates = append(duplicates, config.ProviderID)
				reported[config.ProviderID] = struct{}{}
			}
			continue
		}
		seen[config.ProviderID] = struct{}{}
		if strings.TrimSpace(config.ProviderID) == "" {
			return nil, fmt.Errorf("genericoauth: provider ID is required")
		}
		provider, state, err := newProvider(config, runtime)
		if err != nil {
			return nil, err
		}
		configs[config.ProviderID] = config
		providerMap[config.ProviderID] = provider
		stateMap[config.ProviderID] = state
	}
	if len(duplicates) != 0 && runtime.Logger != nil {
		runtime.Logger.Warn("Duplicate provider IDs found: " + strings.Join(duplicates, ", "))
	}
	options.Runtime = runtime
	return &plugin{
		options: options, runtime: runtime, configs: configs,
		providers: providerMap, providerState: stateMap,
	}, nil
}

func (p *plugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID: "generic-oauth", Version: Version,
		Endpoints: []engine.Endpoint{
			{Name: "signInWithOAuth2", Path: "/sign-in/oauth2", Methods: []string{http.MethodPost}, OperationID: "signInWithOAuth2", Handler: p.signIn},
			{Name: "oAuth2Callback", Path: "/oauth2/callback/:providerId", Methods: []string{http.MethodGet}, OperationID: "oAuth2Callback", Handler: p.callback},
			{Name: "oAuth2LinkAccount", Path: "/oauth2/link", Methods: []string{http.MethodPost}, OperationID: "oAuth2LinkAccount", Handler: p.link},
		},
		ErrorCodes: errorDefinitions(),
	}
}

func cloneOptions(input Options) Options {
	result := input
	result.Config = make([]Config, len(input.Config))
	for index, config := range input.Config {
		clone := config
		clone.Scopes = append([]string(nil), config.Scopes...)
		clone.DiscoveryHeaders = cloneStringMap(config.DiscoveryHeaders)
		clone.AuthorizationHeaders = cloneStringMap(config.AuthorizationHeaders)
		clone.AuthorizationURLParams.Static = cloneStringMap(config.AuthorizationURLParams.Static)
		clone.TokenURLParams.Static = cloneStringMap(config.TokenURLParams.Static)
		result.Config[index] = clone
	}
	return result
}
