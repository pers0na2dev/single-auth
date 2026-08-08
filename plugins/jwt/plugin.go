package jwt

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type compiledPlugin struct {
	options  Options
	clock    func() time.Time
	random   io.Reader
	adapter  jwksAdapter
	secretMu sync.Mutex
}

// New validates and snapshots a single-auth JWT plugin descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input, true)
	if err != nil {
		return engine.Plugin{}, err
	}
	return implementation.descriptor()
}

func MustNew(options Options) engine.Plugin {
	descriptor, err := New(options)
	if err != nil {
		panic(err)
	}
	return descriptor
}

func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return PluginID }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return resolveSchema(factory.options.Schema)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.AdapterForContext = host.AdapterForContext
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.Secret = host.Secret
	options.Runtime.BaseURL = origin(host.Options.BaseURL)
	options.Runtime.ResolveBaseURL = func(ctx *engine.Context) (string, error) {
		resolved, err := host.ResolveBaseURL(ctx.Request())
		if err != nil {
			return "", err
		}
		return origin(resolved), nil
	}
	options.Runtime.ResolveSession = func(ctx *engine.Context, required bool) (*SessionState, error) {
		mode := singleauth.PluginSessionOptional
		if required {
			mode = singleauth.PluginSessionRequired
		}
		state, err := host.ResolveSession(ctx, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.EncryptPrivateKey = func(_ context.Context, value []byte) (string, error) {
		return host.EncryptSecret(value)
	}
	options.Runtime.DecryptPrivateKey = func(_ context.Context, value string) ([]byte, error) {
		return host.DecryptSecret(value)
	}
	return New(options)
}

func normalize(input Options, validateDescriptor bool) (*compiledPlugin, error) {
	options := input
	options.Schema = input.Schema.Clone()
	if input.JWKS.KeyPair != nil {
		keyPair := *input.JWKS.KeyPair
		options.JWKS.KeyPair = &keyPair
	}
	if input.JWKS.Path != nil {
		path := *input.JWKS.Path
		options.JWKS.Path = &path
	}
	if input.Token.Issuer != nil {
		issuer := *input.Token.Issuer
		options.Token.Issuer = &issuer
	}
	options.JWKS.RotationInterval = cloneDuration(input.JWKS.RotationInterval)
	options.JWKS.GracePeriod = cloneDuration(input.JWKS.GracePeriod)
	if audience, ok := input.Token.Audience.([]string); ok {
		options.Token.Audience = append([]string(nil), audience...)
	}
	path := "/jwks"
	if options.JWKS.Path != nil {
		path = *options.JWKS.Path
	}
	options.JWKS.Path = String(path)
	if validateDescriptor {
		if options.Token.Sign != nil && options.JWKS.RemoteURL == "" {
			return nil, fmt.Errorf("options.jwks.remoteUrl must be set when using options.jwt.sign")
		}
		if options.JWKS.RemoteURL != "" && (options.JWKS.KeyPair == nil || options.JWKS.KeyPair.Algorithm == "") {
			return nil, fmt.Errorf("options.jwks.keyPairConfig.alg must be specified when using the oidc plugin with options.jwks.remoteUrl")
		}
		if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return nil, fmt.Errorf("options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'")
		}
		if options.JWKS.KeyPair != nil {
			switch options.JWKS.KeyPair.Algorithm {
			case EdDSA, ES256, ES512, PS256, RS256:
			default:
				return nil, fmt.Errorf("jwt: unsupported JWS algorithm %q", options.JWKS.KeyPair.Algorithm)
			}
		}
		if options.Runtime.ResolveSession == nil {
			return nil, fmt.Errorf("jwt: Runtime.ResolveSession is required")
		}
		if options.Runtime.Adapter == nil && (options.Adapter.GetJWKs == nil || options.Adapter.CreateJWK == nil) && options.Token.Sign == nil {
			return nil, fmt.Errorf("jwt: Runtime.Adapter or a complete custom Adapter is required")
		}
		if !options.JWKS.DisablePrivateKeyEncryption &&
			options.Runtime.Secret == "" &&
			(options.Runtime.EncryptPrivateKey == nil || options.Runtime.DecryptPrivateKey == nil) &&
			options.Token.Sign == nil {
			return nil, fmt.Errorf("jwt: Runtime.Secret or private-key encryption callbacks are required")
		}
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	options.Runtime.Clock = clock
	randomSource := options.Runtime.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	locked := &lockedReader{r: randomSource}
	options.Runtime.Random = locked
	if options.Runtime.AdapterForContext == nil && options.Runtime.Adapter != nil {
		options.Runtime.AdapterForContext = func(context.Context) storage.TransactionAdapter {
			return options.Runtime.Adapter
		}
	}
	if options.Runtime.SerializeUser == nil {
		options.Runtime.SerializeUser = func(record storage.Record) any { return cloneRecord(record) }
	}
	implementation := &compiledPlugin{options: options, clock: clock, random: locked}
	implementation.adapter = jwksAdapter{options: options}
	return implementation, nil
}

func (plugin *compiledPlugin) descriptor() (engine.Plugin, error) {
	schema, err := resolveSchema(plugin.options.Schema)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: schema,
		Endpoints: []engine.Endpoint{
			{
				Name: "getJwks", Path: *plugin.options.JWKS.Path,
				Methods: []string{http.MethodGet}, OperationID: "getJSONWebKeySet",
				Handler: plugin.getJWKs,
			},
			{
				Name: "getToken", Path: "/token", Methods: []string{http.MethodGet},
				OperationID: "getJSONWebToken", Handler: plugin.getToken,
			},
			{
				Name: "signJWT", Methods: []string{http.MethodPost}, ServerOnly: true,
				Handler: plugin.signJWTEndpoint,
			},
			{
				Name: "verifyJWT", Methods: []string{http.MethodPost}, ServerOnly: true,
				Handler: plugin.verifyJWTEndpoint,
			},
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name: "jwt-get-session-header", Matcher: plugin.matchGetSession,
			Handler: plugin.afterGetSession,
		}}},
	}, nil
}

func (plugin *compiledPlugin) baseOrigin(ctx *engine.Context) (string, error) {
	if plugin.options.Runtime.ResolveBaseURL != nil && ctx != nil {
		resolved, err := plugin.options.Runtime.ResolveBaseURL(ctx)
		if err != nil {
			return "", err
		}
		return origin(resolved), nil
	}
	if value := origin(plugin.options.Runtime.BaseURL); value != "" {
		return value, nil
	}
	if ctx != nil {
		request := ctx.Request()
		if request.Host() != "" {
			scheme := request.Scheme()
			if scheme == "" {
				scheme = "https"
			}
			return scheme + "://" + request.Host(), nil
		}
	}
	return "", nil
}

func origin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func cloneDuration(value *time.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func unauthorized() error {
	return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}
