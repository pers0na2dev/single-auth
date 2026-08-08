package mcp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

type plugin struct {
	options Options
	schema  storage.Schema
	clock   func() time.Time
	random  io.Reader
}

// New constructs a transport-neutral MCP descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return implementation.descriptor(), nil
}

// MustNew constructs a descriptor or panics.
func MustNew(options Options) engine.Plugin {
	descriptor, err := New(options)
	if err != nil {
		panic(err)
	}
	return descriptor
}

// NewFactory binds MCP to the final root adapter, session implementation,
// verification storage (including secondary storage), cookie configuration,
// random source, and dynamic base URL resolver.
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
	options.Runtime.Issuer = host.Options.BaseURL
	options.Runtime.BasePath = host.Options.BasePath
	options.Runtime.ResolveBaseURL = host.ResolveBaseURL
	options.Runtime.SessionCookie = host.SessionCookie
	options.Runtime.CreateVerification = host.CreateVerification
	options.Runtime.FindVerification = host.FindVerification
	options.Runtime.PeekVerification = host.PeekVerification
	options.Runtime.ConsumeVerification = host.ConsumeVerification
	options.Runtime.UpdateVerification = host.UpdateVerification
	options.Runtime.DeleteVerification = host.DeleteVerification
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
	options.Runtime.FindSession = func(ctx context.Context, token string) (*SessionState, error) {
		state, err := host.FindSession(ctx, token)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.NewSession = func(ctx *engine.Context) *SessionState {
		state := host.NewSession(ctx)
		if state == nil {
			return nil
		}
		return &SessionState{Session: state.Session, User: state.User}
	}
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	options := input
	options.Schema = input.Schema.Clone()
	options.OIDCConfig.Scopes = append([]string(nil), input.OIDCConfig.Scopes...)
	options.OIDCConfig.Metadata = cloneMap(input.OIDCConfig.Metadata)
	if options.LoginPage == "" {
		return nil, errors.New("mcp: LoginPage is required")
	}
	if options.OIDCConfig.CodeExpiresIn == 0 {
		options.OIDCConfig.CodeExpiresIn = defaultCodeExpiresIn
	}
	if options.OIDCConfig.AccessTokenExpiresIn == 0 {
		options.OIDCConfig.AccessTokenExpiresIn = defaultAccessTokenExpiresIn
	}
	if options.OIDCConfig.RefreshTokenExpiresIn == 0 {
		options.OIDCConfig.RefreshTokenExpiresIn = defaultRefreshTokenExpiresIn
	}
	if options.OIDCConfig.CodeExpiresIn < 0 || options.OIDCConfig.AccessTokenExpiresIn < 0 || options.OIDCConfig.RefreshTokenExpiresIn < 0 {
		return nil, errors.New("mcp: token and code lifetimes must be positive")
	}
	if options.OIDCConfig.DefaultScope == "" {
		options.OIDCConfig.DefaultScope = "openid"
	}
	if options.Runtime.Adapter == nil {
		return nil, errors.New("mcp: Runtime.Adapter is required")
	}
	if options.Runtime.ResolveSession == nil {
		return nil, errors.New("mcp: Runtime.ResolveSession is required")
	}
	if options.Runtime.Secret == "" {
		return nil, errors.New("mcp: Runtime.Secret is required")
	}
	if options.Runtime.ResolveBaseURL == nil {
		issuer := strings.TrimSuffix(options.Runtime.Issuer, "/")
		basePath := options.Runtime.BasePath
		if basePath == "" {
			basePath = "/api/auth"
		}
		if issuer == "" {
			return nil, errors.New("mcp: Runtime.ResolveBaseURL or Runtime.Issuer is required")
		}
		options.Runtime.ResolveBaseURL = func(contract.Request) (string, error) {
			return issuer + basePath, nil
		}
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Random == nil {
		options.Runtime.Random = rand.Reader
	}
	if options.Runtime.AdapterForContext == nil {
		options.Runtime.AdapterForContext = func(context.Context) storage.TransactionAdapter {
			return options.Runtime.Adapter
		}
	}
	schema, err := resolveSchema(options.Schema)
	if err != nil {
		return nil, fmt.Errorf("mcp: schema: %w", err)
	}
	return &plugin{
		options: options, schema: schema,
		clock: options.Runtime.Clock, random: &lockedReader{r: options.Runtime.Random},
	}, nil
}

func (p *plugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: p.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "oAuthConsent", Path: ConsentPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Consent", Handler: p.oauthConsent},
			{Name: "getMcpOAuthConfig", Path: DiscoveryPath, Methods: []string{http.MethodGet}, Handler: p.discovery},
			{Name: "getMCPProtectedResource", Path: ProtectedResourcePath, Methods: []string{http.MethodGet}, Handler: p.protectedResource},
			{Name: "mcpOAuthAuthorize", Path: AuthorizePath, Methods: []string{http.MethodGet}, Handler: p.authorize},
			{Name: "mcpOAuthToken", Path: TokenPath, Methods: []string{http.MethodPost}, Handler: p.token},
			{Name: "registerMcpClient", Path: RegisterPath, Methods: []string{http.MethodPost}, Handler: p.register},
			{Name: "getMcpSession", Path: SessionPath, Methods: []string{http.MethodGet}, Handler: p.getSession},
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    "mcp-continue-login-prompt",
			Matcher: func(*engine.Context) (bool, error) { return true, nil },
			Handler: p.afterLogin,
		}}},
	}
}

func (p *plugin) adapter(ctx context.Context) storage.TransactionAdapter {
	if p.options.Runtime.AdapterForContext != nil {
		if adapter := p.options.Runtime.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return p.options.Runtime.Adapter
}

func (p *plugin) allScopes() []string {
	result := []string{"openid", "profile", "email", "offline_access"}
	return append(result, p.options.OIDCConfig.Scopes...)
}

func (p *plugin) randomString(length int, alphabets ...string) (string, error) {
	alphabet := strings.Join(alphabets, "")
	if length < 0 || len(alphabet) < 2 || len(alphabet) > 256 {
		return "", errors.New("mcp: invalid random string parameters")
	}
	limit := 256 - 256%len(alphabet)
	result := make([]byte, 0, length)
	buffer := make([]byte, 1)
	for len(result) < length {
		if _, err := io.ReadFull(p.random, buffer); err != nil {
			return "", err
		}
		if int(buffer[0]) >= limit {
			continue
		}
		result = append(result, alphabet[int(buffer[0])%len(alphabet)])
	}
	return string(result), nil
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			result[key] = cloneMap(typed)
		case []string:
			result[key] = append([]string(nil), typed...)
		case []any:
			result[key] = append([]any(nil), typed...)
		default:
			result[key] = typed
		}
	}
	return result
}

func (p *plugin) afterLogin(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	rawPrompt, ok := readSignedCookie(ctx.Request(), "oidc_login_prompt", p.options.Runtime.Secret)
	if !ok {
		return nil, nil
	}
	if p.options.Runtime.SessionCookie == nil {
		return nil, nil
	}
	sessionCookieName, _ := p.options.Runtime.SessionCookie(ctx.Request())
	var sessionToken string
	for _, line := range response.Headers().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == sessionCookieName {
				sessionToken = splitSessionCookieToken(parsed.Attributes.Value)
				break
			}
		}
	}
	if sessionToken == "" {
		return nil, nil
	}
	var state *SessionState
	if p.options.Runtime.FindSession != nil {
		resolved, err := p.options.Runtime.FindSession(ctx.GoContext(), sessionToken)
		if err != nil {
			return nil, internalError(err)
		}
		state = resolved
	}
	if state == nil && p.options.Runtime.NewSession != nil {
		state = p.options.Runtime.NewSession(ctx)
	}
	if state == nil || state.User == nil || state.Session == nil {
		return nil, nil
	}
	query := map[string]string{}
	if err := jsonUnmarshalStrict([]byte(rawPrompt), &query); err != nil {
		return nil, nil
	}
	if prompt := query["prompt"]; prompt != "" {
		parts := strings.Fields(prompt)
		filtered := parts[:0]
		for _, part := range parts {
			if part != "login" {
				filtered = append(filtered, part)
			}
		}
		query["prompt"] = strings.Join(filtered, " ")
	}
	expirePromptCookie(ctx, "oidc_login_prompt")
	continued, err := p.authorizeQuery(ctx, query, state)
	if err != nil {
		return nil, err
	}
	return &continued, nil
}

func jsonUnmarshalStrict(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
