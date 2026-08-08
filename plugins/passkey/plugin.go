package passkey

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

const (
	defaultAppName      = "single-auth"
	defaultSecret       = "single-auth-secret-123456789"
	defaultCookieKey    = "single-auth-passkey"
	defaultCookiePrefix = "single-auth"
)

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (r *lockedReader) Read(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Read(buffer)
}

type plugin struct {
	options            Options
	schema             storage.Schema
	rpID               string
	rpName             string
	cookie             ChallengeCookie
	clock              func() time.Time
	random             io.Reader
	verifyRegister     RegistrationVerifier
	verifyAuthenticate AuthenticationVerifier
}

// New validates and snapshots a single-auth passkey plugin.
func New(options Options) (engine.Plugin, error) {
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID:      "passkey",
		Version: Version,
		Schema:  implementation.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{
				Name: "generatePasskeyRegistrationOptions", Path: "/passkey/generate-register-options",
				Methods: []string{"GET"}, OperationID: "generatePasskeyRegistrationOptions",
				Handler: implementation.generateRegistrationOptions,
			},
			{
				Name: "generatePasskeyAuthenticationOptions", Path: "/passkey/generate-authenticate-options",
				Methods: []string{"GET"}, OperationID: "passkeyGenerateAuthenticateOptions",
				Handler: implementation.generateAuthenticationOptions,
			},
			{
				Name: "verifyPasskeyRegistration", Path: "/passkey/verify-registration",
				Methods: []string{"POST"}, OperationID: "passkeyVerifyRegistration",
				Handler: implementation.verifyRegistration,
			},
			{
				Name: "verifyPasskeyAuthentication", Path: "/passkey/verify-authentication",
				Methods: []string{"POST"}, OperationID: "passkeyVerifyAuthentication",
				Handler: implementation.verifyAuthentication,
			},
			{
				Name: "listPasskeys", Path: "/passkey/list-user-passkeys",
				Methods: []string{"GET"}, Handler: implementation.list,
			},
			{
				Name: "deletePasskey", Path: "/passkey/delete-passkey",
				Methods: []string{"POST"}, Handler: implementation.delete,
			},
			{
				Name: "updatePasskey", Path: "/passkey/update-passkey",
				Methods: []string{"POST"}, Handler: implementation.update,
			},
		},
		ErrorCodes: pluginErrorCodes(),
	}, nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

// NewFactory binds passkey persistence, sessions, cryptographic material, and
// cookie policy to the final single-auth runtime during New.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "passkey" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return resolveSchema(factory.options.Schema)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	if options.AppName == "" {
		options.AppName = host.Options.AppName
	}
	if options.BaseURL == "" {
		options.BaseURL = host.Options.BaseURL
	}
	options.Secret = host.Secret
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.ResolveSession = func(ctx *engine.Context, resolution SessionResolution) (*SessionState, error) {
		mode := singleauth.PluginSessionOptional
		switch resolution {
		case SessionRequired:
			mode = singleauth.PluginSessionRequired
		case SessionFresh:
			mode = singleauth.PluginSessionFresh
		}
		state, err := host.ResolveSession(ctx, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.IssueSession = func(ctx *engine.Context, userID string) (*SessionState, error) {
		state, err := host.IssueSession(ctx, userID, false)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	if options.Advanced.ChallengeCookie == nil && options.Runtime.ResolveChallengeCookie == nil {
		key := options.Advanced.WebAuthnChallengeCookie
		if key == "" {
			key = defaultCookieKey
		}
		options.Runtime.ResolveChallengeCookie = func(request contract.Request) (ChallengeCookie, error) {
			name, attributes := host.Cookie(request, key, key)
			return ChallengeCookie{Name: name, Attributes: attributes}, nil
		}
	}
	options.Runtime.CreateChallenge = func(ctx context.Context, identifier, value string, expiresAt time.Time) (storage.Record, error) {
		return host.CreateVerification(ctx, identifier, value, expiresAt)
	}
	options.Runtime.ConsumeChallenge = func(ctx context.Context, identifier string) (storage.Record, error) {
		return host.ConsumeVerification(ctx, identifier)
	}
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	if input.Runtime.Adapter == nil {
		return nil, fmt.Errorf("passkey: Runtime.Adapter is required")
	}
	if input.Runtime.ResolveSession == nil {
		return nil, fmt.Errorf("passkey: Runtime.ResolveSession is required")
	}
	if input.Runtime.IssueSession == nil {
		return nil, fmt.Errorf("passkey: Runtime.IssueSession is required")
	}
	if input.Registration.Extensions != nil && input.Registration.ResolveExtensions != nil {
		return nil, fmt.Errorf("passkey: registration extensions and resolver are mutually exclusive")
	}
	if input.Authentication.Extensions != nil && input.Authentication.ResolveExtensions != nil {
		return nil, fmt.Errorf("passkey: authentication extensions and resolver are mutually exclusive")
	}

	options := input
	if input.Origins != nil {
		options.Origins = append([]string{}, input.Origins...)
	}
	options.Registration.Extensions = cloneMap(input.Registration.Extensions)
	options.Authentication.Extensions = cloneMap(input.Authentication.Extensions)
	options.Schema = input.Schema.Clone()
	if input.Advanced.ChallengeCookie != nil {
		challengeCookie := *input.Advanced.ChallengeCookie
		challengeCookie.Attributes = cloneCookieOptions(challengeCookie.Attributes)
		options.Advanced.ChallengeCookie = &challengeCookie
	}
	if input.AuthenticatorSelection != nil {
		selection := *input.AuthenticatorSelection
		if input.AuthenticatorSelection.RequireResidentKey != nil {
			required := *input.AuthenticatorSelection.RequireResidentKey
			selection.RequireResidentKey = &required
		}
		options.AuthenticatorSelection = &selection
	}
	if input.Registration.RequireSession != nil {
		required := *input.Registration.RequireSession
		options.Registration.RequireSession = &required
	}

	appName := options.AppName
	if appName == "" {
		appName = defaultAppName
	}
	rpName := options.RPName
	if rpName == "" {
		rpName = appName
	}
	rpID := options.RPID
	if rpID == "" && options.BaseURL != "" {
		parsed, err := url.Parse(options.BaseURL)
		if err != nil || parsed.Hostname() == "" {
			return nil, fmt.Errorf("passkey: invalid BaseURL %q", options.BaseURL)
		}
		rpID = parsed.Hostname()
	}
	if rpID == "" {
		rpID = "localhost"
	}
	secret := options.Secret
	if secret == "" {
		secret = defaultSecret
	}
	options.Secret = secret

	cookie, err := resolveChallengeCookie(options)
	if err != nil {
		return nil, err
	}
	schema, err := resolveSchema(options.Schema)
	if err != nil {
		return nil, fmt.Errorf("passkey: schema: %w", err)
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	random := options.Runtime.Random
	if random == nil {
		random = rand.Reader
	}
	registerVerifier := options.Runtime.VerifyRegistration
	if registerVerifier == nil {
		registerVerifier = webauthn.VerifyRegistrationResponse
	}
	authenticateVerifier := options.Runtime.VerifyAuthentication
	if authenticateVerifier == nil {
		authenticateVerifier = webauthn.VerifyAuthenticationResponse
	}

	return &plugin{
		options: options, schema: schema, rpID: rpID, rpName: rpName, cookie: cookie,
		clock: clock, random: &lockedReader{r: random},
		verifyRegister: registerVerifier, verifyAuthenticate: authenticateVerifier,
	}, nil
}

func resolveChallengeCookie(options Options) (ChallengeCookie, error) {
	if options.Advanced.ChallengeCookie != nil {
		cookie := *options.Advanced.ChallengeCookie
		if !cookies.ValidName(cookie.Name) {
			return ChallengeCookie{}, fmt.Errorf("passkey: invalid challenge cookie name %q", cookie.Name)
		}
		return cookie, nil
	}
	key := options.Advanced.WebAuthnChallengeCookie
	if key == "" {
		key = defaultCookieKey
	}
	prefix := options.Advanced.CookiePrefix
	if prefix == "" {
		prefix = defaultCookiePrefix
	}
	secure := strings.HasPrefix(options.BaseURL, "https://")
	name := prefix + "." + key
	if secure {
		name = cookies.SecurePrefix + name
	}
	if !cookies.ValidName(name) {
		return ChallengeCookie{}, fmt.Errorf("passkey: invalid challenge cookie name %q", name)
	}
	return ChallengeCookie{
		Name: name,
		Attributes: cookies.Options{
			Path: "/", HTTPOnly: true, Secure: secure, SameSite: "lax",
		},
	}, nil
}

func (p *plugin) challengeCookie(request contract.Request) (ChallengeCookie, error) {
	cookie := p.cookie
	if p.options.Runtime.ResolveChallengeCookie != nil {
		resolved, err := p.options.Runtime.ResolveChallengeCookie(request)
		if err != nil {
			return ChallengeCookie{}, err
		}
		cookie = resolved
	}
	if !cookies.ValidName(cookie.Name) {
		return ChallengeCookie{}, fmt.Errorf("passkey: invalid resolved challenge cookie name %q", cookie.Name)
	}
	cookie.Attributes = cloneCookieOptions(cookie.Attributes)
	return cookie, nil
}

func cloneMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = cloneExtensionValue(value)
	}
	return result
}

func cloneExtensionValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneExtensionValue(item)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	case []int:
		return append([]int(nil), typed...)
	case []bool:
		return append([]bool(nil), typed...)
	case []byte:
		return append([]byte(nil), typed...)
	default:
		return value
	}
}

func cloneCookieOptions(source cookies.Options) cookies.Options {
	result := source
	if source.MaxAge != nil {
		maxAge := *source.MaxAge
		result.MaxAge = &maxAge
	}
	if source.Expires != nil {
		expires := *source.Expires
		result.Expires = &expires
	}
	return result
}
