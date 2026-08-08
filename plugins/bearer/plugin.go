package bearer

import (
	"fmt"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const bearerPrefixLength = len("bearer ")

type plugin struct {
	options Options
}

// New validates and snapshots a single-auth bearer plugin.
func New(options Options) (engine.Plugin, error) {
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "bearer", Version: Version,
		Hooks: engine.Hooks{
			Before: []engine.BeforeHook{{
				Matcher: implementation.matchesAuthorization,
				Handler: implementation.authorizationToCookie,
			}},
			After: []engine.AfterHook{{
				Matcher: func(*engine.Context) (bool, error) { return true, nil },
				Handler: implementation.cookieToAuthorization,
			}},
		},
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

// NewFactory binds the bearer plugin to the final root secret and
// request-scoped session cookie configuration during singleauth.New.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "bearer" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Secret = host.Secret
	options.Runtime.ResolveSessionCookie = func(request contract.Request) string {
		name, _ := host.SessionCookie(request)
		return name
	}
	name, _ := host.SessionCookie(contract.Request{})
	options.Runtime.SessionCookieName = name
	return New(options)
}

func normalize(options Options) (*plugin, error) {
	if options.Runtime.Secret == "" {
		return nil, fmt.Errorf("bearer: Runtime.Secret is required")
	}
	if options.Runtime.ResolveSessionCookie == nil && !cookies.ValidName(options.Runtime.SessionCookieName) {
		return nil, fmt.Errorf(
			"bearer: Runtime.SessionCookieName %q is invalid",
			options.Runtime.SessionCookieName,
		)
	}
	return &plugin{options: options}, nil
}

func (p *plugin) sessionCookieName(request contract.Request) (string, error) {
	name := p.options.Runtime.SessionCookieName
	if p.options.Runtime.ResolveSessionCookie != nil {
		name = p.options.Runtime.ResolveSessionCookie(request)
	}
	if !cookies.ValidName(name) {
		return "", fmt.Errorf("bearer: resolved session cookie name %q is invalid", name)
	}
	return name, nil
}

func (p *plugin) matchesAuthorization(ctx *engine.Context) (bool, error) {
	value := combinedHeaderValue(ctx.Request().Headers(), "Authorization")
	return value != "", nil
}

func (p *plugin) authorizationToCookie(ctx *engine.Context) (*contract.Response, error) {
	request := ctx.Request()
	sessionCookieName, err := p.sessionCookieName(request)
	if err != nil {
		return nil, err
	}
	authorization := combinedHeaderValue(request.Headers(), "Authorization")
	if !hasBearerScheme(authorization) {
		return nil, nil
	}
	token := trimJavaScriptSpace(authorization[bearerPrefixLength:])
	if token == "" {
		return nil, nil
	}

	var decodedToken string
	if strings.Contains(token, ".") {
		if strings.Contains(token, "%") {
			decodedToken = tryDecodeURIComponent(token)
		} else {
			decodedToken = token
		}
	} else {
		if p.options.RequireSignature {
			return nil, nil
		}
		decodedToken = signCookieValue(token, p.options.Runtime.Secret)
	}
	if !verifySignedCookie(decodedToken, p.options.Runtime.Secret) {
		return nil, nil
	}

	headers := request.Headers()
	existingCookie := strings.Join(headers.Values("Cookie"), "; ")
	headers.Set("Cookie", cookies.SetRequestCookie(
		existingCookie,
		sessionCookieName,
		decodedToken,
	))
	ctx.ReplaceRequest(request.WithHeaders(headers))
	return nil, nil
}

func (p *plugin) cookieToAuthorization(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	sessionCookieName, err := p.sessionCookieName(ctx.Request())
	if err != nil {
		return nil, err
	}
	setCookieValues := response.Headers().Values("Set-Cookie")
	if len(setCookieValues) == 0 {
		return nil, nil
	}
	parsed := cookies.ParseSetCookieHeader(strings.Join(setCookieValues, ", "))
	var sessionCookie *cookies.SetCookie
	for index := range parsed {
		if parsed[index].Name == sessionCookieName {
			candidate := parsed[index]
			sessionCookie = &candidate
		}
	}
	if sessionCookie == nil || sessionCookie.Attributes.Value == "" ||
		(sessionCookie.Attributes.MaxAge != nil && *sessionCookie.Attributes.MaxAge == 0) {
		return nil, nil
	}

	exposed := combinedHeaderValue(response.Headers(), "Access-Control-Expose-Headers")
	ctx.SetResponseHeader("set-auth-token", sessionCookie.Attributes.Value)
	ctx.SetResponseHeader("Access-Control-Expose-Headers", mergeExposedHeaders(exposed))
	return nil, nil
}

func combinedHeaderValue(headers contract.Headers, name string) string {
	return strings.Join(headers.Values(name), ", ")
}

func mergeExposedHeaders(value string) string {
	ordered := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for _, header := range strings.Split(value, ",") {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		if _, exists := seen[header]; exists {
			continue
		}
		seen[header] = struct{}{}
		ordered = append(ordered, header)
	}
	if _, exists := seen["set-auth-token"]; !exists {
		ordered = append(ordered, "set-auth-token")
	}
	return strings.Join(ordered, ", ")
}
