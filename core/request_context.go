package core

import (
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const endpointAuthContextKey = "single-auth.endpoint.auth-context"

// AuthCookie describes one request-scoped upstream implementation cookie declaration.
// Attributes is copied when the context is created and whenever it is read.
type AuthCookie struct {
	Name       string
	Attributes cookies.Options
}

// RequestAuthCookies contains the core cookie declarations available to an
// endpoint for the current request. Dynamic base URLs may produce a different
// Domain for every request.
type RequestAuthCookies struct {
	SessionToken AuthCookie
	SessionData  AuthCookie
	DontRemember AuthCookie
	State        AuthCookie
	OAuthState   AuthCookie
	AccountData  AuthCookie
}

// RequestAuthContext is the request-local counterpart of upstream implementation's
// AuthContext. It exposes the resolved public URL, the resolved option
// snapshot, trusted origins, cookie declarations, and the internal adapter to
// hooks and plugin endpoints without mutating the shared Auth runtime.
type RequestAuthContext struct {
	BaseURL         string
	Options         Options
	TrustedOrigins  []string
	AuthCookies     RequestAuthCookies
	InternalAdapter InternalAdapter
}

// RequestContextFromEndpoint returns an independent snapshot of the auth
// context associated with an engine endpoint invocation.
func RequestContextFromEndpoint(ctx *engine.Context) (RequestAuthContext, bool) {
	if ctx == nil {
		return RequestAuthContext{}, false
	}
	value, exists := ctx.Value(endpointAuthContextKey)
	snapshot, valid := value.(RequestAuthContext)
	if !exists || !valid {
		return RequestAuthContext{}, false
	}
	return cloneRequestAuthContext(snapshot), true
}

func (a *Auth) requestAuthContext(ctx *engine.Context) (RequestAuthContext, error) {
	request := ctx.Request()
	resolvedBaseURL := ""
	shouldResolve := a.options.BaseURL != "" || a.options.DynamicBaseURL != nil ||
		request.Host() != ""
	if !shouldResolve {
		_, shouldResolve = request.Headers().Get("Host")
	}
	if shouldResolve {
		var err error
		resolvedBaseURL, err = a.resolveBaseURLForRequest(request)
		if err != nil {
			return RequestAuthContext{}, err
		}
	}

	trustedOrigins, err := a.trustedOrigins(request)
	if err != nil {
		// Direct calls without any URL source historically remain valid. There
		// is no request-specific origin to expose in that case.
		if shouldResolve {
			return RequestAuthContext{}, err
		}
		trustedOrigins = nil
	}

	options := cloneOptions(a.options.Options)
	if resolvedBaseURL != "" {
		options.BaseURL = originOf(resolvedBaseURL)
		options.DynamicBaseURL = nil
	}
	cookieConfig := a.cookiesForRequest(request)
	return RequestAuthContext{
		BaseURL:         resolvedBaseURL,
		Options:         options,
		TrustedOrigins:  append([]string(nil), trustedOrigins...),
		AuthCookies:     requestCookies(cookieConfig),
		InternalAdapter: a.InternalAdapter(),
	}, nil
}

func requestCookies(config cookieConfig) RequestAuthCookies {
	return RequestAuthCookies{
		SessionToken: AuthCookie{Name: config.sessionName, Attributes: cloneRequestCookieOptions(config.sessionToken)},
		SessionData:  AuthCookie{Name: config.sessionDataName, Attributes: cloneRequestCookieOptions(config.sessionData)},
		DontRemember: AuthCookie{Name: config.dontRememberName, Attributes: cloneRequestCookieOptions(config.dontRemember)},
		State:        AuthCookie{Name: config.stateName, Attributes: cloneRequestCookieOptions(config.state)},
		OAuthState:   AuthCookie{Name: config.oauthStateName, Attributes: cloneRequestCookieOptions(config.oauthState)},
		AccountData:  AuthCookie{Name: config.accountDataName, Attributes: cloneRequestCookieOptions(config.accountData)},
	}
}

func cloneRequestAuthContext(source RequestAuthContext) RequestAuthContext {
	clone := source
	clone.Options = cloneOptions(source.Options)
	clone.TrustedOrigins = append([]string(nil), source.TrustedOrigins...)
	clone.AuthCookies = RequestAuthCookies{
		SessionToken: cloneAuthCookie(source.AuthCookies.SessionToken),
		SessionData:  cloneAuthCookie(source.AuthCookies.SessionData),
		DontRemember: cloneAuthCookie(source.AuthCookies.DontRemember),
		State:        cloneAuthCookie(source.AuthCookies.State),
		OAuthState:   cloneAuthCookie(source.AuthCookies.OAuthState),
		AccountData:  cloneAuthCookie(source.AuthCookies.AccountData),
	}
	return clone
}

func cloneAuthCookie(source AuthCookie) AuthCookie {
	return AuthCookie{Name: source.Name, Attributes: cloneRequestCookieOptions(source.Attributes)}
}

func cloneRequestCookieOptions(source cookies.Options) cookies.Options {
	clone := source
	if source.MaxAge != nil {
		value := *source.MaxAge
		clone.MaxAge = &value
	}
	if source.Expires != nil {
		value := *source.Expires
		clone.Expires = &value
	}
	return clone
}
