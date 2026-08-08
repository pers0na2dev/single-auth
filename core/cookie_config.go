package core

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
)

func resolveCookies(options Options) (cookieConfig, error) {
	builder, err := newCookieBuilder(options)
	if err != nil {
		return cookieConfig{}, err
	}

	sessionSeconds := durationSeconds(options.Session.ExpiresIn)
	cacheSeconds := durationSeconds(options.Session.CookieCache.MaxAge)
	stateSeconds := 5 * 60
	oauthStateSeconds := 10 * 60
	sessionName, session := builder.cookie("session_token", "session_token", &sessionSeconds)
	sessionDataName, sessionData := builder.cookie("session_data", "session_data", &cacheSeconds)
	dontRememberName, dontRemember := builder.cookie("dont_remember", "dont_remember", nil)
	stateName, state := builder.cookie("state", "state", &stateSeconds)
	oauthStateName, oauthState := builder.cookie("oauth_state", "oauth_state", &oauthStateSeconds)
	accountDataName, accountData := builder.cookie("account_data", "account_data", &cacheSeconds)
	return cookieConfig{
		sessionToken:     session,
		sessionName:      sessionName,
		sessionData:      sessionData,
		sessionDataName:  sessionDataName,
		dontRemember:     dontRemember,
		dontRememberName: dontRememberName,
		state:            state,
		stateName:        stateName,
		oauthState:       oauthState,
		oauthStateName:   oauthStateName,
		accountData:      accountData,
		accountDataName:  accountDataName,
	}, nil
}

type cookieBuilder struct {
	securePrefix string
	prefix       string
	base         cookies.Options
	overrides    map[string]CookieOverride
}

func newCookieBuilder(options Options) (cookieBuilder, error) {
	secure := strings.EqualFold(options.Environment, "production")
	if options.Advanced.UseSecureCookies != nil {
		secure = *options.Advanced.UseSecureCookies
	} else if options.DynamicBaseURL != nil {
		switch options.DynamicBaseURL.Protocol {
		case "https":
			secure = true
		case "http":
			secure = false
		}
	} else if options.BaseURL != "" {
		parsed, err := url.Parse(options.BaseURL)
		if err != nil {
			return cookieBuilder{}, fmt.Errorf("single-auth: invalid base URL: %w", err)
		}
		secure = strings.EqualFold(parsed.Scheme, "https")
	}
	prefix := options.Advanced.CookiePrefix
	if prefix == "" {
		prefix = "single-auth"
	}
	securePrefix := ""
	if secure {
		securePrefix = cookies.SecurePrefix
	}

	base := cookies.Options{
		Path:     "/",
		Secure:   secure,
		HTTPOnly: true,
		SameSite: "lax",
	}
	crossSubDomain := options.Advanced.CrossSubDomainCookies
	if crossSubDomain.Enabled {
		domain := crossSubDomain.Domain
		if domain == "" && options.BaseURL != "" {
			parsed, err := url.Parse(options.BaseURL)
			if err != nil || parsed.Hostname() == "" {
				return cookieBuilder{}, fmt.Errorf("single-auth: invalid base URL for cross-subdomain cookies")
			}
			domain = parsed.Hostname()
		}
		if domain == "" && options.DynamicBaseURL == nil {
			return cookieBuilder{}, fmt.Errorf("single-auth: base URL is required when cross-subdomain cookies are enabled")
		}
		base.Domain = domain
	}
	base = applyCookieOverride(base, options.Advanced.DefaultCookieAttributes)
	return cookieBuilder{
		securePrefix: securePrefix,
		prefix:       prefix,
		base:         base,
		overrides:    options.Advanced.Cookies,
	}, nil
}

func (builder cookieBuilder) cookie(key, suffix string, maxAge *int) (string, cookies.Options) {
	value := builder.base
	value.MaxAge = maxAge
	override := builder.overrides[key]
	value = applyCookieOverride(value, override)
	name := builder.securePrefix + builder.prefix + "." + suffix
	if override.Name != "" {
		name = builder.securePrefix + override.Name
	}
	return name, value
}

func (a *Auth) cookiesForRequest(request contract.Request) cookieConfig {
	if a == nil {
		return cookieConfig{}
	}
	if a.options.DynamicBaseURL == nil ||
		!a.options.Advanced.CrossSubDomainCookies.Enabled {
		return a.options.cookie
	}
	baseURL, err := a.resolveBaseURLForRequest(request)
	if err != nil || baseURL == "" {
		return a.options.cookie
	}
	options := a.options.Options
	options.BaseURL = baseURL
	options.DynamicBaseURL = nil
	resolved, err := resolveCookies(options)
	if err != nil {
		return a.options.cookie
	}
	return resolved
}

func (a *Auth) pluginCookieForRequest(
	request contract.Request,
	key string,
	suffix string,
) (string, cookies.Options) {
	if a == nil {
		return "", cookies.Options{}
	}
	options := a.options.Options
	if options.DynamicBaseURL != nil && options.Advanced.CrossSubDomainCookies.Enabled {
		if baseURL, err := a.resolveBaseURLForRequest(request); err == nil && baseURL != "" {
			options.BaseURL = baseURL
			options.DynamicBaseURL = nil
		}
	}
	builder, err := newCookieBuilder(options)
	if err != nil {
		return "", cookies.Options{}
	}
	return builder.cookie(key, suffix, nil)
}

func applyCookieOverride(base cookies.Options, override CookieOverride) cookies.Options {
	if override.MaxAge != nil {
		base.MaxAge = intPointer(*override.MaxAge)
	}
	if override.Expires != nil {
		value := *override.Expires
		base.Expires = &value
	}
	if override.Domain != nil {
		base.Domain = *override.Domain
	}
	if override.Path != nil {
		base.Path = *override.Path
	}
	if override.Secure != nil {
		base.Secure = *override.Secure
	}
	if override.HTTPOnly != nil {
		base.HTTPOnly = *override.HTTPOnly
	}
	if override.Partitioned != nil {
		base.Partitioned = *override.Partitioned
	}
	if override.SameSite != nil {
		base.SameSite = *override.SameSite
	}
	return base
}

func durationSeconds(value interface{ Seconds() float64 }) int {
	return int(value.Seconds())
}

func intPointer(value int) *int { return &value }
