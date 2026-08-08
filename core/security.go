package core

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

var relativeRedirectPattern = regexp.MustCompile(`^/[A-Za-z0-9_\-.+/@]*(?:\?[A-Za-z0-9_\-.+/=&%@]*)?$`)

const originBackwardCompatWarning = "[Deprecation] disableOriginCheck: true currently also disables CSRF checks. " +
	"In a future version, disableOriginCheck will ONLY disable URL validation. " +
	"To keep CSRF disabled, add disableCSRFCheck: true to your config."

func (a *Auth) securityMiddleware() engine.Middleware {
	var backwardCompatWarning sync.Once
	return engine.Middleware{
		Name: "single-auth-origin-check",
		Path: "/**",
		Handler: func(ctx *engine.Context, next engine.Next) (contract.Response, error) {
			request := ctx.Request()
			if a.options.DynamicBaseURL != nil {
				if _, err := a.resolveBaseURLForRequest(request); err != nil {
					apiErr := internalServerError(err)
					return contract.ResponseFromError(apiErr), apiErr
				}
			}
			switch request.Method() {
			case "GET", "HEAD", "OPTIONS":
				return next()
			}
			if a.usesBackwardCompatibleOriginCSRF() {
				backwardCompatWarning.Do(func() {
					a.logger.Warn(originBackwardCompatWarning)
				})
			}
			if !a.shouldSkipCSRF(ctx) {
				if err := a.validateRequestCSRF(ctx); err != nil {
					return contract.ResponseFromError(err), err
				}
			}
			if !a.shouldSkipOrigin(ctx) {
				if err := a.validateRedirectFields(request); err != nil {
					return contract.ResponseFromError(err), err
				}
			}
			return next()
		},
	}
}

func optionEnabled(value *bool) bool { return value != nil && *value }

func (a *Auth) skipsOriginPath(path string) bool {
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	for _, skip := range a.options.Advanced.SkipOriginCheckPaths {
		skip = strings.TrimRight(skip, "/")
		if skip == "" {
			skip = "/"
		}
		if path == skip || (skip != "/" && strings.HasPrefix(path, skip+"/")) {
			return true
		}
	}
	return false
}

func (a *Auth) shouldSkipOrigin(ctx *engine.Context) bool {
	return optionEnabled(a.options.Advanced.DisableOriginCheck) || a.skipsOriginPath(ctx.RoutePath())
}

func (a *Auth) shouldSkipCSRF(ctx *engine.Context) bool {
	if optionEnabled(a.options.Advanced.DisableCSRFCheck) || a.skipsOriginPath(ctx.RoutePath()) {
		return true
	}
	// Backward compatibility in upstream implementation 1.6: disableOriginCheck also
	// disables CSRF when disableCSRFCheck was omitted. A non-nil false pointer
	// opts into the separated semantics.
	return a.usesBackwardCompatibleOriginCSRF()
}

func (a *Auth) usesBackwardCompatibleOriginCSRF() bool {
	return optionEnabled(a.options.Advanced.DisableOriginCheck) &&
		a.options.Advanced.DisableCSRFCheck == nil
}

func (a *Auth) validateRequestCSRF(ctx *engine.Context) error {
	return a.validateRequestCSRFWithFormScope(ctx, false)
}

func (a *Auth) validateFormRequestCSRF(ctx *engine.Context) error {
	return a.validateRequestCSRFWithFormScope(ctx, true)
}

func (a *Auth) validateRequestCSRFWithFormScope(ctx *engine.Context, forceForm bool) error {
	if a.shouldSkipCSRF(ctx) {
		return nil
	}
	if a.shouldSkipOrigin(ctx) {
		return nil
	}
	request := ctx.Request()
	hasCookies := request.Headers().Has("Cookie")
	if hasCookies {
		return a.validateOriginHeader(request, false)
	}
	formEndpoint := forceForm || ctx.RoutePath() == "/sign-in/email" || ctx.RoutePath() == "/sign-up/email"
	if !formEndpoint {
		return nil
	}
	site := requestHeader(request, "Sec-Fetch-Site")
	mode := requestHeader(request, "Sec-Fetch-Mode")
	dest := requestHeader(request, "Sec-Fetch-Dest")
	hasMetadata := strings.TrimSpace(site) != "" || strings.TrimSpace(mode) != "" || strings.TrimSpace(dest) != ""
	if hasMetadata {
		if site == "cross-site" && mode == "navigate" {
			return baseError(contract.StatusForbidden, ErrorCrossSiteNavigationLoginBlocked)
		}
		return a.validateOriginHeader(request, true)
	}
	if requestHeader(request, "Origin") != "" || requestHeader(request, "Referer") != "" {
		return a.validateOriginHeader(request, true)
	}
	return nil
}

func (a *Auth) validateOriginHeader(request contract.Request, force bool) error {
	if !force && !request.Headers().Has("Cookie") {
		return nil
	}
	origin := requestHeader(request, "Origin")
	if origin == "" {
		origin = requestHeader(request, "Referer")
	}
	if origin == "" || origin == "null" {
		return baseError(contract.StatusForbidden, ErrorMissingOrNullOrigin)
	}
	trustedOrigins, err := a.trustedOrigins(request)
	if err != nil {
		return internalServerError(err)
	}
	for _, trusted := range trustedOrigins {
		if matchesOriginPattern(origin, trusted, false) {
			return nil
		}
	}
	return baseError(contract.StatusForbidden, ErrorInvalidOrigin)
}

func (a *Auth) validateRedirectFields(request contract.Request) error {
	bodyValues := make(map[string]any)
	if body, err := decodeObjectBody(request); err == nil {
		for key, value := range body {
			bodyValues[key] = value
		}
	}
	queryValues := make(map[string]any)
	if query, err := request.Query(); err == nil {
		for key, entries := range query {
			if len(entries) == 1 {
				queryValues[key] = entries[0]
			} else if len(entries) > 1 {
				queryValues[key] = append([]string(nil), entries...)
			}
		}
	}
	checks := []struct {
		field      string
		label      string
		allowQuery bool
		code       ErrorCode
	}{
		{"callbackURL", "callbackURL", true, ErrorInvalidCallbackURL},
		{"redirectTo", "redirectURL", false, ErrorInvalidRedirectURL},
		{"errorCallbackURL", "errorCallbackURL", false, ErrorInvalidErrorCallbackURL},
		{"newUserCallbackURL", "newUserCallbackURL", false, ErrorInvalidNewUserCallbackURL},
	}
	for _, check := range checks {
		value, exists := bodyValues[check.field]
		if (!exists || value == nil || value == "") && check.allowQuery {
			value, exists = queryValues[check.field]
		}
		if !exists || value == nil || value == "" {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return contract.NewAPIError(
				contract.StatusBadRequest,
				"BAD_REQUEST",
				"Invalid "+check.label+": expected a string",
			)
		}
		if err := a.validateRedirectCandidate(request, text, check.field); err != nil {
			return err
		}
	}
	return nil
}

func (a *Auth) validateRedirectCandidate(request contract.Request, candidate, field string) error {
	trustedOrigins, err := a.trustedOrigins(request)
	if err != nil {
		return internalServerError(err)
	}
	for _, pattern := range trustedOrigins {
		if matchesOriginPattern(candidate, pattern, true) {
			return nil
		}
	}
	code := ErrorInvalidCallbackURL
	switch field {
	case "redirectTo", "redirectURL":
		code = ErrorInvalidRedirectURL
	case "errorCallbackURL":
		code = ErrorInvalidErrorCallbackURL
	case "newUserCallbackURL":
		code = ErrorInvalidNewUserCallbackURL
	}
	return baseError(contract.StatusForbidden, code)
}

func (a *Auth) trustedOrigins(request contract.Request) ([]string, error) {
	trusted := make([]string, 0, len(a.options.TrustedOrigins)+4)
	switch {
	case a.options.DynamicBaseURL != nil:
		trusted = append(trusted, dynamicTrustedOrigins(*a.options.DynamicBaseURL)...)
	case a.options.BaseURL != "":
		resolved, err := staticBaseURL(a.options.BaseURL, a.options.BasePath)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, originOf(resolved))
	default:
		resolved, err := a.resolveBaseURLForRequest(request)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, originOf(resolved))
	}
	trusted = append(trusted, a.options.TrustedOrigins...)
	trusted = append(trusted, a.options.pluginTrustedOrigins...)
	if a.options.ResolveTrustedOrigins != nil {
		resolved, err := a.options.ResolveTrustedOrigins(request.Context(), request.Clone())
		if err != nil {
			return nil, fmt.Errorf("single-auth: resolve trusted origins: %w", err)
		}
		trusted = append(trusted, resolved...)
	}
	for _, resolver := range a.options.pluginTrustedOriginResolvers {
		resolved, err := resolver(request.Context(), request.Clone())
		if err != nil {
			return nil, fmt.Errorf("single-auth: resolve plugin trusted origins: %w", err)
		}
		trusted = append(trusted, resolved...)
	}
	if configured := os.Getenv("SINGLE_AUTH_TRUSTED_ORIGINS"); configured != "" {
		trusted = append(trusted, strings.Split(configured, ",")...)
	}
	filtered := trusted[:0]
	for _, value := range trusted {
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	return filtered, nil
}

func mergePluginTrustedOrigins(options *runtimeOptions, plugin engine.Plugin) {
	if options == nil {
		return
	}
	options.pluginTrustedOrigins = append(
		options.pluginTrustedOrigins,
		plugin.TrustedOrigins...,
	)
	if plugin.ResolveTrustedOrigins != nil {
		options.pluginTrustedOriginResolvers = append(
			options.pluginTrustedOriginResolvers,
			TrustedOriginsResolver(plugin.ResolveTrustedOrigins),
		)
	}
	options.Advanced.SkipOriginCheckPaths = append(
		options.Advanced.SkipOriginCheckPaths,
		plugin.SkipOriginCheckPaths...,
	)
}

func matchesOriginPattern(candidate, pattern string, allowRelative bool) bool {
	if strings.HasPrefix(candidate, "/") {
		if !allowRelative {
			return false
		}
		lower := strings.ToLower(candidate)
		return relativeRedirectPattern.MatchString(candidate) &&
			!strings.HasPrefix(candidate, "//") &&
			!strings.Contains(candidate, "\\") &&
			!strings.Contains(lower, "%2f") &&
			!strings.Contains(lower, "%5c")
	}
	candidateURL, candidateErr := url.Parse(candidate)
	if candidateErr != nil {
		return false
	}
	if strings.ContainsAny(pattern, "*?") {
		if candidateURL.Host == "" {
			return false
		}
		sample := candidateURL.Host
		if strings.Contains(pattern, "://") {
			if candidateURL.Scheme == "http" || candidateURL.Scheme == "https" {
				sample = candidateURL.Scheme + "://" + candidateURL.Host
			} else {
				sample = candidate
			}
		}
		return wildcardMatch(pattern, sample)
	}
	if candidateURL.Scheme == "http" || candidateURL.Scheme == "https" || candidateURL.Scheme == "" {
		if candidateURL.Host == "" {
			return false
		}
		return pattern == candidateURL.Scheme+"://"+candidateURL.Host
	}
	return strings.HasPrefix(candidate, pattern)
}

func wildcardMatch(pattern, sample string) bool {
	var expression strings.Builder
	expression.WriteByte('^')
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				expression.WriteString(".*")
				index++
			} else {
				expression.WriteString(`[^/\\]*`)
			}
		case '?':
			expression.WriteString(`[^/\\]`)
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
		}
	}
	expression.WriteString(`[/\\]*$`)
	compiled, err := regexp.Compile(expression.String())
	return err == nil && compiled.MatchString(sample)
}
