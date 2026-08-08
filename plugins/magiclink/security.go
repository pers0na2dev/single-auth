package magiclink

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

var relativeRedirectPattern = regexp.MustCompile(`^/[A-Za-z0-9_\-.+/@]*(?:\?[A-Za-z0-9_\-.+/=&%@]*)?$`)

func (p *plugin) sendMiddleware(ctx *engine.Context, next engine.Next) (contract.Response, error) {
	if validator := p.options.Runtime.ValidateFormRequest; validator != nil {
		if err := validator(ctx); err != nil {
			return contract.ResponseFromError(err), err
		}
	} else if err := p.validateFormCSRF(ctx); err != nil {
		return contract.ResponseFromError(err), err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	for _, field := range []struct {
		name string
		kind RedirectKind
	}{
		{"callbackURL", RedirectCallback},
		{"newUserCallbackURL", RedirectNewUser},
		{"errorCallbackURL", RedirectError},
	} {
		value, valueErr := optionalString(body, field.name)
		if valueErr != nil {
			return contract.ResponseFromError(valueErr), valueErr
		}
		if value == nil || *value == "" {
			continue
		}
		if validationErr := p.validateRedirect(ctx, *value, field.kind); validationErr != nil {
			return contract.ResponseFromError(validationErr), validationErr
		}
	}
	return next()
}

func (p *plugin) verifyRedirectMiddleware(ctx *engine.Context, next engine.Next) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		err := validationError("Invalid query")
		return contract.ResponseFromError(err), err
	}
	for _, field := range []struct {
		name string
		kind RedirectKind
	}{
		{"callbackURL", RedirectCallback},
		{"newUserCallbackURL", RedirectNewUser},
		{"errorCallbackURL", RedirectError},
	} {
		value := query.Get(field.name)
		if value == "" {
			value = "/"
		} else {
			value, err = url.PathUnescape(value)
			if err != nil {
				err := validationError("Invalid " + field.name)
				return contract.ResponseFromError(err), err
			}
		}
		if validationErr := p.validateRedirect(ctx, value, field.kind); validationErr != nil {
			return contract.ResponseFromError(validationErr), validationErr
		}
	}
	return next()
}

func (p *plugin) validateFormCSRF(ctx *engine.Context) error {
	request := ctx.Request()
	headers := request.Headers()
	site, _ := headers.Get("Sec-Fetch-Site")
	mode, _ := headers.Get("Sec-Fetch-Mode")
	destination, _ := headers.Get("Sec-Fetch-Dest")
	if site == "cross-site" && mode == "navigate" {
		return apiError(
			contract.StatusForbidden,
			"CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
			"Cross-site navigation login blocked. This request appears to be a CSRF attack.",
		)
	}
	origin, _ := headers.Get("Origin")
	if origin == "" {
		origin, _ = headers.Get("Referer")
	}
	hasMetadata := strings.TrimSpace(site) != "" || strings.TrimSpace(mode) != "" || strings.TrimSpace(destination) != ""
	if !headers.Has("Cookie") && !hasMetadata && origin == "" {
		return nil
	}
	if origin == "" || origin == "null" {
		return apiError(contract.StatusForbidden, "MISSING_OR_NULL_ORIGIN", "Missing or null Origin")
	}
	trusted, err := p.trustedOrigins(ctx)
	if err != nil {
		return internalError(err)
	}
	for _, pattern := range trusted {
		if matchesOriginPattern(origin, pattern, false) {
			return nil
		}
	}
	return apiError(contract.StatusForbidden, "INVALID_ORIGIN", "Invalid origin")
}

func (p *plugin) validateRedirect(ctx *engine.Context, candidate string, kind RedirectKind) error {
	if validator := p.options.Runtime.ValidateRedirect; validator != nil {
		return validator(ctx, candidate, kind)
	}
	trusted, err := p.trustedOrigins(ctx)
	if err != nil {
		return internalError(err)
	}
	for _, pattern := range trusted {
		if matchesOriginPattern(candidate, pattern, true) {
			return nil
		}
	}
	code, message := redirectError(kind)
	return apiError(contract.StatusForbidden, code, message)
}

func redirectError(kind RedirectKind) (string, string) {
	switch kind {
	case RedirectNewUser:
		return "INVALID_NEW_USER_CALLBACK_URL", "Invalid newUserCallbackURL"
	case RedirectError:
		return "INVALID_ERROR_CALLBACK_URL", "Invalid errorCallbackURL"
	default:
		return "INVALID_CALLBACK_URL", "Invalid callbackURL"
	}
}

func (p *plugin) trustedOrigins(ctx *engine.Context) ([]string, error) {
	base, err := p.resolveBaseURL(ctx)
	if err != nil {
		return nil, err
	}
	trusted := make([]string, 0, len(p.options.Runtime.TrustedOrigins)+2)
	trusted = append(trusted, base.Scheme+"://"+base.Host)
	trusted = append(trusted, p.options.Runtime.TrustedOrigins...)
	if resolver := p.options.Runtime.ResolveTrustedOrigins; resolver != nil {
		resolved, resolveErr := resolver(ctx.GoContext(), ctx.Request())
		if resolveErr != nil {
			return nil, fmt.Errorf("magiclink: resolve trusted origins: %w", resolveErr)
		}
		trusted = append(trusted, resolved...)
	}
	return trusted, nil
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
	candidateURL, err := url.Parse(candidate)
	if err != nil {
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
