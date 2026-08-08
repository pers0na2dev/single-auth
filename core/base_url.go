package core

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
)

var validForwardedHost = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*(?::[0-9]{1,5})?$`)
var validForwardedIPv4 = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}(?::[0-9]{1,5})?$`)
var validForwardedIPv6 = regexp.MustCompile(`^\[[0-9A-Fa-f:]+\](?::[0-9]{1,5})?$`)

func baseURLFromEnvironment() string {
	for _, name := range []string{
		"SINGLE_AUTH_URL",
		"NEXT_PUBLIC_SINGLE_AUTH_URL",
		"PUBLIC_SINGLE_AUTH_URL",
		"NUXT_PUBLIC_SINGLE_AUTH_URL",
		"NUXT_PUBLIC_AUTH_URL",
		"BASE_URL",
	} {
		value := strings.TrimSpace(os.Getenv(name))
		if value != "" && !(name == "BASE_URL" && value == "/") {
			return value
		}
	}
	return ""
}

func staticBaseURL(value, basePath string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", &UpstreamError{message: fmt.Sprintf(
			"Invalid base URL: %s. Please provide a valid base URL.", value,
		)}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", &UpstreamError{message: fmt.Sprintf(
			"Invalid base URL: %s. URL must include 'http://' or 'https://'", value,
		)}
	}
	if parsed.Host == "" {
		return "", &UpstreamError{message: fmt.Sprintf(
			"Invalid base URL: %s. Please provide a valid base URL.", value,
		)}
	}
	parsed.Fragment = ""
	if strings.TrimRight(parsed.Path, "/") == "" {
		parsed.Path = normalizedBasePath(basePath)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func normalizedBasePath(path string) string {
	if path == "" {
		return defaultBasePath
	}
	if path == "/" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(path, "/")
}

func originOf(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func validProxyHost(host string) bool {
	if host == "" || strings.TrimSpace(host) != host || strings.Contains(host, "..") ||
		strings.ContainsRune(host, 0) || strings.ContainsAny(host, "<>'\"") ||
		strings.HasPrefix(host, ".") {
		return false
	}
	lower := strings.ToLower(host)
	if strings.Contains(lower, "javascript:") || strings.Contains(lower, "file:") || strings.Contains(lower, "data:") {
		return false
	}
	if !validForwardedHost.MatchString(host) && !validForwardedIPv4.MatchString(host) && !validForwardedIPv6.MatchString(host) {
		return false
	}
	if _, port, err := net.SplitHostPort(host); err == nil {
		var number int
		if _, scanErr := fmt.Sscanf(port, "%d", &number); scanErr != nil || number > 65535 {
			return false
		}
	}
	return true
}

func firstHeaderValue(value string) string {
	// upstream implementation rejects comma-separated proxy chains instead of selecting an
	// attacker-controlled element. Keep the value intact for validation.
	return strings.TrimSpace(value)
}

func trustedProxyHeaders(options AdvancedOptions, dynamic bool) bool {
	if options.TrustedProxyHeaders != nil {
		return *options.TrustedProxyHeaders
	}
	return dynamic
}

func requestHost(request contract.Request, trustProxy bool) string {
	if trustProxy {
		if value, ok := request.Headers().Get("X-Forwarded-Host"); ok {
			value = firstHeaderValue(value)
			if validProxyHost(value) {
				return value
			}
		}
	}
	host := strings.TrimSpace(request.Host())
	if host == "" {
		if value, ok := request.Headers().Get("Host"); ok {
			host = strings.TrimSpace(value)
		}
	}
	if validProxyHost(host) {
		return host
	}
	return ""
}

func requestProtocol(request contract.Request, configured string, trustProxy bool, host string) string {
	if configured == "http" || configured == "https" {
		return configured
	}
	if trustProxy {
		if value, ok := request.Headers().Get("X-Forwarded-Proto"); ok {
			value = firstHeaderValue(value)
			if value == "http" || value == "https" {
				return value
			}
		}
	}
	if request.Scheme() == "http" || request.Scheme() == "https" {
		return request.Scheme()
	}
	if isLoopbackHost(host) {
		return "http"
	}
	return "https"
}

func stripHostProtocol(value string) string {
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if index := strings.IndexByte(value, '/'); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(value)
}

func matchesHostPattern(host, pattern string) bool {
	host = stripHostProtocol(host)
	pattern = stripHostProtocol(pattern)
	if host == "" || pattern == "" {
		return false
	}
	if strings.ContainsAny(pattern, "*?") {
		return wildcardMatch(pattern, host)
	}
	return strings.EqualFold(host, pattern)
}

func isLoopbackHost(host string) bool {
	host = stripHostProtocol(host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = strings.Trim(parsedHost, "[]")
	} else {
		host = strings.Trim(host, "[]")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *Auth) resolveBaseURLForRequest(request contract.Request) (string, error) {
	if a.options.BaseURL != "" {
		return staticBaseURL(a.options.BaseURL, a.options.BasePath)
	}
	if config := a.options.DynamicBaseURL; config != nil {
		trustProxy := trustedProxyHeaders(a.options.Advanced, true)
		host := requestHost(request, trustProxy)
		if host == "" {
			if config.Fallback != "" {
				return staticBaseURL(config.Fallback, a.options.BasePath)
			}
			return "", errors.New("Could not determine host from request headers. Please provide a fallback URL in your baseURL config.")
		}
		allowed := false
		for _, pattern := range config.AllowedHosts {
			if matchesHostPattern(host, pattern) {
				allowed = true
				break
			}
		}
		if !allowed {
			if config.Fallback != "" {
				return staticBaseURL(config.Fallback, a.options.BasePath)
			}
			return "", fmt.Errorf(
				"Host %q is not in the allowed hosts list. Allowed hosts: %s. Add this host to your allowedHosts config or provide a fallback URL.",
				host, strings.Join(config.AllowedHosts, ", "),
			)
		}
		protocol := requestProtocol(request, config.Protocol, trustProxy, host)
		return staticBaseURL(protocol+"://"+host, a.options.BasePath)
	}

	trustProxy := trustedProxyHeaders(a.options.Advanced, false)
	host := requestHost(request, trustProxy)
	if host == "" {
		return "", errors.New("single-auth: could not get base URL from request")
	}
	protocol := requestProtocol(request, "auto", trustProxy, host)
	return staticBaseURL(protocol+"://"+host, a.options.BasePath)
}

func (a *Auth) baseOriginForRequest(request contract.Request) string {
	resolved, err := a.resolveBaseURLForRequest(request)
	if err != nil {
		return ""
	}
	return originOf(resolved)
}

func dynamicTrustedOrigins(config DynamicBaseURLOptions) []string {
	trusted := make([]string, 0, len(config.AllowedHosts)*2+1)
	for _, host := range config.AllowedHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") {
			trusted = append(trusted, host)
			continue
		}
		if config.Protocol == "" || config.Protocol == "https" || config.Protocol == "auto" {
			trusted = append(trusted, "https://"+host)
		}
		if config.Protocol == "http" || config.Protocol == "auto" || isLoopbackHost(host) {
			trusted = append(trusted, "http://"+host)
		}
	}
	if config.Fallback != "" {
		if origin := originOf(config.Fallback); origin != "" {
			trusted = append(trusted, origin)
		}
	}
	return trusted
}
