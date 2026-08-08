// Package coreurl provides the reference implementation-compatible URL normalization and
// redirect-URI safety checks.
package coreurl

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/internal/hostutil"
)

var (
	// ErrURLNotParseable indicates that a value is not an absolute URL.
	ErrURLNotParseable = errors.New("URL must be parseable")
	// ErrDangerousURLScheme indicates a code-execution URL scheme.
	ErrDangerousURLScheme = errors.New("URL cannot use javascript:, data:, or vbscript: scheme")
	// ErrURLFragment indicates a redirect URI containing a fragment marker.
	ErrURLFragment = errors.New("Redirect URI must not contain a fragment component")
	// ErrInsecureURL indicates HTTP on a non-loopback host.
	ErrInsecureURL = errors.New("Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)")

	proxyHostnamePattern  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`)
	proxyIPv4Pattern      = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(:[0-9]{1,5})?$`)
	proxyIPv6Pattern      = regexp.MustCompile(`^\[[0-9a-fA-F:]+\](:[0-9]{1,5})?$`)
	proxyLocalhostPattern = regexp.MustCompile(`(?i)^localhost(:[0-9]{1,5})?$`)
)

// DangerousURLSchemes contains the schemes the reference implementation rejects at navigation
// and redirect sinks.
var DangerousURLSchemes = [...]string{"javascript", "data", "vbscript"}

// NormalizePathname removes a complete base-path prefix and trailing slashes
// from an absolute request URL. It returns "/" when parsing fails.
func NormalizePathname(requestURL, basePath string) string {
	parsed, err := url.Parse(requestURL)
	if err != nil || parsed.Scheme == "" {
		return "/"
	}

	pathname := parsed.EscapedPath()
	pathname = strings.TrimRight(pathname, "/")
	if pathname == "" {
		pathname = "/"
	}

	normalizedBasePath := strings.TrimRight(basePath, "/")
	if normalizedBasePath == "" {
		return pathname
	}
	if pathname == normalizedBasePath {
		return "/"
	}
	if strings.HasPrefix(pathname, normalizedBasePath+"/") {
		pathname = strings.TrimRight(pathname[len(normalizedBasePath):], "/")
		if pathname == "" {
			return "/"
		}
	}
	return pathname
}

// IsSafeURLScheme rejects only absolute URLs with a dangerous code-execution
// scheme. Relative paths, HTTP(S), and custom application schemes are allowed.
func IsSafeURLScheme(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" {
		return true
	}
	return !isDangerousScheme(parsed.Scheme)
}

// ValidateSafeURL validates an OAuth redirect URI according to the reference implementation's
// SafeUrlSchema. Custom schemes are allowed, fragments are rejected, and HTTP
// is allowed only for loopback hosts.
func ValidateSafeURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || !validAbsoluteURL(parsed) {
		return ErrURLNotParseable
	}
	if isDangerousScheme(parsed.Scheme) {
		return ErrDangerousURLScheme
	}
	if strings.Contains(value, "#") {
		return ErrURLFragment
	}
	if strings.EqualFold(parsed.Scheme, "http") && !hostutil.IsLoopbackHost(parsed.Host) {
		return ErrInsecureURL
	}
	return nil
}

// IsSafeURL reports whether ValidateSafeURL accepts value.
func IsSafeURL(value string) bool {
	return ValidateSafeURL(value) == nil
}

func isDangerousScheme(scheme string) bool {
	for _, dangerous := range DangerousURLSchemes {
		if strings.EqualFold(scheme, dangerous) {
			return true
		}
	}
	return false
}

func validAbsoluteURL(parsed *url.URL) bool {
	if parsed.Scheme == "http" || parsed.Scheme == "https" ||
		strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https") {
		return parsed.Host != ""
	}
	return parsed.Opaque != "" || parsed.Host != "" || parsed.Path != ""
}

// DynamicBaseURLConfig selects a request-specific public auth URL from an
// allowlist. It mirrors the reference implementation's DynamicBaseURLConfig server semantics.
type DynamicBaseURLConfig struct {
	AllowedHosts []string
	Fallback     string
	Protocol     string
}

// GetBaseURLOptions contains the optional inputs accepted by GetBaseURL. A nil
// Path selects the reference implementation's default /api/auth path; a pointer to an empty
// string deliberately requests no appended path.
type GetBaseURLOptions struct {
	URL                 string
	Path                *string
	Request             *contract.Request
	LoadEnvironment     *bool
	TrustedProxyHeaders bool
}

// TrimTrailingSlashes removes only slash bytes at the end of value. It uses a
// reverse scan so very long paths do not trigger regular-expression backtracking.
func TrimTrailingSlashes(value string) string {
	end := len(value)
	for end > 0 && value[end-1] == '/' {
		end--
	}
	return value[:end]
}

// GetBaseURL resolves a static URL, the the reference implementation URL environment variables,
// trusted proxy headers, or the request origin, in that precedence order.
func GetBaseURL(options GetBaseURLOptions) (string, error) {
	if options.URL != "" {
		return withPath(options.URL, options.Path)
	}

	loadEnvironment := true
	if options.LoadEnvironment != nil {
		loadEnvironment = *options.LoadEnvironment
	}
	if loadEnvironment {
		if fromEnvironment := baseURLFromEnvironment(); fromEnvironment != "" {
			return withPath(fromEnvironment, options.Path)
		}
	}

	if options.Request != nil && options.TrustedProxyHeaders {
		headers := options.Request.Headers()
		forwardedHost, hasHost := headers.Get("x-forwarded-host")
		forwardedProtocol, hasProtocol := headers.Get("x-forwarded-proto")
		if hasHost && hasProtocol &&
			validateProxyHeader(forwardedHost, "host") &&
			validateProxyHeader(forwardedProtocol, "proto") {
			if resolved, err := withPath(forwardedProtocol+"://"+forwardedHost, options.Path); err == nil {
				return resolved, nil
			}
		}
	}

	if options.Request != nil {
		origin := requestOrigin(*options.Request)
		if origin == "" {
			return "", errors.New("Could not get origin from request. Please provide a valid base URL.")
		}
		return withPath(origin, options.Path)
	}

	// the reference implementation has one additional browser-only fallback to window.location.
	// A Go server has no global window, so an empty result represents undefined.
	return "", nil
}

// GetHostFromSource returns a validated forwarded host when proxy headers are
// trusted, then a validated Host header, and finally the request URL host.
func GetHostFromSource(source contract.Request, trustedProxyHeaders bool) string {
	headers := source.Headers()
	if trustedProxyHeaders {
		if forwardedHost, ok := headers.Get("x-forwarded-host"); ok &&
			validateProxyHeader(forwardedHost, "host") {
			return forwardedHost
		}
	}
	if host, ok := headers.Get("host"); ok && validateProxyHeader(host, "host") {
		return host
	}
	return source.Host()
}

// GetProtocolFromSource resolves an explicit protocol, a trusted forwarded
// protocol, the request URL scheme, or the reference implementation's loopback-aware fallback.
func GetProtocolFromSource(
	source contract.Request,
	configuredProtocol string,
	trustedProxyHeaders bool,
) string {
	if configuredProtocol == "http" || configuredProtocol == "https" {
		return configuredProtocol
	}
	headers := source.Headers()
	if trustedProxyHeaders {
		if forwardedProtocol, ok := headers.Get("x-forwarded-proto"); ok &&
			validateProxyHeader(forwardedProtocol, "proto") {
			return forwardedProtocol
		}
	}
	if source.Scheme() == "http" || source.Scheme() == "https" {
		return source.Scheme()
	}
	if isLoopbackForDevScheme(GetHostFromSource(source, trustedProxyHeaders)) {
		return "http"
	}
	return "https"
}

// IsDynamicBaseURLConfig is the runtime type guard corresponding to Better
// Auth's string-or-object BaseURLConfig union.
func IsDynamicBaseURLConfig(config any) bool {
	switch value := config.(type) {
	case DynamicBaseURLConfig:
		return true
	case *DynamicBaseURLConfig:
		return value != nil
	case map[string]any:
		allowedHosts, exists := value["allowedHosts"]
		if !exists || allowedHosts == nil {
			return false
		}
		switch allowedHosts.(type) {
		case []string, []any:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// MatchesHostPattern performs case-insensitive exact or wildcard matching
// after removing an accidental HTTP(S) protocol and path.
func MatchesHostPattern(host, pattern string) bool {
	host = normalizeHostPatternValue(host)
	pattern = normalizeHostPatternValue(pattern)
	if host == "" || pattern == "" {
		return false
	}
	if !strings.ContainsAny(pattern, "*?") {
		return strings.EqualFold(host, pattern)
	}
	expression, err := regexp.Compile("^" + wildcardExpression(pattern) + "$")
	return err == nil && expression.MatchString(host)
}

// ResolveDynamicBaseURL derives an allowed host and protocol from source, or
// uses the configured fallback. Rejection messages intentionally match Better
// Auth because applications commonly expose them in configuration diagnostics.
func ResolveDynamicBaseURL(
	config DynamicBaseURLConfig,
	source contract.Request,
	basePath string,
	trustedProxyHeaders bool,
) (string, error) {
	host := GetHostFromSource(source, trustedProxyHeaders)
	if host == "" {
		if config.Fallback != "" {
			return withPath(config.Fallback, stringPointer(basePath))
		}
		return "", errors.New(
			"Could not determine host from request headers. Please provide a fallback URL in your baseURL config.",
		)
	}

	for _, pattern := range config.AllowedHosts {
		if MatchesHostPattern(host, pattern) {
			protocol := GetProtocolFromSource(source, config.Protocol, trustedProxyHeaders)
			return withPath(protocol+"://"+host, stringPointer(basePath))
		}
	}
	if config.Fallback != "" {
		return withPath(config.Fallback, stringPointer(basePath))
	}
	return "", fmt.Errorf(
		"Host %q is not in the allowed hosts list. Allowed hosts: %s. Add this host to your allowedHosts config or provide a fallback URL.",
		host,
		strings.Join(config.AllowedHosts, ", "),
	)
}

// ResolveBaseURL resolves a static string, DynamicBaseURLConfig value/pointer,
// or nil legacy config through the same production functions.
func ResolveBaseURL(
	config any,
	basePath string,
	source *contract.Request,
	loadEnvironment *bool,
	trustedProxyHeaders bool,
) (string, error) {
	if IsDynamicBaseURLConfig(config) {
		dynamic, ok := dynamicBaseURLConfig(config)
		if !ok {
			return "", errors.New("Invalid dynamic base URL configuration")
		}
		if source != nil {
			return ResolveDynamicBaseURL(dynamic, *source, basePath, trustedProxyHeaders)
		}
		if dynamic.Fallback != "" {
			return withPath(dynamic.Fallback, stringPointer(basePath))
		}
		return GetBaseURL(GetBaseURLOptions{
			Path:                stringPointer(basePath),
			LoadEnvironment:     loadEnvironment,
			TrustedProxyHeaders: trustedProxyHeaders,
		})
	}

	if static, ok := config.(string); ok {
		return GetBaseURL(GetBaseURLOptions{
			URL:                 static,
			Path:                stringPointer(basePath),
			Request:             source,
			LoadEnvironment:     loadEnvironment,
			TrustedProxyHeaders: trustedProxyHeaders,
		})
	}
	return GetBaseURL(GetBaseURLOptions{
		Path:                stringPointer(basePath),
		Request:             source,
		LoadEnvironment:     loadEnvironment,
		TrustedProxyHeaders: trustedProxyHeaders,
	})
}

func withPath(rawURL string, path *string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("Invalid base URL: %s. Please provide a valid base URL.", rawURL)
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf(
			"Invalid base URL: %s. URL must include 'http://' or 'https://'",
			rawURL,
		)
	}
	if err := validateURLPort(parsed); err != nil {
		return "", fmt.Errorf("Invalid base URL: %s. Please provide a valid base URL.", rawURL)
	}
	pathname := TrimTrailingSlashes(parsed.EscapedPath())
	if pathname != "" && pathname != "/" {
		return rawURL, nil
	}

	resolvedPath := "/api/auth"
	if path != nil {
		resolvedPath = *path
	}
	trimmedURL := TrimTrailingSlashes(rawURL)
	if resolvedPath == "" || resolvedPath == "/" {
		return trimmedURL, nil
	}
	if !strings.HasPrefix(resolvedPath, "/") {
		resolvedPath = "/" + resolvedPath
	}
	return trimmedURL + resolvedPath, nil
}

func validateURLPort(parsed *url.URL) error {
	port := parsed.Port()
	if port == "" {
		return nil
	}
	number, err := strconv.Atoi(port)
	if err != nil || number > 65535 {
		return errors.New("invalid port")
	}
	return nil
}

func baseURLFromEnvironment() string {
	for _, name := range []string{
		"SINGLE_AUTH_URL",
		"NEXT_PUBLIC_SINGLE_AUTH_URL",
		"PUBLIC_SINGLE_AUTH_URL",
		"NUXT_PUBLIC_SINGLE_AUTH_URL",
		"NUXT_PUBLIC_AUTH_URL",
		"BASE_URL",
	} {
		value := os.Getenv(name)
		if value != "" && !(name == "BASE_URL" && value == "/") {
			return value
		}
	}
	return ""
}

func requestOrigin(request contract.Request) string {
	if request.Scheme() == "" || request.Host() == "" {
		return ""
	}
	return request.Scheme() + "://" + request.Host()
}

func validateProxyHeader(header, kind string) bool {
	if header == "" || strings.TrimSpace(header) == "" {
		return false
	}
	if kind == "proto" {
		return header == "http" || header == "https"
	}
	if kind != "host" {
		return false
	}
	if strings.Contains(header, "..") || strings.ContainsRune(header, 0) ||
		strings.ContainsAny(header, "<>'\"") || strings.HasPrefix(header, ".") ||
		strings.IndexFunc(header, unicode.IsSpace) >= 0 {
		return false
	}
	lower := strings.ToLower(header)
	if strings.Contains(lower, "javascript:") || strings.Contains(lower, "file:") ||
		strings.Contains(lower, "data:") {
		return false
	}
	return proxyHostnamePattern.MatchString(header) ||
		proxyIPv4Pattern.MatchString(header) ||
		proxyIPv6Pattern.MatchString(header) ||
		proxyLocalhostPattern.MatchString(header)
}

func isLoopbackForDevScheme(host string) bool {
	host = strings.ToLower(host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if index := strings.LastIndexByte(host, ':'); index >= 0 {
		if _, err := strconv.Atoi(host[index+1:]); err == nil {
			host = host[:index]
		}
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		host == "::1" || strings.HasPrefix(host, "127.")
}

func normalizeHostPatternValue(value string) string {
	if strings.HasPrefix(value, "http://") {
		value = strings.TrimPrefix(value, "http://")
	} else if strings.HasPrefix(value, "https://") {
		value = strings.TrimPrefix(value, "https://")
	}
	if index := strings.IndexByte(value, '/'); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(value)
}

func wildcardExpression(pattern string) string {
	const wildcard = `[^/\\]`
	var expression strings.Builder
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '\\':
			if index+1 < len(pattern) {
				index++
				expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
			}
		case '?':
			expression.WriteString(wildcard)
		case '*':
			expression.WriteString(wildcard)
			expression.WriteString("*?")
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
		}
	}
	expression.WriteString(`[/\\]*?`)
	return expression.String()
}

func dynamicBaseURLConfig(config any) (DynamicBaseURLConfig, bool) {
	switch value := config.(type) {
	case DynamicBaseURLConfig:
		return value, true
	case *DynamicBaseURLConfig:
		if value == nil {
			return DynamicBaseURLConfig{}, false
		}
		return *value, true
	case map[string]any:
		if !IsDynamicBaseURLConfig(value) {
			return DynamicBaseURLConfig{}, false
		}
		result := DynamicBaseURLConfig{}
		switch allowedHosts := value["allowedHosts"].(type) {
		case []string:
			result.AllowedHosts = append([]string(nil), allowedHosts...)
		case []any:
			for _, allowedHost := range allowedHosts {
				if text, ok := allowedHost.(string); ok {
					result.AllowedHosts = append(result.AllowedHosts, text)
				}
			}
		}
		result.Fallback, _ = value["fallback"].(string)
		result.Protocol, _ = value["protocol"].(string)
		return result, true
	default:
		return DynamicBaseURLConfig{}, false
	}
}

func stringPointer(value string) *string { return &value }
