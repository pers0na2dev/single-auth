package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

const (
	defaultOIDCDiscoveryTimeout = 10 * time.Second
	maxOIDCResponseBytes        = 1 << 20
)

type oidcDiscoveryError struct {
	Code    string
	Message string
	Cause   error
}

func (err *oidcDiscoveryError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.Cause != nil {
		return err.Message + ": " + err.Cause.Error()
	}
	return err.Message
}

func (err *oidcDiscoveryError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

type oidcDiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSEndpoint          string   `json:"jwks_uri"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// ComputeDiscoveryURL returns the OIDC discovery location used by Better
// Auth, including the issuer-path behavior and trailing-slash normalization.
func ComputeDiscoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

func zeroSAMLConfig(config SAMLConfig) bool {
	return config.Issuer == "" && config.EntryPoint == "" && config.Certificate == "" &&
		config.CallbackURL == "" && config.IDPMetadata == nil && config.SPMetadata == nil
}

func cloneOIDCConfig(input *OIDCConfig) *OIDCConfig {
	if input == nil {
		return nil
	}
	result := *input
	result.PKCE = cloneBool(input.PKCE)
	result.Scopes = append([]string(nil), input.Scopes...)
	result.ScopesSupported = append([]string(nil), input.ScopesSupported...)
	result.Mapping.ExtraFields = cloneStringMap(input.Mapping.ExtraFields)
	return &result
}

func oidcPKCEEnabled(config OIDCConfig) bool {
	return config.PKCE == nil || *config.PKCE
}

func validateConfiguredOIDC(config OIDCConfig, allowDiscovery bool) error {
	if err := validateOIDCCredentials(config); err != nil {
		return err
	}
	for name, endpoint := range map[string]string{
		"authorizationEndpoint": config.AuthorizationEndpoint,
		"tokenEndpoint":         config.TokenEndpoint,
		"userInfoEndpoint":      config.UserInfoEndpoint,
		"jwksEndpoint":          config.JWKSEndpoint,
		"discoveryEndpoint":     config.DiscoveryEndpoint,
	} {
		if endpoint == "" {
			continue
		}
		if _, err := absoluteHTTPURL(endpoint); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if !allowDiscovery && (config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" || config.JWKSEndpoint == "") {
		return errors.New("authorizationEndpoint, tokenEndpoint, and jwksEndpoint are required")
	}
	return nil
}

func validateOIDCCredentials(config OIDCConfig) error {
	if strings.TrimSpace(config.Issuer) == "" {
		return errors.New("issuer is required")
	}
	if _, err := absoluteHTTPURL(config.Issuer); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if strings.TrimSpace(config.ClientID) == "" {
		return errors.New("clientId is required")
	}
	if strings.TrimSpace(config.ClientSecret) == "" {
		return errors.New("clientSecret is required")
	}
	switch config.TokenEndpointAuthentication {
	case "", "client_secret_basic", "client_secret_post":
	default:
		return errors.New("tokenEndpointAuthentication must be client_secret_basic or client_secret_post")
	}
	return nil
}

func (p *plugin) ensureOIDCConfig(ctx *engine.Context, provider *resolvedProvider) (OIDCConfig, error) {
	if provider == nil || provider.OIDCConfig == nil {
		return OIDCConfig{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Invalid SSO provider")
	}
	config := *cloneOIDCConfig(provider.OIDCConfig)
	if config.Issuer == "" {
		config.Issuer = provider.Issuer
	}
	if err := validateConfiguredOIDC(config, true); err != nil {
		return OIDCConfig{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Invalid OIDC configuration")
	}
	if err := p.validateOIDCEndpoints(ctx, config, false); err != nil {
		return OIDCConfig{}, err
	}
	if config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" || config.JWKSEndpoint == "" {
		hydrated, err := p.discoverOIDCConfig(ctx, config)
		if err != nil {
			return OIDCConfig{}, err
		}
		config = hydrated
	}
	if config.TokenEndpointAuthentication == "" {
		config.TokenEndpointAuthentication = "client_secret_basic"
	}
	if config.DiscoveryEndpoint == "" {
		config.DiscoveryEndpoint = ComputeDiscoveryURL(config.Issuer)
	}
	if err := p.validateOIDCEndpoints(ctx, config, true); err != nil {
		return OIDCConfig{}, err
	}
	return config, nil
}

func (p *plugin) discoverOIDCConfig(ctx *engine.Context, existing OIDCConfig) (OIDCConfig, error) {
	discoveryEndpoint := existing.DiscoveryEndpoint
	if discoveryEndpoint == "" {
		discoveryEndpoint = ComputeDiscoveryURL(existing.Issuer)
	}
	parsed, err := parseOIDCURL("discoveryEndpoint", discoveryEndpoint)
	if err != nil {
		return OIDCConfig{}, err
	}
	trusted, err := p.isTrustedOIDCOrigin(ctx, parsed.String())
	if err != nil {
		return OIDCConfig{}, err
	}
	if !trusted {
		return OIDCConfig{}, discoveryError("discovery_untrusted_origin",
			fmt.Sprintf("The main discovery endpoint %q is not trusted by your trusted origins configuration.", parsed.String()), nil)
	}

	var document oidcDiscoveryDocument
	if err := p.fetchOIDCJSON(ctx.GoContext(), parsed.String(), &document); err != nil {
		return OIDCConfig{}, err
	}
	missing := make([]string, 0, 4)
	for _, field := range []struct{ name, value string }{
		{"issuer", document.Issuer},
		{"authorization_endpoint", document.AuthorizationEndpoint},
		{"token_endpoint", document.TokenEndpoint},
		{"jwks_uri", document.JWKSEndpoint},
	} {
		if strings.TrimSpace(field.value) == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) != 0 {
		return OIDCConfig{}, discoveryError("discovery_incomplete",
			"Discovery document is missing required fields: "+strings.Join(missing, ", "), nil)
	}
	if strings.TrimSuffix(document.Issuer, "/") != strings.TrimSuffix(existing.Issuer, "/") {
		return OIDCConfig{}, discoveryError("issuer_mismatch",
			fmt.Sprintf("Discovered issuer %q does not match configured issuer %q", document.Issuer, existing.Issuer), nil)
	}

	document.AuthorizationEndpoint, err = p.normalizeDiscoveredEndpoint(ctx, "authorization_endpoint", document.AuthorizationEndpoint, existing.Issuer)
	if err != nil {
		return OIDCConfig{}, err
	}
	document.TokenEndpoint, err = p.normalizeDiscoveredEndpoint(ctx, "token_endpoint", document.TokenEndpoint, existing.Issuer)
	if err != nil {
		return OIDCConfig{}, err
	}
	document.JWKSEndpoint, err = p.normalizeDiscoveredEndpoint(ctx, "jwks_uri", document.JWKSEndpoint, existing.Issuer)
	if err != nil {
		return OIDCConfig{}, err
	}
	if document.UserInfoEndpoint != "" {
		document.UserInfoEndpoint, err = p.normalizeDiscoveredEndpoint(ctx, "userinfo_endpoint", document.UserInfoEndpoint, existing.Issuer)
		if err != nil {
			return OIDCConfig{}, err
		}
	}

	result := *cloneOIDCConfig(&existing)
	result.DiscoveryEndpoint = firstNonEmpty(existing.DiscoveryEndpoint, parsed.String())
	result.AuthorizationEndpoint = firstNonEmpty(existing.AuthorizationEndpoint, document.AuthorizationEndpoint)
	result.TokenEndpoint = firstNonEmpty(existing.TokenEndpoint, document.TokenEndpoint)
	result.JWKSEndpoint = firstNonEmpty(existing.JWKSEndpoint, document.JWKSEndpoint)
	result.UserInfoEndpoint = firstNonEmpty(existing.UserInfoEndpoint, document.UserInfoEndpoint)
	result.ScopesSupported = append([]string(nil), document.ScopesSupported...)
	if result.TokenEndpointAuthentication == "" {
		result.TokenEndpointAuthentication = selectOIDCTokenAuth(document.TokenAuthMethods)
	}
	result.SkipDiscovery = false
	if err := p.validateOIDCEndpoints(ctx, result, true); err != nil {
		return OIDCConfig{}, err
	}
	return result, nil
}

func selectOIDCTokenAuth(supported []string) string {
	for _, method := range supported {
		if method == "client_secret_basic" {
			return method
		}
	}
	for _, method := range supported {
		if method == "client_secret_post" {
			return method
		}
	}
	return "client_secret_basic"
}

func (p *plugin) normalizeDiscoveredEndpoint(ctx *engine.Context, name, endpoint, issuer string) (string, error) {
	normalized, err := normalizeOIDCEndpoint(name, endpoint, issuer)
	if err != nil {
		return "", err
	}
	trusted, err := p.isTrustedOIDCOrigin(ctx, normalized)
	if err != nil {
		return "", err
	}
	if !trusted {
		return "", discoveryError("discovery_untrusted_origin",
			fmt.Sprintf("The %s %q is not trusted by your trusted origins configuration.", name, normalized), nil)
	}
	return normalized, nil
}

func normalizeOIDCEndpoint(name, endpoint, issuer string) (string, error) {
	if parsed, err := parseOIDCURL(name, endpoint); err == nil {
		return parsed.String(), nil
	}
	issuerURL, err := parseOIDCURL("issuer", issuer)
	if err != nil {
		return "", err
	}
	basePath := strings.TrimRight(issuerURL.Path, "/")
	endpointPath := strings.TrimLeft(endpoint, "/")
	issuerURL.Path = basePath + "/" + endpointPath
	issuerURL.RawPath = ""
	issuerURL.RawQuery = ""
	issuerURL.Fragment = ""
	return issuerURL.String(), nil
}

func parseOIDCURL(name, value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" {
		return nil, discoveryError("discovery_invalid_url", fmt.Sprintf("The url %q must be valid: %s", name, value), err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, discoveryError("discovery_invalid_url",
			fmt.Sprintf("The url %q must use the http or https supported protocols: %s", name, value), nil)
	}
	if parsed.User != nil {
		return nil, discoveryError("discovery_invalid_url", fmt.Sprintf("The url %q must not contain user information", name), nil)
	}
	return parsed, nil
}

func (p *plugin) validateOIDCEndpoints(ctx *engine.Context, config OIDCConfig, resolveServerEndpoints bool) error {
	endpoints := []struct {
		name   string
		value  string
		server bool
	}{
		{"authorizationEndpoint", config.AuthorizationEndpoint, false},
		{"tokenEndpoint", config.TokenEndpoint, true},
		{"userInfoEndpoint", config.UserInfoEndpoint, true},
		{"jwksEndpoint", config.JWKSEndpoint, true},
		{"discoveryEndpoint", config.DiscoveryEndpoint, true},
	}
	for _, endpoint := range endpoints {
		if endpoint.value == "" {
			continue
		}
		parsed, err := parseOIDCURL(endpoint.name, endpoint.value)
		if err != nil {
			return err
		}
		trusted, err := p.isTrustedOIDCOrigin(ctx, parsed.String())
		if err != nil {
			return err
		}
		if !trusted && !publicOIDCHost(parsed.Hostname()) {
			return discoveryError("discovery_private_host",
				fmt.Sprintf("The %s URL (%s) is not publicly routable: %s. If this is an internal IdP, add its origin to trustedOrigins.", endpoint.name, parsed.String(), parsed.Hostname()), nil)
		}
		if resolveServerEndpoints && endpoint.server && !trusted && net.ParseIP(parsed.Hostname()) == nil {
			if err := p.assertOIDCHostResolvesPublic(ctx.GoContext(), endpoint.name, parsed); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *plugin) isTrustedOIDCOrigin(ctx *engine.Context, candidate string) (bool, error) {
	if p.runtime.IsTrustedOrigin == nil {
		return false, nil
	}
	return p.runtime.IsTrustedOrigin(ctx.Request(), candidate, false)
}

func (p *plugin) assertOIDCHostResolvesPublic(ctx context.Context, name string, endpoint *url.URL) error {
	lookup := p.options.OIDC.LookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	addresses, err := lookup(ctx, endpoint.Hostname())
	if err != nil {
		return nil
	}
	for _, address := range addresses {
		if !publicOIDCIP(address.IP) {
			return discoveryError("discovery_private_host",
				fmt.Sprintf("The %s host %q resolves to a non-publicly-routable address (%s). If this is an internal IdP, add its origin to trustedOrigins.", name, endpoint.Hostname(), address.IP.String()), nil)
		}
	}
	return nil
}

func publicOIDCHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case "", "localhost", "localhost.localdomain", "metadata.google.internal", "metadata.aws.internal":
		return false
	}
	if strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return publicOIDCIP(ip)
	}
	return true
}

var nonPublicOIDCPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("2001:db8::/32"),
}

func publicOIDCIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range nonPublicOIDCPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.IsGlobalUnicast()
}

func (p *plugin) fetchOIDCJSON(ctx context.Context, endpoint string, output any) error {
	timeout := p.options.OIDC.DiscoveryTimeout
	if timeout <= 0 {
		timeout = defaultOIDCDiscoveryTimeout
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return discoveryError("discovery_invalid_url", "Invalid OIDC discovery URL", err)
	}
	client := p.options.OIDC.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := oauth2.DoRefusingRedirects(client, request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return discoveryError("discovery_timeout", "Discovery request timed out", err)
		}
		return discoveryError("discovery_unexpected_error", "Unexpected error during discovery", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
	if err != nil {
		return discoveryError("discovery_unexpected_error", "Unable to read discovery response", err)
	}
	if len(raw) > maxOIDCResponseBytes {
		return discoveryError("discovery_invalid_json", "Discovery response is too large", nil)
	}
	if response.StatusCode == http.StatusNotFound {
		return discoveryError("discovery_not_found", "Discovery endpoint not found", nil)
	}
	if response.StatusCode == http.StatusRequestTimeout {
		return discoveryError("discovery_timeout", "Discovery request timed out", nil)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return discoveryError("discovery_unexpected_error", fmt.Sprintf("Unexpected discovery status: %d", response.StatusCode), nil)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return discoveryError("discovery_invalid_json", "Discovery endpoint returned an empty response", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return discoveryError("discovery_invalid_json", "Discovery endpoint returned invalid JSON", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return discoveryError("discovery_invalid_json", "Discovery endpoint returned invalid JSON", err)
	}
	return nil
}

func discoveryError(code, message string, cause error) *oidcDiscoveryError {
	return &oidcDiscoveryError{Code: code, Message: message, Cause: cause}
}

func discoveryAPIError(err error) error {
	var discovery *oidcDiscoveryError
	if !errors.As(err, &discovery) {
		return err
	}
	status := contract.StatusBadRequest
	message := discovery.Message
	switch discovery.Code {
	case "discovery_timeout":
		status = http.StatusBadGateway
		message = "OIDC discovery timed out: " + message
	case "discovery_unexpected_error":
		status = http.StatusBadGateway
		message = "OIDC discovery failed: " + message
	case "discovery_not_found":
		message = "OIDC discovery endpoint not found. The issuer may not support OIDC discovery, or the URL is incorrect. " + message
	case "discovery_invalid_url":
		message = "Invalid OIDC endpoint URL: " + message
	case "discovery_untrusted_origin":
		message = "Untrusted OIDC discovery URL: " + message
	case "discovery_invalid_json":
		message = "OIDC discovery returned invalid data: " + message
	case "discovery_incomplete":
		message = "OIDC discovery document is missing required fields: " + message
	case "issuer_mismatch":
		message = "OIDC issuer mismatch: " + message
	}
	return apiError(status, discovery.Code, message)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
