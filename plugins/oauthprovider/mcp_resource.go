package oauthprovider

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
)

// MCPResourceOptions configures RFC 9728 discovery and bearer-token
// verification for a protected MCP resource. Resource accepts the same union
// as single-auth: either one absolute resource URL or []string of URLs.
type MCPResourceOptions struct {
	Resource                 any
	AuthorizationServers     []string
	ScopesSupported          []string
	ResourceMetadataMappings map[string]string
	Issuer                   string
	Audience                 any
	JWT                      jwtplugin.Options
}

// MCPResourceService is transport-neutral. Endpoints built with Guard run
// unchanged through net/http, fasthttp, Fiber, and direct dispatch.
type MCPResourceService struct {
	options   MCPResourceOptions
	resources []string
	challenge string
}

// NewMCPResourceService validates and snapshots a protected-resource service.
func NewMCPResourceService(input MCPResourceOptions) (*MCPResourceService, error) {
	resources, err := normalizeMCPResources(input.Resource)
	if err != nil {
		return nil, err
	}
	challenge, err := MCPWWWAuthenticate(input.Resource, input.ResourceMetadataMappings)
	if err != nil {
		return nil, err
	}
	options := input
	options.AuthorizationServers = append([]string(nil), input.AuthorizationServers...)
	options.ScopesSupported = append([]string(nil), input.ScopesSupported...)
	options.ResourceMetadataMappings = cloneStringMap(input.ResourceMetadataMappings)
	if options.Audience == nil {
		if len(resources) == 1 {
			options.Audience = resources[0]
		} else {
			options.Audience = append([]string(nil), resources...)
		}
	}
	if options.Issuer != "" {
		issuer := options.Issuer
		options.JWT.Token.Issuer = &issuer
	}
	options.JWT.Token.Audience = cloneMCPAudience(options.Audience)
	return &MCPResourceService{options: options, resources: resources, challenge: challenge}, nil
}

// MCPWWWAuthenticate renders single-auth 1.6.26's exact RFC 9728 challenge.
// Every URL audience has its own Bearer challenge and array entries are joined
// with comma-space in declaration order.
func MCPWWWAuthenticate(resource any, mappings map[string]string) (string, error) {
	resources, err := normalizeMCPResources(resource)
	if err != nil {
		return "", err
	}
	challenges := make([]string, 0, len(resources))
	for _, item := range resources {
		if mapped := mappings[item]; mapped != "" {
			challenges = append(challenges, "Bearer resource_metadata="+mapped)
			continue
		}
		parsed, parseErr := url.Parse(item)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
			return "", fmt.Errorf("oauthprovider: MCP resource %q must be an absolute URL or have a metadata mapping", item)
		}
		path := strings.TrimSuffix(parsed.EscapedPath(), "/")
		metadataURL := parsed.Scheme + "://" + parsed.Host + "/.well-known/oauth-protected-resource" + path
		challenges = append(challenges, `Bearer resource_metadata="`+metadataURL+`"`)
	}
	return strings.Join(challenges, ", "), nil
}

// ProtectedResourceMetadata returns the RFC 9728 document exported by an MCP
// resource server. The caller chooses where to mount it (normally both the
// root well-known path and the path-suffixed form advertised in the challenge).
func (service *MCPResourceService) ProtectedResourceMetadata() map[string]any {
	if service == nil {
		return nil
	}
	resource := ""
	if len(service.resources) > 0 {
		resource = service.resources[0]
	}
	result := map[string]any{
		"resource":              resource,
		"authorization_servers": append([]string(nil), service.options.AuthorizationServers...),
	}
	if service.options.ScopesSupported != nil {
		result["scopes_supported"] = append([]string(nil), service.options.ScopesSupported...)
	}
	return result
}

// Challenge returns the immutable WWW-Authenticate value used by Guard.
func (service *MCPResourceService) Challenge() string {
	if service == nil {
		return ""
	}
	return service.challenge
}

// VerifyAccessToken verifies a bearer using the configured production JWT/JWK
// runtime. Missing, opaque, expired, incorrectly signed, wrong-issuer, and
// wrong-audience tokens all become the same externally observable 401.
func (service *MCPResourceService) VerifyAccessToken(
	ctx *engine.Context,
	token string,
) (map[string]any, error) {
	if service == nil {
		return nil, errors.New("oauthprovider: MCP resource service is nil")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("oauthprovider: bearer token is required")
	}
	payload, disposition, err := jwtplugin.VerifyAccessToken(ctx, token, service.options.JWT)
	if err != nil || disposition != jwtplugin.AccessTokenValid {
		if err == nil {
			err = errors.New("oauthprovider: invalid bearer token")
		}
		return nil, err
	}
	// @single-auth/core's verifier exposes the authorized party under both its
	// JWT name (azp) and OAuth resource-server name (client_id).
	if _, exists := payload["client_id"]; !exists {
		if authorizedParty, ok := payload["azp"].(string); ok && authorizedParty != "" {
			payload["client_id"] = authorizedParty
		}
	}
	if len(service.options.ScopesSupported) > 0 {
		granted, _ := payload["scope"].(string)
		grantedSet := make(map[string]struct{})
		for _, scope := range strings.Fields(granted) {
			grantedSet[scope] = struct{}{}
		}
		for _, required := range service.options.ScopesSupported {
			if _, ok := grantedSet[required]; !ok {
				return nil, fmt.Errorf("oauthprovider: required scope %q is missing", required)
			}
		}
	}
	return payload, nil
}

// Guard wraps one production endpoint with the same unauthorized conversion
// as single-auth's mcpHandler. Verified claims are exposed through
// MCPAccessTokenClaims for the application handler.
func (service *MCPResourceService) Guard(next engine.HandlerFunc) engine.HandlerFunc {
	return func(ctx *engine.Context) (contract.Response, error) {
		authorization, _ := ctx.Request().Headers().Get("Authorization")
		token := ""
		if strings.HasPrefix(authorization, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		}
		claims, err := service.VerifyAccessToken(ctx, token)
		if err != nil {
			return service.unauthorized(), nil
		}
		ctx.Set(MCPAccessTokenClaims, cloneAnyMap(claims))
		if next == nil {
			return contract.JSONResponse(contract.StatusOK, map[string]bool{"ok": true})
		}
		return next(ctx)
	}
}

// MCPAccessTokenClaims is the request-context key populated by Guard.
const MCPAccessTokenClaims = "oauthprovider:mcp-access-token-claims"

func (service *MCPResourceService) unauthorized() contract.Response {
	response, err := contract.JSONResponse(contract.StatusUnauthorized, map[string]any{
		"error": "invalid_token",
	})
	if err != nil {
		return contract.TextResponse(contract.StatusUnauthorized, "Unauthorized").WithHeader(
			"WWW-Authenticate", service.challenge,
		)
	}
	return response.WithHeader("WWW-Authenticate", service.challenge)
}

func normalizeMCPResources(value any) ([]string, error) {
	var resources []string
	switch typed := value.(type) {
	case string:
		resources = []string{typed}
	case []string:
		resources = append([]string(nil), typed...)
	case nil:
		return nil, errors.New("oauthprovider: MCP resource is required")
	default:
		return nil, fmt.Errorf("oauthprovider: MCP resource must be string or []string, got %T", value)
	}
	if len(resources) == 0 {
		return nil, errors.New("oauthprovider: MCP resource list must not be empty")
	}
	for _, resource := range resources {
		if strings.TrimSpace(resource) == "" {
			return nil, errors.New("oauthprovider: MCP resource must not be empty")
		}
	}
	return resources, nil
}

func cloneMCPAudience(value any) any {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneAnyMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
