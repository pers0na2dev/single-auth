package mcp

import (
	"encoding/json"
	"net/http"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
)

// WithMCPAuth protects a net/http resource handler with getMcpSession and
// emits the MCP JSON-RPC authentication challenge used by single-auth.
func WithMCPAuth(
	auth *singleauth.Auth,
	handler func(http.ResponseWriter, *http.Request, AccessToken),
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		baseURL := ""
		if auth != nil {
			resolved, err := auth.ResolveBaseURL(contractRequest(request))
			if err == nil {
				baseURL = resolved
			}
		}
		wwwAuthenticate := "Bearer"
		if baseURL != "" {
			wwwAuthenticate = `Bearer resource_metadata="` + baseURL + ProtectedResourcePath + `"`
		}
		var token *AccessToken
		if auth != nil {
			result, err := auth.API().Call(request.Context(), "getMcpSession", singleauth.DirectCallInput{
				Method: http.MethodGet, Scheme: requestScheme(request), Host: request.Host,
				Headers: contractHeaders(request.Header),
			})
			if err == nil && result.Value != nil {
				var decoded AccessToken
				if json.Unmarshal(result.Response.Body(), &decoded) == nil && decoded.UserID != "" {
					token = &decoded
				}
			}
		}
		if token == nil {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("WWW-Authenticate", wwwAuthenticate)
			writer.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
			writer.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"error": map[string]any{
					"code": -32000, "message": "Unauthorized: Authentication required",
					"www-authenticate": wwwAuthenticate,
				},
				"id": nil,
			})
			return
		}
		handler(writer, request, *token)
	})
}

// OAuthDiscoveryMetadataHandler exposes discovery metadata with the CORS
// headers used by single-auth's oAuthDiscoveryMetadata helper.
func OAuthDiscoveryMetadataHandler(auth *singleauth.Auth) http.Handler {
	return metadataProxyHandler(auth, "getMcpOAuthConfig")
}

// OAuthProtectedResourceMetadataHandler exposes protected-resource metadata
// with the CORS headers used by single-auth's helper.
func OAuthProtectedResourceMetadataHandler(auth *singleauth.Auth) http.Handler {
	return metadataProxyHandler(auth, "getMCPProtectedResource")
}

func metadataProxyHandler(auth *singleauth.Auth, endpoint string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var value any
		if auth != nil {
			result, err := auth.API().Call(request.Context(), endpoint, singleauth.DirectCallInput{
				Method: http.MethodGet, Scheme: requestScheme(request), Host: request.Host,
				Headers: contractHeaders(request.Header),
			})
			if err == nil {
				value = result.Value
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		writer.Header().Set("Access-Control-Max-Age", "86400")
		_ = json.NewEncoder(writer).Encode(value)
	})
}

func contractRequest(request *http.Request) contract.Request {
	return contract.NewRequest(request.Method, request.URL.EscapedPath(), contract.RequestOptions{
		Context: request.Context(), Scheme: requestScheme(request), Host: request.Host,
		RawQuery: request.URL.RawQuery, Headers: contractHeaders(request.Header),
	})
}

func contractHeaders(source http.Header) contract.Headers {
	result := contract.Headers{}
	for name, values := range source {
		for _, value := range values {
			result.Add(name, value)
		}
	}
	return result
}

func requestScheme(request *http.Request) string {
	if request.URL != nil && request.URL.Scheme != "" {
		return request.URL.Scheme
	}
	if forwarded := request.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if request.TLS != nil {
		return "https"
	}
	return "http"
}
