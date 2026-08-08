package oauthprovider

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type mcpCase struct {
	Suite       string
	Title       string
	Observation map[string]any
}

func TestOAuthProviderMCPMetadata(t *testing.T) {
	metadata := make(map[string]map[string]any)
	for _, vector := range mcpCases {
		if vector.Suite == "mcp" {
			metadata[vector.Title] = vector.Observation
		}
	}
	vectors := []struct {
		title    string
		resource any
	}{
		{"should provide the correct metadata using resource: 'http://localhost:5000'", "http://localhost:5000"},
		{"should provide the correct metadata using resource: 'http://localhost:5000/resource1'", "http://localhost:5000/resource1"},
		{"should provide the correct metadata using resource: [ 'http://localhost:5000', …(1) ]", []string{"http://localhost:5000", "http://localhost:5000/resource1"}},
	}
	for _, vector := range vectors {
		vector := vector
		t.Run(vector.title, func(t *testing.T) {
			observation := metadata[vector.title]
			wantChallenge, _ := observation["expectedChallenge"].(string)
			actualChallenge, err := MCPWWWAuthenticate(vector.resource, nil)
			if err != nil || actualChallenge != wantChallenge {
				t.Fatalf("challenge=%q want=%q err=%v", actualChallenge, wantChallenge, err)
			}
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					verifyStatus, verifyChallenge := runMCPUnauthorized(t, transportName, vector.resource, "Bearer bad_access_token")
					handlerStatus, handlerChallenge := runMCPUnauthorized(t, transportName, vector.resource, "")
					if verifyStatus != int(observation["verifyStatus"].(float64)) || verifyChallenge != observation["verifyChallenge"] {
						t.Fatalf("verify status=%d challenge=%q observation=%#v", verifyStatus, verifyChallenge, observation)
					}
					if handlerStatus != int(observation["handlerStatus"].(float64)) || handlerChallenge != observation["handlerChallenge"] {
						t.Fatalf("handler status=%d challenge=%q observation=%#v", handlerStatus, handlerChallenge, observation)
					}
				})
			}
		})
	}
}

func TestMCPAuthorizationServerMetadataAdvertisesFactoryRoutesOnly(t *testing.T) {
	jwksPath := "/oauth2/keys"
	service := &MCPAuthorizationService{
		options: MCPAuthorizationOptions{
			Issuer: "https://issuer.example.test", Scopes: []string{"openid", "greeting"},
			AllowDynamicClientRegistration: true, AllowUnauthenticatedPublicClientRegistration: true,
		},
		jwt: jwtplugin.Options{JWKS: jwtplugin.JWKSOptions{Path: &jwksPath}},
	}
	baseURL := "https://auth.example.test/api/auth/"
	want := map[string]any{
		"issuer":                                         "https://issuer.example.test",
		"authorization_endpoint":                         "https://auth.example.test/api/auth/oauth2/authorize",
		"token_endpoint":                                 "https://auth.example.test/api/auth/oauth2/token",
		"registration_endpoint":                          "https://auth.example.test/api/auth/oauth2/register",
		"jwks_uri":                                       "https://auth.example.test/api/auth/oauth2/keys",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               []string{"openid", "greeting"},
	}
	if got := service.AuthorizationServerMetadata(baseURL); !reflect.DeepEqual(got, want) {
		t.Fatalf("MCP authorization metadata = %#v, want %#v", got, want)
	}

	service.options.AllowDynamicClientRegistration = false
	wantWithoutRegistration := make(map[string]any, len(want)-1)
	for key, value := range want {
		if key != "registration_endpoint" {
			wantWithoutRegistration[key] = value
		}
	}
	if got := service.AuthorizationServerMetadata(baseURL); !reflect.DeepEqual(got, wantWithoutRegistration) {
		t.Fatalf("MCP authorization metadata without registration = %#v, want %#v", got, wantWithoutRegistration)
	}
}

func runMCPUnauthorized(t *testing.T, transportName string, resource any, authorization string) (int, string) {
	t.Helper()
	now := time.Date(2028, time.January, 2, 3, 4, 5, 0, time.UTC)
	schema, err := storage.CoreSchema().Merge(jwtplugin.Schema())
	if err != nil {
		t.Fatal(err)
	}
	adapter := memory.MustNew(memory.WithSchema(schema), memory.WithClock(func() time.Time { return now }))
	service, err := NewMCPResourceService(MCPResourceOptions{
		Resource: resource, Issuer: "http://localhost:3000", Audience: resource,
		JWT: jwtplugin.Options{Runtime: jwtplugin.Runtime{Adapter: adapter, Clock: func() time.Time { return now }}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plugin := engine.Plugin{ID: "mcp-resource-test", Endpoints: []engine.Endpoint{{
		Name: "mcpResourceTest", Path: "/mcp", Methods: []string{http.MethodPost}, Handler: service.Guard(nil),
	}}}
	registry, err := engine.NewRegistry(nil, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "http://localhost/api/auth/mcp", strings.NewReader(`{}`))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	switch transportName {
	case "net-http":
		recorder := httptest.NewRecorder()
		nethttptransport.NewHandler(dispatcher).ServeHTTP(recorder, request)
		return recorder.Code, recorder.Header().Get("WWW-Authenticate")
	case "fasthttp":
		var fastRequest fasthttpserver.Request
		fastRequest.Header.SetMethod(http.MethodPost)
		fastRequest.SetRequestURI(request.URL.String())
		fastRequest.Header.Set("Authorization", authorization)
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&fastRequest, nil, nil)
		fasthttptransport.NewHandler(dispatcher)(&ctx)
		return ctx.Response.StatusCode(), string(ctx.Response.Header.Peek("WWW-Authenticate"))
	case "fiber":
		app := fiberframework.New()
		app.All("/*", fibertransport.NewHandler(dispatcher))
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode, response.Header.Get("WWW-Authenticate")
	default:
		t.Fatalf("unknown transport %q", transportName)
		return 0, ""
	}
}
