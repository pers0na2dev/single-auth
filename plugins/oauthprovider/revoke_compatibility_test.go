package oauthprovider

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

const (
	revokeIssuerBaseURL     = "http://localhost:3000"
	revokeIssuerAudience    = "https://myapi.example.com"
	revokeIssuerRedirectURI = "http://localhost:5000/api/auth/oauth2/callback/test"
)

type revokeCase struct {
	Title       string
	Observation revokeObservation
}

type revokeObservation struct {
	Status                          int   `json:"status"`
	DataIsNull                      bool  `json:"dataIsNull"`
	ErrorIsNull                     bool  `json:"errorIsNull"`
	TokenStartsWithConfiguredPrefix *bool `json:"tokenStartsWithConfiguredPrefix,omitempty"`
}

type revokeExchange func(body []byte) (int, []byte, error)

type revokeHarness struct {
	adapter          storage.Adapter
	dispatcher       *engine.Dispatcher
	service          *RevokeService
	exchange         revokeExchange
	tokenExchange    revokeExchange
	input            RevokeInput
	targetKind       string
	targetID         any
	linkedAccessID   any
	jwtRefreshID     any
	jwtToken         string
	prefixConfigured bool
	issuedByEndpoint bool
}

func TestOAuthProviderRevokeHTTP(t *testing.T) {
	for _, vector := range revokeCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber", "direct"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					harness := newRevokeHarness(t, transportName, vector.Title)
					actual := harness.run(t)
					if !reflect.DeepEqual(actual, vector.Observation) {
						t.Fatalf("revoke observation = %#v, want %#v", actual, vector.Observation)
					}
					harness.assertMutation(t, vector.Title)
				})
			}
		})
	}
}

func newRevokeHarness(t *testing.T, transportName, title string) *revokeHarness {
	t.Helper()
	now := time.Date(2028, time.January, 2, 3, 4, 5, 987654321, time.UTC)
	schema, err := storage.CoreSchema().Merge(OAuthProviderSchema())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(title, "jwt access_token") {
		schema, err = schema.Merge(jwtplugin.Schema())
		if err != nil {
			t.Fatal(err)
		}
	}
	adapter := memory.MustNew(
		memory.WithSchema(schema),
		memory.WithClock(func() time.Time { return now }),
	)
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user",
		Data: storage.Record{
			"id": "revoke-user", "name": "Revoke User",
			"email": "revoke@example.com", "emailVerified": true,
		},
		ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	session, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "session",
		Data: storage.Record{
			"token": "revoke-session-token", "userId": "revoke-user",
			"expiresAt": now.Add(24 * time.Hour),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	storedSecret, err := defaultRevokeStoredToken(t.Context(), "revoke-secret", RevokeAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "oauthClient",
		Data: storage.Record{
			"clientId": "revoke-client", "clientSecret": storedSecret,
			"redirectUris": []string{"http://localhost:5000/callback"},
			"disabled":     false, "public": false,
			"grantTypes": []string{
				"authorization_code", "client_credentials", "refresh_token",
			},
			"scopes": []string{
				"openid", "profile", "email", "offline_access", "read:profile",
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	options := RevokeOptions{
		Issuer: &RevokeIssuerOptions{
			Random: rand.Reader, ValidAudiences: []string{revokeIssuerAudience},
		},
		Runtime: RevokeRuntime{
			Adapter: adapter, Clock: func() time.Time { return now },
		},
	}
	harness := &revokeHarness{
		adapter: adapter,
		input: RevokeInput{
			ClientID: "revoke-client", ClientSecret: "revoke-secret",
		},
	}

	switch title {
	case "should pass with the correct opaqueAccessTokenPrefix":
		options.OpaqueAccessTokenPrefix = "hello_"
		harness.prefixConfigured = true
		harness.input.TokenTypeHint = RevokeAccessToken
		harness.targetKind = "issued-access"
	case "should pass with the correct refreshTokenPrefix":
		options.RefreshTokenPrefix = "hello_rt_"
		harness.prefixConfigured = true
		harness.input.TokenTypeHint = RevokeRefreshToken
		harness.targetKind = "issued-refresh"
	case "should fail unauthenticated request":
		harness.input.ClientID = ""
		harness.input.ClientSecret = ""
		harness.seedOpaqueAccessToken(t, "opaque-access-token", "", now)
	case "should fail verification with token_type_hint refresh_token and sent access_token":
		harness.input.TokenTypeHint = RevokeRefreshToken
		harness.seedOpaqueAccessToken(t, "opaque-access-token", "", now)
	case "should fail with token_type_hint access_token and sent refresh_token":
		harness.input.TokenTypeHint = RevokeAccessToken
		harness.seedRefreshToken(t, "refresh-token", "", now)
	case "should pass verification with token_type_hint access_token and sent jwt access_token":
		harness.input.TokenTypeHint = RevokeAccessToken
		harness.targetKind = "issued-jwt"
	case "should pass verification with token_type_hint access_token and sent opaque access_token":
		harness.input.TokenTypeHint = RevokeAccessToken
		harness.seedOpaqueAccessToken(t, "opaque-access-token", "", now)
	case "should pass verification with token_type_hint refresh_token and sent refresh_token":
		harness.input.TokenTypeHint = RevokeRefreshToken
		harness.seedRefreshToken(t, "refresh-token", "", now)
	case "should pass verification without token_type_hint and sent jwt access_token":
		harness.targetKind = "issued-jwt"
	case "should pass verification without token_type_hint and sent opaque access_token":
		harness.seedOpaqueAccessToken(t, "opaque-access-token", "", now)
	case "should pass verification without token_type_hint and sent refresh_token":
		harness.seedRefreshToken(t, "refresh-token", "", now)
	default:
		t.Fatalf("unsupported OAuth revoke title %q", title)
	}

	var jwtDescriptor *engine.Plugin
	if harness.targetKind == "issued-jwt" {
		issuer := revokeIssuerBaseURL
		jwtOptions := jwtplugin.Options{
			JWKS: jwtplugin.JWKSOptions{
				KeyPair: &jwtplugin.KeyPairConfig{
					Algorithm: jwtplugin.EdDSA, Curve: "Ed25519",
				},
				DisablePrivateKeyEncryption: true,
			},
			Token: jwtplugin.TokenOptions{
				Issuer: &issuer, Audience: revokeIssuerAudience,
			},
			Runtime: jwtplugin.Runtime{
				Adapter: adapter, Clock: func() time.Time { return now }, Random: rand.Reader,
				BaseURL: revokeIssuerBaseURL,
				ResolveSession: func(ctx *engine.Context, _ bool) (*jwtplugin.SessionState, error) {
					sessionRecord, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
						Model: "session", Where: []storage.Where{{Field: "id", Value: session["id"]}},
					})
					if findErr != nil {
						return nil, findErr
					}
					userRecord, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
						Model: "user", Where: []storage.Where{{Field: "id", Value: "revoke-user"}},
					})
					if findErr != nil {
						return nil, findErr
					}
					return &jwtplugin.SessionState{Session: sessionRecord, User: userRecord}, nil
				},
			},
		}
		options.JWT = &jwtOptions
		descriptor, descriptorErr := jwtplugin.New(jwtOptions)
		if descriptorErr != nil {
			t.Fatal(descriptorErr)
		}
		jwtDescriptor = &descriptor
	}
	service, err := NewRevokeService(options)
	if err != nil {
		t.Fatal(err)
	}
	plugins := []engine.Plugin{service.Descriptor()}
	if jwtDescriptor != nil {
		plugins = append([]engine.Plugin{*jwtDescriptor}, plugins...)
	}
	registry, err := engine.NewRegistry(nil, plugins...)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	harness.dispatcher = dispatcher
	harness.service = service
	harness.exchange = newRevokeExchange(
		t, transportName, dispatcher, "oauth2Revoke", "/api/auth/oauth2/revoke",
	)
	harness.tokenExchange = newRevokeExchange(
		t, transportName, dispatcher, "oauth2Token", "/api/auth/oauth2/token",
	)
	if strings.HasPrefix(harness.targetKind, "issued-") {
		harness.issueProductionToken(t, title, session["id"], now)
	}
	return harness
}

func (harness *revokeHarness) seedOpaqueAccessToken(
	t *testing.T,
	presented, prefix string,
	now time.Time,
) {
	t.Helper()
	raw := strings.TrimPrefix(presented, prefix)
	stored, err := defaultRevokeStoredToken(t.Context(), raw, RevokeAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	record, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "oauthAccessToken",
		Data: storage.Record{
			"token": stored, "clientId": "revoke-client", "userId": "revoke-user",
			"expiresAt": now.Add(time.Hour), "createdAt": now,
			"scopes": []string{"openid", "profile", "email", "offline_access"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.input.Token = presented
	harness.targetKind = "access"
	harness.targetID = record["id"]
}

func (harness *revokeHarness) seedRefreshToken(
	t *testing.T,
	presented, prefix string,
	now time.Time,
) {
	t.Helper()
	raw := strings.TrimPrefix(presented, prefix)
	stored, err := defaultRevokeStoredToken(t.Context(), raw, RevokeRefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "oauthRefreshToken",
		Data: storage.Record{
			"token": stored, "clientId": "revoke-client", "userId": "revoke-user",
			"expiresAt": now.Add(24 * time.Hour), "createdAt": now,
			"revoked": nil,
			"scopes":  []string{"openid", "profile", "email", "offline_access"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	linkedStored, err := defaultRevokeStoredToken(
		t.Context(), "linked-access-token", RevokeAccessToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	linked, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "oauthAccessToken",
		Data: storage.Record{
			"token": linkedStored, "clientId": "revoke-client", "userId": "revoke-user",
			"refreshId": refresh["id"], "expiresAt": now.Add(time.Hour),
			"createdAt": now, "scopes": []string{"openid"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.input.Token = presented
	harness.targetKind = "refresh"
	harness.targetID = refresh["id"]
	harness.linkedAccessID = linked["id"]
}

func (harness *revokeHarness) issueProductionToken(
	t *testing.T,
	title string,
	sessionID any,
	now time.Time,
) {
	t.Helper()
	values := make(url.Values)
	values.Set("client_id", harness.input.ClientID)
	values.Set("client_secret", harness.input.ClientSecret)
	values.Set("redirect_uri", revokeIssuerRedirectURI)

	switch harness.targetKind {
	case "issued-access":
		values.Set("grant_type", "client_credentials")
		values.Set("scope", "read:profile")
	case "issued-refresh", "issued-jwt":
		code, err := harness.service.CreateAuthorizationCode(
			t.Context(),
			RevokeAuthorizationGrant{
				ClientID: "revoke-client", UserID: "revoke-user",
				SessionID: fmt.Sprint(sessionID), RedirectURI: revokeIssuerRedirectURI,
				Scopes: []string{"openid", "profile", "email", "offline_access"},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		values.Set("grant_type", "authorization_code")
		values.Set("code", code)
		if harness.targetKind == "issued-jwt" {
			values.Set("resource", revokeIssuerAudience)
		}
	default:
		t.Fatalf("unsupported production issuance target %q", harness.targetKind)
	}

	status, encoded, err := harness.tokenExchange([]byte(values.Encode()))
	if err != nil {
		if apiError, ok := contract.AsAPIError(err); ok {
			t.Fatalf("production token endpoint error=%v cause=%v", err, apiError.Cause)
		}
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("production /oauth2/token status=%d body=%s", status, encoded)
	}
	var issued revokeIssuedTokens
	if err := json.Unmarshal(encoded, &issued); err != nil {
		t.Fatalf("decode production token response %q: %v", encoded, err)
	}
	if issued.AccessToken == "" || issued.TokenType != "Bearer" || issued.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Fatalf("production token response = %#v", issued)
	}
	harness.issuedByEndpoint = true

	switch harness.targetKind {
	case "issued-access":
		harness.input.Token = issued.AccessToken
		raw := strings.TrimPrefix(issued.AccessToken, "hello_")
		stored, err := defaultRevokeStoredToken(t.Context(), raw, RevokeAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		row := harness.findByToken(t, "oauthAccessToken", stored)
		if row == nil {
			t.Fatal("issued opaque access token was not persisted")
		}
		harness.targetKind = "access"
		harness.targetID = row["id"]
	case "issued-refresh":
		if issued.RefreshToken == "" {
			t.Fatal("production authorization_code exchange omitted refresh token")
		}
		harness.input.Token = issued.RefreshToken
		raw := strings.TrimPrefix(issued.RefreshToken, "hello_rt_")
		stored, err := defaultRevokeStoredToken(t.Context(), raw, RevokeRefreshToken)
		if err != nil {
			t.Fatal(err)
		}
		refresh := harness.findByToken(t, "oauthRefreshToken", stored)
		if refresh == nil {
			t.Fatal("issued refresh token was not persisted")
		}
		linked, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "oauthAccessToken",
			Where: []storage.Where{{Field: "refreshId", Value: refresh["id"]}},
		})
		if err != nil || linked == nil {
			t.Fatalf("issued refresh family access token=%#v err=%v", linked, err)
		}
		harness.targetKind = "refresh"
		harness.targetID = refresh["id"]
		harness.linkedAccessID = linked["id"]
	case "issued-jwt":
		if len(strings.Split(issued.AccessToken, ".")) != 3 {
			t.Fatalf("production issuer returned non-JWT access token %q", issued.AccessToken)
		}
		if issued.RefreshToken == "" {
			t.Fatal("JWT authorization_code exchange omitted refresh family")
		}
		harness.input.Token = issued.AccessToken
		harness.jwtToken = issued.AccessToken
		rawRefresh := issued.RefreshToken
		storedRefresh, err := defaultRevokeStoredToken(
			t.Context(), rawRefresh, RevokeRefreshToken,
		)
		if err != nil {
			t.Fatal(err)
		}
		refresh := harness.findByToken(t, "oauthRefreshToken", storedRefresh)
		if refresh == nil {
			t.Fatal("JWT issuance did not persist its refresh family")
		}
		harness.jwtRefreshID = refresh["id"]
		harness.targetKind = "jwt"
	default:
		t.Fatalf("unsupported issued target %q for %q", harness.targetKind, title)
	}
}

func (harness *revokeHarness) findByToken(
	t *testing.T,
	model, token string,
) storage.Record {
	t.Helper()
	row, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: model, Where: []storage.Where{{Field: "token", Value: token}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func (harness *revokeHarness) run(t *testing.T) revokeObservation {
	t.Helper()
	values := make(url.Values)
	if harness.input.ClientID != "" {
		values.Set("client_id", harness.input.ClientID)
	}
	if harness.input.ClientSecret != "" {
		values.Set("client_secret", harness.input.ClientSecret)
	}
	values.Set("token", harness.input.Token)
	if harness.input.TokenTypeHint != "" {
		values.Set("token_type_hint", string(harness.input.TokenTypeHint))
	}
	status, encoded, err := harness.exchange([]byte(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	observation := revokeObservation{
		Status: status, DataIsNull: true, ErrorIsNull: status < http.StatusBadRequest,
	}
	if status < http.StatusBadRequest {
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("decode successful revoke response %q: %v", encoded, err)
		}
		observation.DataIsNull = value == nil
	} else {
		var value map[string]any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("decode failed revoke response %q: %v", encoded, err)
		}
		if value["error"] == nil || value["error_description"] == nil {
			t.Fatalf("OAuth revoke error body = %#v", value)
		}
	}
	if harness.prefixConfigured {
		matches := strings.HasPrefix(harness.input.Token, "hello_")
		observation.TokenStartsWithConfiguredPrefix = &matches
	}
	return observation
}

func (harness *revokeHarness) assertMutation(t *testing.T, title string) {
	t.Helper()
	if harness.prefixConfigured && !harness.issuedByEndpoint {
		t.Fatal("prefix vector did not obtain its token from production /oauth2/token")
	}
	switch harness.targetKind {
	case "jwt":
		if !harness.issuedByEndpoint || harness.jwtToken == "" {
			t.Fatal("JWT revoke vector did not traverse production /oauth2/token")
		}
		parts := strings.Split(harness.jwtToken, ".")
		headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		var header map[string]any
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			t.Fatal(err)
		}
		kid, _ := header["kid"].(string)
		if kid == "" || header["alg"] != "EdDSA" {
			t.Fatalf("signed JWT header = %#v", header)
		}
		request := contract.NewRequest(http.MethodGet, "/api/auth/jwks", contract.RequestOptions{
			Scheme: "http", Host: "localhost:3000",
		})
		jwksResponse, jwksErr := harness.dispatcher.Invoke(
			"getJwks", engine.DirectInput{Request: request},
		)
		if jwksErr != nil || jwksResponse.Status() != http.StatusOK {
			t.Fatalf("production JWKS response status=%d err=%v", jwksResponse.Status(), jwksErr)
		}
		var jwks struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(jwksResponse.Body(), &jwks); err != nil {
			t.Fatal(err)
		}
		matched := false
		for _, key := range jwks.Keys {
			if key["kid"] == kid && key["alg"] == "EdDSA" {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("signed JWT kid %q missing from JWKS %#v", kid, jwks.Keys)
		}
		refresh := harness.findByID(t, "oauthRefreshToken", harness.jwtRefreshID)
		if refresh == nil || refresh["revoked"] != nil {
			t.Fatalf("stateless JWT revocation mutated refresh family: %#v", refresh)
		}
		opaqueCount, err := harness.adapter.Count(t.Context(), storage.CountParams{
			Model: "oauthAccessToken",
		})
		if err != nil || opaqueCount != 0 {
			t.Fatalf("JWT issuer persisted opaque access tokens: count=%d err=%v", opaqueCount, err)
		}
		return
	case "access":
		row := harness.findByID(t, "oauthAccessToken", harness.targetID)
		shouldRemain := title == "should fail unauthenticated request" ||
			title == "should fail verification with token_type_hint refresh_token and sent access_token"
		if shouldRemain != (row != nil) {
			t.Fatalf("opaque access token remains = %v, want %v", row != nil, shouldRemain)
		}
	case "refresh":
		row := harness.findByID(t, "oauthRefreshToken", harness.targetID)
		linked := harness.findByID(t, "oauthAccessToken", harness.linkedAccessID)
		shouldRemainActive := title == "should fail with token_type_hint access_token and sent refresh_token"
		if row == nil {
			t.Fatal("refresh token row was deleted instead of atomically revoked")
		}
		if shouldRemainActive {
			if row["revoked"] != nil || linked == nil {
				t.Fatalf("mismatched access hint mutated refresh family: refresh=%#v linked=%#v", row, linked)
			}
			return
		}
		if row["revoked"] == nil || linked != nil {
			t.Fatalf("successful refresh revocation did not revoke family: refresh=%#v linked=%#v", row, linked)
		}
	default:
		t.Fatalf("unknown revoke target kind %q", harness.targetKind)
	}
}

func (harness *revokeHarness) findByID(t *testing.T, model string, id any) storage.Record {
	t.Helper()
	row, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: model, Where: []storage.Where{{Field: "id", Value: id}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func newRevokeExchange(
	t *testing.T,
	transportName string,
	dispatcher *engine.Dispatcher,
	endpointName, target string,
) revokeExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		handler := nethttptransport.NewHandler(dispatcher)
		return func(body []byte) (int, []byte, error) {
			request := httptest.NewRequest(
				http.MethodPost,
				"http://localhost:3000"+target,
				bytes.NewReader(body),
			)
			request.Header.Set("Accept", "application/json")
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, encoded, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(dispatcher)
		return func(body []byte) (int, []byte, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(http.MethodPost)
			request.Header.SetHost("localhost:3000")
			request.Header.Set("Accept", "application/json")
			request.Header.SetContentType("application/x-www-form-urlencoded")
			request.SetRequestURI(target)
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(
				&request,
				&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
				nil,
			)
			handler(&requestContext)
			return requestContext.Response.StatusCode(),
				append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(dispatcher))
		return func(body []byte) (int, []byte, error) {
			request, err := http.NewRequest(
				http.MethodPost,
				"http://localhost:3000"+target,
				bytes.NewReader(body),
			)
			if err != nil {
				return 0, nil, err
			}
			request.Header.Set("Accept", "application/json")
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return 0, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, encoded, err
		}
	case "direct":
		return func(body []byte) (int, []byte, error) {
			headers := contract.NewHeaders(
				contract.HeaderField{Name: "Accept", Value: "application/json"},
				contract.HeaderField{
					Name: "Content-Type", Value: "application/x-www-form-urlencoded",
				},
			)
			request := contract.NewRequest(
				http.MethodPost,
				target,
				contract.RequestOptions{
					Scheme: "http", Host: "localhost:3000", Headers: headers, Body: body,
				},
			)
			response, dispatchErr := dispatcher.Invoke(
				endpointName, engine.DirectInput{Request: request},
			)
			if response.IsZero() {
				return 0, nil, dispatchErr
			}
			if endpointName == "oauth2Token" && dispatchErr != nil {
				return response.Status(), response.Body(), dispatchErr
			}
			return response.Status(), response.Body(), nil
		}
	default:
		t.Fatalf("unknown OAuth revoke transport %q", transportName)
		return nil
	}
}
