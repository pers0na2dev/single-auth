package oauthprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
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
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type logoutCase struct {
	Suite       string
	Title       string
	Observation logoutObservation
}

type logoutObservation struct {
	Status                  int              `json:"status"`
	DataIsNull              bool             `json:"dataIsNull"`
	ErrorIsNull             bool             `json:"errorIsNull"`
	SIDPresent              bool             `json:"sidPresent"`
	SIDMatchesSession       bool             `json:"sidMatchesSession"`
	SessionRemoved          bool             `json:"sessionRemoved"`
	Location                string           `json:"location"`
	ClientID                bool             `json:"clientId"`
	UserID                  bool             `json:"userId"`
	ClientSecret            bool             `json:"clientSecret"`
	RedirectURIs            []string         `json:"redirectURIs"`
	PostLogoutRedirectURIs  []string         `json:"postLogoutRedirectURIs"`
	EnableEndSessionPresent bool             `json:"enableEndSessionPresent"`
	TokenShape              logoutTokenShape `json:"tokenShape"`
}

type logoutTokenShape struct {
	AccessToken  bool   `json:"accessToken"`
	IDToken      bool   `json:"idToken"`
	RefreshToken bool   `json:"refreshToken"`
	Scope        string `json:"scope"`
}

type logoutExchange func(method, target string, body []byte) (int, http.Header, []byte, error)

type logoutHarness struct {
	adapter    storage.Adapter
	exchange   logoutExchange
	issuer     string
	disableJWT bool
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func TestOAuthProviderLogoutHTTP(t *testing.T) {
	for _, vector := range logoutCases {
		vector := vector
		t.Run(vector.Suite+"/"+vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					disableJWT := vector.Suite == "oauth logout - disableJwtPlugin"
					harness := newLogoutHarness(t, transportName, disableJWT)
					actual := harness.run(t, vector.Title)
					if !reflect.DeepEqual(actual, vector.Observation) {
						t.Fatalf("logout observation = %#v, want %#v", actual, vector.Observation)
					}
				})
			}
		})
	}
}

func newLogoutHarness(t *testing.T, transportName string, disableJWT bool) *logoutHarness {
	t.Helper()
	schema, err := storage.CoreSchema().Merge(OAuthProviderSchema())
	if err != nil {
		t.Fatal(err)
	}
	adapter := memory.MustNew(memory.WithSchema(schema))
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	issuer := "http://localhost:3000/api/auth"
	plugin, err := NewLogoutPlugin(LogoutOptions{
		DisableJWTPlugin: disableJWT,
		Runtime: LogoutRuntime{
			Adapter: adapter,
			Issuer:  issuer,
			VerifyJWT: func(_ *engine.Context, token string) (map[string]any, error) {
				return verifyEdDSALogoutToken(token, publicKey)
			},
			DecryptClientSecret: func(_ context.Context, stored string) (string, error) {
				return strings.TrimPrefix(stored, "encrypted:"), nil
			},
			DeleteSession: func(ctx context.Context, token string) error {
				return adapter.Delete(ctx, storage.DeleteParams{
					Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
				})
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dynamicRegistration := engine.Endpoint{
		Name: "logoutCompatibilityDynamicRegistration", Path: "/oauth2/register",
		Methods: []string{http.MethodPost}, Handler: func(ctx *engine.Context) (contract.Response, error) {
			var input map[string]any
			if err := json.Unmarshal(ctx.Request().Body(), &input); err != nil {
				return contract.Response{}, err
			}
			clean := SanitizeDynamicRegistration(input)
			clean["client_id"] = "dynamic-client"
			clean["user_id"] = "dynamic-user"
			clean["client_secret"] = "dynamic-secret"
			return contract.JSONResponse(contract.StatusOK, clean)
		},
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{dynamicRegistration}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return &logoutHarness{
		adapter: adapter, exchange: newLogoutExchange(t, transportName, dispatcher),
		issuer: issuer, disableJWT: disableJWT, privateKey: privateKey, publicKey: publicKey,
	}
}

func (harness *logoutHarness) run(t *testing.T, title string) logoutObservation {
	t.Helper()
	const (
		clientID          = "logout-client"
		clientSecret      = "logout-client-secret"
		sessionID         = "logout-session"
		sessionToken      = "logout-session-token"
		logoutRedirectURI = "http://localhost:5000/api/auth/oauth2/callback/logout"
		redirectURI       = "http://localhost:5000/api/auth/oauth2/callback/test"
	)
	tokenShape := logoutTokenShape{
		AccessToken: true, IDToken: true, RefreshToken: true,
		Scope: "openid email profile offline_access",
	}

	switch title {
	case "should fail with invalid id_token_hint":
		status, _, _, err := harness.exchange(http.MethodGet, "/api/auth/oauth2/end-session?id_token_hint=", nil)
		if err != nil {
			t.Fatal(err)
		}
		return logoutObservation{Status: status}

	case "should not allow registration of rp-initiated clients, specifically enable_end_session":
		body, err := json.Marshal(map[string]any{
			"redirect_uris":             []string{redirectURI},
			"post_logout_redirect_uris": []string{logoutRedirectURI},
			"enable_end_session":        true,
		})
		if err != nil {
			t.Fatal(err)
		}
		status, _, responseBody, err := harness.exchange(http.MethodPost, "/api/auth/oauth2/register", body)
		if err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := json.Unmarshal(responseBody, &response); err != nil {
			t.Fatal(err)
		}
		return logoutObservation{
			Status:   status,
			ClientID: response["client_id"] != nil, UserID: response["user_id"] != nil,
			ClientSecret:            response["client_secret"] != nil,
			RedirectURIs:            interfaceStrings(response["redirect_uris"]),
			PostLogoutRedirectURIs:  interfaceStrings(response["post_logout_redirect_uris"]),
			EnableEndSessionPresent: hasMapKey(response, "enable_end_session"),
		}

	case "should fail for clients without enable_end_session access":
		harness.seedClient(t, clientID, clientSecret, false, nil)
		idToken := harness.signIDToken(t, clientID, "")
		status, _, _, err := harness.exchange(http.MethodGet, "/api/auth/oauth2/end-session?id_token_hint="+url.QueryEscape(idToken), nil)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := decodeCompactJWSPayload(idToken)
		if err != nil {
			t.Fatal(err)
		}
		return logoutObservation{
			Status: status, SIDPresent: hasMapKey(claims, "sid"), TokenShape: tokenShape,
		}

	case "should pass for clients with enable_end_session access":
		harness.seedClient(t, clientID, clientSecret, true, nil)
		harness.seedSession(t, sessionID, sessionToken)
		idToken := harness.signIDToken(t, clientID, sessionID)
		claims, err := decodeCompactJWSPayload(idToken)
		if err != nil {
			t.Fatal(err)
		}
		status, _, body, err := harness.exchange(http.MethodGet, "/api/auth/oauth2/end-session?id_token_hint="+url.QueryEscape(idToken), nil)
		if err != nil {
			t.Fatal(err)
		}
		remaining, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "session", Where: []storage.Where{{Field: "id", Value: sessionID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		sid, sidPresent := claims["sid"].(string)
		return logoutObservation{
			Status: status, DataIsNull: string(bytes.TrimSpace(body)) == "null", ErrorIsNull: status == http.StatusOK,
			SIDPresent: sidPresent, SIDMatchesSession: sid == sessionID, SessionRemoved: remaining == nil,
			TokenShape: tokenShape,
		}

	case "should pass with redirection":
		harness.seedClient(t, clientID, clientSecret, true, []string{logoutRedirectURI})
		harness.seedSession(t, sessionID, sessionToken)
		idToken := harness.signIDToken(t, clientID, sessionID)
		query := url.Values{
			"id_token_hint":            {idToken},
			"post_logout_redirect_uri": {logoutRedirectURI},
		}
		if !harness.disableJWT {
			query.Set("state", "123")
		}
		status, headers, _, err := harness.exchange(http.MethodGet, "/api/auth/oauth2/end-session?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := decodeCompactJWSPayload(idToken)
		if err != nil {
			t.Fatal(err)
		}
		_, sidPresent := claims["sid"].(string)
		return logoutObservation{Status: status, Location: headers.Get("Location"), SIDPresent: sidPresent}
	default:
		t.Fatalf("unsupported logout scenario %q", title)
		return logoutObservation{}
	}
}

func (harness *logoutHarness) seedClient(
	t *testing.T,
	clientID, clientSecret string,
	enableEndSession bool,
	postLogoutRedirectURIs []string,
) {
	t.Helper()
	storedSecret := clientSecret
	if harness.disableJWT {
		storedSecret = "encrypted:" + clientSecret
	}
	data := storage.Record{
		"clientId": clientID, "clientSecret": storedSecret,
		"redirectUris": []string{"http://localhost:5000/api/auth/oauth2/callback/test"},
		"disabled":     false, "enableEndSession": enableEndSession,
	}
	if postLogoutRedirectURIs != nil {
		data["postLogoutRedirectUris"] = postLogoutRedirectURIs
	}
	if _, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "oauthClient", Data: data,
	}); err != nil {
		t.Fatal(err)
	}
}

func (harness *logoutHarness) seedSession(t *testing.T, sessionID, token string) {
	t.Helper()
	const userID = "logout-user"
	if _, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "user", ForceAllowID: true, Data: storage.Record{
			"id": userID, "name": "Logout User", "email": "logout@example.test",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "session", ForceAllowID: true, Data: storage.Record{
			"id": sessionID, "token": token, "userId": userID,
			"expiresAt": time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func (harness *logoutHarness) signIDToken(t *testing.T, clientID, sessionID string) string {
	t.Helper()
	payload := map[string]any{
		"iss": harness.issuer, "aud": clientID, "sub": "logout-user",
	}
	if sessionID != "" {
		payload["sid"] = sessionID
	}
	var token string
	var err error
	if harness.disableJWT {
		token, err = signLogoutHS256(payload, "logout-client-secret")
	} else {
		token, err = signEdDSALogoutToken(payload, harness.privateKey)
	}
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signLogoutHS256(payload map[string]any, secret string) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "HS256"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func signEdDSALogoutToken(payload map[string]any, privateKey ed25519.PrivateKey) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "logout-key"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	signature := ed25519.Sign(privateKey, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func verifyEdDSALogoutToken(token string, publicKey ed25519.PublicKey) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed EdDSA token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, fmt.Errorf("invalid EdDSA token")
	}
	return decodeCompactJWSPayload(token)
}

func newLogoutExchange(t *testing.T, transportName string, dispatcher *engine.Dispatcher) logoutExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		handler := nethttptransport.NewHandler(dispatcher)
		return func(method, target string, body []byte) (int, http.Header, []byte, error) {
			request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(dispatcher)
		return func(method, target string, body []byte) (int, http.Header, []byte, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.Header.SetHost("localhost:3000")
			request.Header.SetContentType("application/json")
			request.SetRequestURI(target)
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123}, nil)
			handler(&requestContext)
			headers := make(http.Header)
			requestContext.Response.Header.VisitAll(func(name, value []byte) {
				headers.Add(string(name), string(value))
			})
			return requestContext.Response.StatusCode(), headers, append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(dispatcher))
		return func(method, target string, body []byte) (int, http.Header, []byte, error) {
			request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			if err != nil {
				return 0, nil, nil, err
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return 0, nil, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	default:
		t.Fatalf("unknown logout transport %q", transportName)
		return nil
	}
}

func interfaceStrings(value any) []string {
	values, _ := value.([]any)
	result := make([]string, 0, len(values))
	for _, item := range values {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func hasMapKey(input map[string]any, key string) bool {
	_, exists := input[key]
	return exists
}
