package oauthprovider

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
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

type userInfoCase struct {
	Title       string
	Observation userInfoObservation
}

type userInfoObservation struct {
	Status               int      `json:"status"`
	ClaimKeys            []string `json:"claimKeys,omitempty"`
	SubMatches           bool     `json:"subMatches,omitempty"`
	NameMatches          bool     `json:"nameMatches,omitempty"`
	GivenNameType        string   `json:"givenNameType,omitempty"`
	FamilyNameType       string   `json:"familyNameType,omitempty"`
	EmailMatches         bool     `json:"emailMatches,omitempty"`
	EmailVerifiedMatches bool     `json:"emailVerifiedMatches,omitempty"`
	Error                string   `json:"error,omitempty"`
	ErrorDescription     string   `json:"errorDescription,omitempty"`
}

type userInfoExchange func(method, target, authorization string) (int, []byte, error)

type userInfoHarness struct {
	adapter    storage.Adapter
	dispatcher *engine.Dispatcher
	exchange   userInfoExchange
	user       storage.Record
}

func TestOAuthProviderUserInfoHTTP(t *testing.T) {
	for _, vector := range userInfoCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					harness := newUserInfoHarness(t, transportName)
					actual := harness.run(t, vector.Title)
					if !reflect.DeepEqual(actual, vector.Observation) {
						t.Fatalf("userinfo observation = %#v, want %#v", actual, vector.Observation)
					}
				})
			}
		})
	}
}

func newUserInfoHarness(t *testing.T, transportName string) *userInfoHarness {
	t.Helper()
	now := time.Date(2028, time.January, 2, 3, 4, 5, 0, time.UTC)
	schema, err := storage.CoreSchema().Merge(OAuthProviderSchema())
	if err != nil {
		t.Fatal(err)
	}
	adapter := memory.MustNew(memory.WithSchema(schema), memory.WithClock(func() time.Time { return now }))
	user := storage.Record{
		"id": "userinfo-user", "name": "Test User", "email": "test@example.com",
		"emailVerified": true, "image": nil,
	}
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user", Data: user, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "oauthClient", Data: storage.Record{
			"clientId": "userinfo-client", "clientSecret": "secret",
			"redirectUris": []string{"http://localhost:5000/callback"}, "disabled": false,
		},
	}); err != nil {
		t.Fatal(err)
	}
	for token, scopes := range map[string][]string{
		"opaque-all":       {"openid", "profile", "email", "offline_access"},
		"opaque-profile":   {"openid", "profile"},
		"opaque-email":     {"openid", "email"},
		"opaque-sub":       {"openid"},
		"opaque-no-openid": {"profile"},
	} {
		if _, err := adapter.Create(t.Context(), storage.CreateParams{
			Model: "oauthAccessToken", Data: storage.Record{
				"token": token, "clientId": "userinfo-client", "userId": user["id"],
				"expiresAt": now.Add(time.Hour), "createdAt": now, "scopes": scopes,
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	plugin, err := NewUserInfoPlugin(UserInfoOptions{
		Adapter: adapter, Clock: func() time.Time { return now },
		ValidateJWT: func(_ *engine.Context, token string) (map[string]any, error) {
			if token != "jwt-all" {
				return nil, ErrInvalidJWTAccessToken
			}
			return map[string]any{
				"active": true, "sub": user["id"], "azp": "userinfo-client",
				"scope": "openid profile email offline_access",
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry(nil, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return &userInfoHarness{
		adapter: adapter, dispatcher: dispatcher,
		exchange: newUserInfoExchange(t, transportName, dispatcher), user: user,
	}
}

func (harness *userInfoHarness) run(t *testing.T, title string) userInfoObservation {
	t.Helper()
	method := http.MethodGet
	token := "opaque-all"
	direct := false
	switch title {
	case "should accept POST with the bearer token in the Authorization header":
		method = http.MethodPost
		token = "Bearer opaque-all"
	case "should fail unauthenticated request":
		token = ""
	case "should fail without the openid scope":
		token = "opaque-no-openid"
	case "should pass provide all user information - jwt":
		token = "jwt-all"
	case "should pass provide all user information - opaque":
	case "should pass provide scoped user information - email only":
		token = "opaque-email"
	case "should pass provide scoped user information - profile only":
		token = "opaque-profile"
	case "should pass provide scoped user information - sub only":
		token = "opaque-sub"
	case "should reject auth.api userinfo when Authorization header is missing":
		token = ""
		direct = true
	case "should return userinfo via auth.api with headers only (no Request)":
		token = "Bearer opaque-all"
		direct = true
	default:
		t.Fatalf("unsupported userinfo title %q", title)
	}

	var status int
	var encoded []byte
	var err error
	if direct {
		headers := contract.NewHeaders()
		if token != "" {
			headers.Set("Authorization", token)
		}
		request := contract.NewRequest(method, "/:direct", contract.RequestOptions{Headers: headers})
		response, _ := harness.dispatcher.Invoke("oauth2UserInfo", engine.DirectInput{Request: request})
		status, encoded = response.Status(), response.Body()
	} else {
		status, encoded, err = harness.exchange(method, "/api/auth/oauth2/userinfo", token)
		if err != nil {
			t.Fatal(err)
		}
	}
	return observeUserInfo(t, title, status, encoded, harness.user)
}

func observeUserInfo(
	t *testing.T,
	title string,
	status int,
	encoded []byte,
	user storage.Record,
) userInfoObservation {
	t.Helper()
	observation := userInfoObservation{Status: status}
	var value map[string]any
	if len(bytes.TrimSpace(encoded)) > 0 {
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
	}
	if status != http.StatusOK {
		if title == "should reject auth.api userinfo when Authorization header is missing" {
			observation.Error, _ = value["error"].(string)
			observation.ErrorDescription, _ = value["error_description"].(string)
		}
		return observation
	}
	observation.ClaimKeys = make([]string, 0, len(value))
	for key := range value {
		observation.ClaimKeys = append(observation.ClaimKeys, key)
	}
	sort.Strings(observation.ClaimKeys)
	observation.SubMatches = value["sub"] == user["id"]
	observation.NameMatches = value["name"] == user["name"]
	observation.GivenNameType = userInfoJSONType(value, "given_name")
	observation.FamilyNameType = userInfoJSONType(value, "family_name")
	observation.EmailMatches = value["email"] == user["email"]
	observation.EmailVerifiedMatches = value["email_verified"] == user["emailVerified"]
	return observation
}

func userInfoJSONType(value map[string]any, key string) string {
	claim, exists := value[key]
	if !exists {
		return "undefined"
	}
	switch claim.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case nil:
		return "object"
	default:
		return "object"
	}
}

func newUserInfoExchange(
	t *testing.T,
	transportName string,
	dispatcher *engine.Dispatcher,
) userInfoExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		handler := nethttptransport.NewHandler(dispatcher)
		return func(method, target, authorization string) (int, []byte, error) {
			request := httptest.NewRequest(method, "http://localhost:3000"+target, nil)
			if authorization != "" {
				request.Header.Set("Authorization", authorization)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, encoded, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(dispatcher)
		return func(method, target, authorization string) (int, []byte, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.Header.SetHost("localhost:3000")
			if authorization != "" {
				request.Header.Set("Authorization", authorization)
			}
			request.SetRequestURI(target)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123}, nil)
			handler(&requestContext)
			return requestContext.Response.StatusCode(), append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(dispatcher))
		return func(method, target, authorization string) (int, []byte, error) {
			request, err := http.NewRequest(method, "http://localhost:3000"+target, nil)
			if err != nil {
				return 0, nil, err
			}
			if authorization != "" {
				request.Header.Set("Authorization", authorization)
			}
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return 0, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, encoded, err
		}
	default:
		t.Fatalf("unknown userinfo transport %q", transportName)
		return nil
	}
}
