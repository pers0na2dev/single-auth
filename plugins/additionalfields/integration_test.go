package additionalfields_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/plugins/additionalfields"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
)

func TestNetHTTPAndDirectEndpointHooks(t *testing.T) {
	auth := newAuth(t, nil, true)

	status, headers, signedUp := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Alice", "email": "alice@example.com", "password": "password123",
		"displayName": "  Alice D.  ", "code": "abc", "role": "admin",
	})
	if status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%#v", status, signedUp)
	}
	user := object(t, signedUp, "user")
	if user["displayName"] != "Alice D." || user["code"] != "public:abc!!" || user["role"] != "user" {
		t.Fatalf("sign-up user = %#v", user)
	}
	if _, leaked := user["secret"]; leaked {
		t.Fatalf("returned:false user field leaked: %#v", user)
	}
	cookieHeader := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	if !strings.Contains(cookieHeader, "session_data") {
		t.Fatalf("cookie cache did not include additional-field session data: %q", cookieHeader)
	}
	status, _, sessionResult := exchangeHTTP(t, auth.Handler(), http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK {
		t.Fatalf("get-session status=%d body=%#v", status, sessionResult)
	}
	session := object(t, sessionResult, "session")
	if session["theme"] != "light" {
		t.Fatalf("session defaults = %#v", session)
	}
	if _, leaked := session["internalNote"]; leaked {
		t.Fatalf("returned:false session field leaked: %#v", session)
	}

	status, headers, updated := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/update-session", cookieHeader, map[string]any{
		"device": "laptop",
	})
	if status != http.StatusOK || object(t, updated, "session")["device"] != "laptop!!" {
		t.Fatalf("update-session status=%d body=%#v", status, updated)
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, headers.Values("Set-Cookie"))

	fields := model.Fields{}
	fields.Set("displayName", "  Direct Name  ")
	direct, err := auth.API().UpdateUser(t.Context(), singleauth.UpdateUserInput{
		AdditionalFields: fields,
		Headers:          contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
	})
	if err != nil || !direct.Status {
		t.Fatalf("direct update-user = %#v, err=%v", direct, err)
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, direct.Headers.Values("Set-Cookie"))
	status, _, sessionResult = exchangeHTTP(t, auth.Handler(), http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || object(t, sessionResult, "user")["displayName"] != "Direct Name" {
		t.Fatalf("direct update not persisted: status=%d body=%#v", status, sessionResult)
	}

	blocked := model.Fields{}
	blocked.Set("authority", "admin")
	_, err = auth.API().UpdateUser(t.Context(), singleauth.UpdateUserInput{
		AdditionalFields: blocked,
		Headers:          contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
	})
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != 400 || apiError.Code != additionalfields.CodeFieldNotAllowed || apiError.Message != "authority is not allowed to be set" {
		t.Fatalf("input:false direct error = %#v", err)
	}
}

func TestFasthttpHookUsesSameFrozenErrors(t *testing.T) {
	auth := newAuth(t, nil, false)
	handler := fasthttptransport.NewHandler(auth.Dispatcher())
	body, err := json.Marshal(map[string]any{
		"name": "Fast", "email": "fast@example.com", "password": "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	var request fasthttpserver.Request
	request.Header.SetMethod(http.MethodPost)
	request.SetRequestURI("http://localhost/api/auth/sign-up/email")
	request.Header.SetContentType("application/json")
	request.SetBody(body)
	var requestContext fasthttpserver.RequestCtx
	requestContext.Init(&request, nil, nil)
	handler(&requestContext)
	if requestContext.Response.StatusCode() != http.StatusBadRequest {
		t.Fatalf("fasthttp status=%d body=%s", requestContext.Response.StatusCode(), requestContext.Response.Body())
	}
	var response map[string]any
	if err := json.Unmarshal(requestContext.Response.Body(), &response); err != nil {
		t.Fatal(err)
	}
	if response["code"] != additionalfields.CodeMissingField || response["message"] != "displayName is required" {
		t.Fatalf("fasthttp error = %#v", response)
	}
}

func TestFormEndpointHookPreservesRootFormSemantics(t *testing.T) {
	auth := newAuth(t, nil, false)
	form := url.Values{
		"name":        {"Form"},
		"email":       {"form@example.com"},
		"password":    {"password123"},
		"displayName": {"  Form Name  "},
		"code":        {"abc"},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"http://localhost/api/auth/sign-up/email",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://localhost")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("form status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	user := object(t, result, "user")
	if user["displayName"] != "Form Name" || user["code"] != "public:abc!!" {
		t.Fatalf("form user = %#v", user)
	}
}

func TestSecondaryStorageKeepsAndPropagatesAdditionalFields(t *testing.T) {
	secondary := newSecondaryStore()
	auth := newAuth(t, secondary, false)
	status, headers, signedUp := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Secondary", "email": "secondary@example.com", "password": "password123",
		"displayName": "First", "code": "one",
	})
	if status != http.StatusOK {
		t.Fatalf("secondary sign-up status=%d body=%#v", status, signedUp)
	}
	token, _ := signedUp["token"].(string)
	if token == "" {
		t.Fatalf("secondary sign-up token = %#v", signedUp["token"])
	}
	stored := secondary.value(token)
	var payload map[string]map[string]any
	decoder := json.NewDecoder(strings.NewReader(stored))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		t.Fatalf("secondary payload %q: %v", stored, err)
	}
	if payload["session"]["theme"] != "light" || payload["session"]["internalNote"] != "server" ||
		payload["user"]["role"] != "user" || payload["user"]["secret"] != "classified" {
		t.Fatalf("secondary payload = %#v", payload)
	}

	firstCookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, secondHeaders, secondSignIn := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": "secondary@example.com", "password": "password123",
	})
	if status != http.StatusOK {
		t.Fatalf("second sign-in status=%d body=%#v", status, secondSignIn)
	}
	secondCookie := cookies.ApplySetCookies("", secondHeaders.Values("Set-Cookie"))

	status, firstUpdateHeaders, update := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/update-user", firstCookie, map[string]any{
		"displayName": "  Updated Everywhere  ",
	})
	if status != http.StatusOK || update["status"] != true {
		t.Fatalf("secondary update-user status=%d body=%#v", status, update)
	}
	firstCookie = cookies.ApplySetCookies(firstCookie, firstUpdateHeaders.Values("Set-Cookie"))
	status, _, secondSession := exchangeHTTP(t, auth.Handler(), http.MethodGet, "/get-session", secondCookie, nil)
	if status != http.StatusOK || object(t, secondSession, "user")["displayName"] != "Updated Everywhere" {
		t.Fatalf("secondary propagation status=%d body=%#v", status, secondSession)
	}

	status, _, updatedSession := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/update-session", firstCookie, map[string]any{
		"device": "phone",
	})
	if status != http.StatusOK || object(t, updatedSession, "session")["device"] != "phone!" {
		t.Fatalf("secondary update-session status=%d body=%#v", status, updatedSession)
	}
	stored = secondary.value(token)
	decoder = json.NewDecoder(strings.NewReader(stored))
	decoder.UseNumber()
	payload = nil
	if err := decoder.Decode(&payload); err != nil || payload["session"]["device"] != "phone!" {
		t.Fatalf("updated secondary payload=%#v err=%v", payload, err)
	}
}

func newAuth(t *testing.T, secondary singleauth.SecondaryStorage, cookieCache bool) *singleauth.Auth {
	t.Helper()
	optional := storage.Bool(false)
	blocked := storage.Bool(false)
	hidden := storage.Bool(false)
	factory := additionalfields.NewFactory(additionalfields.Options{
		User: additionalfields.Fields{
			{
				Name: "displayName", Attribute: storage.FieldAttribute{Type: storage.FieldString, Required: storage.Bool(true)},
				Validators: additionalfields.FieldValidators{Input: func(value any) (additionalfields.ValidationResult, error) {
					text, ok := value.(string)
					if !ok || strings.TrimSpace(text) == "" {
						return additionalfields.ValidationResult{Issues: []additionalfields.Issue{{Message: "displayName must not be empty"}}}, nil
					}
					return additionalfields.ValidationResult{Value: strings.TrimSpace(text)}, nil
				}},
			},
			{Name: "code", Attribute: storage.FieldAttribute{
				Type: storage.FieldString, Required: optional,
				Transform: storage.FieldTransform{
					Input: func(value any) (any, error) {
						return value.(string) + "!", nil
					},
					Output: func(value any) (any, error) {
						return "public:" + value.(string), nil
					},
				},
			}},
			{Name: "role", Attribute: storage.FieldAttribute{
				Type: storage.FieldString, Input: blocked, DefaultValue: storage.StaticValue("user"),
			}},
			{Name: "authority", Attribute: storage.FieldAttribute{
				Type: storage.FieldString, Required: optional, Input: blocked,
			}},
			{Name: "secret", Attribute: storage.FieldAttribute{
				Type: storage.FieldString, Input: blocked, Returned: hidden, DefaultValue: storage.StaticValue("classified"),
			}},
		},
		Session: additionalfields.Fields{
			{Name: "theme", Attribute: storage.FieldAttribute{Type: storage.FieldString, DefaultValue: storage.StaticValue("light")}},
			{Name: "device", Attribute: storage.FieldAttribute{
				Type: storage.FieldString, Required: optional,
				Transform: storage.FieldTransform{Input: func(value any) (any, error) {
					return value.(string) + "!", nil
				}},
			}},
			{Name: "internalNote", Attribute: storage.FieldAttribute{
				Type: storage.FieldString, Input: blocked, Returned: hidden, DefaultValue: storage.StaticValue("server"),
			}},
		},
	})
	auth, err := singleauth.New(singleauth.Options{
		Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		SecondaryStorage: secondary,
		Session: singleauth.SessionOptions{CookieCache: singleauth.CookieCacheOptions{
			Enabled: cookieCache,
		}},
		PluginFactories: []singleauth.PluginFactory{factory},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func exchangeHTTP(
	t *testing.T,
	handler http.Handler,
	method, path, cookieHeader string,
	body any,
) (int, contract.Headers, map[string]any) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "http://localhost/api/auth"+path, bytes.NewReader(encoded))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", "http://localhost")
	}
	if cookieHeader != "" {
		request.Header.Set("Cookie", cookieHeader)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	headers := contract.Headers{}
	for name, values := range recorder.Header() {
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	if len(recorder.Body.Bytes()) == 0 || bytes.Equal(bytes.TrimSpace(recorder.Body.Bytes()), []byte("null")) {
		return recorder.Code, headers, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes()))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode response status=%d body=%q: %v", recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, headers, decoded
}

func object(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("%s in %#v is not an object", key, parent)
	}
	return value
}

type secondaryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newSecondaryStore() *secondaryStore {
	return &secondaryStore{values: make(map[string]string)}
}

func (s *secondaryStore) Get(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[key], nil
}

func (s *secondaryStore) Set(_ context.Context, key, value string, _ int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
	return nil
}

func (s *secondaryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func (s *secondaryStore) value(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[key]
}
