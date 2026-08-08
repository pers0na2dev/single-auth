package anonymous_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/anonymous"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const (
	testBaseURL = "http://auth.example.test"
	testSecret  = "0123456789abcdef0123456789abcdef"
)

func TestRootFactoryNetHTTPAnonymousLifecycle(t *testing.T) {
	auth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL,
		Secret:  testSecret,
		PluginFactories: []singleauth.PluginFactory{
			anonymous.NewFactory(anonymous.Options{}),
		},
	})

	status, headers, signedIn := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", "", nil)
	if status != http.StatusOK {
		t.Fatalf("anonymous sign-in status=%d body=%#v", status, signedIn)
	}
	user := object(t, signedIn, "user")
	if user["isAnonymous"] != true || user["name"] != "Anonymous" {
		t.Fatalf("anonymous user = %#v", user)
	}
	userID := user["id"].(string)
	token := signedIn["token"].(string)
	if token == "" {
		t.Fatal("anonymous token is empty")
	}
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))

	status, _, session := exchangeHTTP(t, auth.Handler(), http.MethodGet, "/get-session", cookie, nil)
	if status != http.StatusOK || object(t, session, "user")["isAnonymous"] != true {
		t.Fatalf("anonymous session status=%d body=%#v", status, session)
	}
	status, _, repeated := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", cookie, nil)
	if status != http.StatusBadRequest || repeated["code"] != anonymous.ErrorAnonymousUsersCannotSignInAgainAnonymously ||
		repeated["message"] != "Anonymous users cannot sign in again anonymously" {
		t.Fatalf("repeat status=%d body=%#v", status, repeated)
	}

	status, deleteHeaders, deleted := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/delete-anonymous-user", cookie, nil)
	if status != http.StatusOK || deleted["success"] != true {
		t.Fatalf("delete status=%d body=%#v", status, deleted)
	}
	for _, value := range deleteHeaders.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(value) {
			if strings.Contains(parsed.Name, "session_") && (parsed.Attributes.MaxAge == nil || *parsed.Attributes.MaxAge != 0) {
				t.Fatalf("non-expiring delete cookie = %#v", parsed)
			}
		}
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil || stored != nil {
		t.Fatalf("deleted root user = %#v, err=%v", stored, err)
	}
	status, _, after := exchangeHTTPValue(t, auth.Handler(), http.MethodGet, "/get-session", cookie, nil)
	if status != http.StatusOK || after != nil {
		t.Fatalf("session after delete status=%d body=%#v", status, after)
	}
}

func TestRootFactoryDirectAnonymousLifecycle(t *testing.T) {
	auth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{
			GenerateName: func(*engine.Context) (string, error) { return "Direct Guest", nil },
			GenerateRandomEmail: func() (string, error) {
				return "direct-guest@example.com", nil
			},
		})},
	})
	request := contract.NewRequest(http.MethodPost, "/api/auth/sign-in/anonymous", contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "auth.example.test",
	})
	signedIn, err := auth.Invoke("signInAnonymous", engine.DirectInput{Request: request})
	if err != nil || signedIn.Status() != http.StatusOK {
		t.Fatalf("direct sign-in status=%d body=%s err=%v", signedIn.Status(), signedIn.Body(), err)
	}
	var result map[string]any
	if err := json.Unmarshal(signedIn.Body(), &result); err != nil {
		t.Fatal(err)
	}
	user := object(t, result, "user")
	if user["name"] != "Direct Guest" || user["email"] != "direct-guest@example.com" {
		t.Fatalf("direct anonymous user = %#v", user)
	}
	cookie := cookies.ApplySetCookies("", signedIn.Headers().Values("Set-Cookie"))
	headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie})
	repeatRequest := contract.NewRequest(http.MethodPost, "/api/auth/sign-in/anonymous", contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "auth.example.test", Headers: headers,
	})
	repeated, repeatErr := auth.Invoke("signInAnonymous", engine.DirectInput{Request: repeatRequest})
	apiError, ok := contract.AsAPIError(repeatErr)
	if !ok || apiError.Code != anonymous.ErrorAnonymousUsersCannotSignInAgainAnonymously || repeated.Status() != http.StatusBadRequest {
		t.Fatalf("direct repeat status=%d body=%s err=%v", repeated.Status(), repeated.Body(), repeatErr)
	}
	deleteRequest := contract.NewRequest(http.MethodPost, "/api/auth/delete-anonymous-user", contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "auth.example.test", Headers: headers,
	})
	deleted, deleteErr := auth.Invoke("deleteAnonymousUser", engine.DirectInput{Request: deleteRequest})
	if deleteErr != nil || deleted.Status() != http.StatusOK || !strings.Contains(string(deleted.Body()), `"success":true`) {
		t.Fatalf("direct delete status=%d body=%s err=%v", deleted.Status(), deleted.Body(), deleteErr)
	}
}

func TestRootFactoryLinksAnonymousAccountBeforeCleanup(t *testing.T) {
	var mu sync.Mutex
	var linked anonymous.LinkAccountData
	var anonymousExistedInCallback bool
	var auth *singleauth.Auth
	options := singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{
			OnLinkAccount: func(data anonymous.LinkAccountData) error {
				oldID, _ := data.AnonymousUser.User["id"].(string)
				stored, err := auth.Adapter().FindOne(data.Context.GoContext(), storage.FindOneParams{
					Model: "user", Where: []storage.Where{{Field: "id", Value: oldID}},
				})
				mu.Lock()
				linked = data
				anonymousExistedInCallback = err == nil && stored != nil
				mu.Unlock()
				return nil
			},
		})},
	}
	auth = mustAuth(t, options)
	status, headers, signedIn := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", "", nil)
	if status != http.StatusOK {
		t.Fatalf("anonymous sign-in status=%d body=%#v", status, signedIn)
	}
	oldUserID := object(t, signedIn, "user")["id"].(string)
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, _, signedUp := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-up/email", cookie, map[string]any{
		"name": "Permanent User", "email": "permanent@example.com", "password": "password123",
	})
	if status != http.StatusOK {
		t.Fatalf("linked sign-up status=%d body=%#v", status, signedUp)
	}
	newUser := object(t, signedUp, "user")
	if newUser["isAnonymous"] != false || newUser["id"] == oldUserID {
		t.Fatalf("linked new user = %#v", newUser)
	}
	mu.Lock()
	callback := linked
	existed := anonymousExistedInCallback
	mu.Unlock()
	if !existed || callback.Context == nil || callback.Context.Path() != "/sign-up/email" ||
		callback.AnonymousUser.User["id"] != oldUserID || callback.NewUser.User["id"] != newUser["id"] {
		t.Fatalf("link callback existed=%v data=%#v", existed, callback)
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: oldUserID}},
	})
	if err != nil || stored != nil {
		t.Fatalf("post-link anonymous user = %#v, err=%v", stored, err)
	}
}

func TestRootFactoryLinksAfterEmailVerificationAutoSignIn(t *testing.T) {
	var verificationToken string
	var callbackCount int
	var linked anonymous.LinkAccountData
	auth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true, RequireEmailVerification: true,
		},
		EmailVerification: singleauth.EmailVerificationOptions{
			AutoSignInAfterVerification: true,
			SendVerificationEmail: func(_ context.Context, message singleauth.EmailVerificationMessage) error {
				parsed, err := url.Parse(message.URL)
				if err != nil {
					return err
				}
				verificationToken = parsed.Query().Get("token")
				return nil
			},
		},
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{
			OnLinkAccount: func(data anonymous.LinkAccountData) error {
				callbackCount++
				linked = data
				return nil
			},
		})},
	})
	status, headers, signedIn := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", "", nil)
	if status != http.StatusOK {
		t.Fatalf("verification anonymous sign-in status=%d body=%#v", status, signedIn)
	}
	oldUserID := object(t, signedIn, "user")["id"].(string)
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, _, signedUp := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-up/email", cookie, map[string]any{
		"name": "Verified User", "email": "verified@example.com", "password": "password123",
	})
	if status != http.StatusOK || verificationToken == "" || callbackCount != 0 {
		t.Fatalf("verification sign-up status=%d body=%#v token=%q callbacks=%d", status, signedUp, verificationToken, callbackCount)
	}
	status, _, verified := exchangeHTTP(t, auth.Handler(), http.MethodGet, "/verify-email?token="+url.QueryEscape(verificationToken), cookie, nil)
	if status != http.StatusOK || callbackCount != 1 {
		t.Fatalf("verify status=%d body=%#v callbacks=%d", status, verified, callbackCount)
	}
	if linked.Context == nil || linked.Context.Path() != "/verify-email" ||
		linked.AnonymousUser.User["id"] != oldUserID || linked.NewUser.User["email"] != "verified@example.com" {
		t.Fatalf("verification link data = %#v", linked)
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: oldUserID}},
	})
	if err != nil || stored != nil {
		t.Fatalf("verified post-link anonymous user = %#v, err=%v", stored, err)
	}
}

func TestRootFactoryCustomAnonymousFieldAlias(t *testing.T) {
	auth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{
			Schema: storage.Schema{Models: map[string]storage.ModelSchema{
				"user": {Fields: map[string]storage.FieldAttribute{
					"isAnonymous": {FieldName: "is_anon"},
				}},
			}},
		})},
	})
	status, headers, signedIn := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", "", nil)
	if status != http.StatusOK || object(t, signedIn, "user")["isAnonymous"] != true {
		t.Fatalf("aliased sign-in status=%d body=%#v", status, signedIn)
	}
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, _, session := exchangeHTTP(t, auth.Handler(), http.MethodGet, "/get-session", cookie, nil)
	if status != http.StatusOK || object(t, session, "user")["isAnonymous"] != true {
		t.Fatalf("aliased session status=%d body=%#v", status, session)
	}
}

func TestRootFactorySecondaryStorageDeleteInvalidatesSession(t *testing.T) {
	secondary := newSecondaryStore()
	auth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret, SecondaryStorage: secondary,
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{})},
	})
	status, headers, signedIn := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", "", nil)
	if status != http.StatusOK {
		t.Fatalf("secondary sign-in status=%d body=%#v", status, signedIn)
	}
	token := signedIn["token"].(string)
	if !secondary.has(token) {
		t.Fatalf("secondary session %q was not stored", token)
	}
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, _, deleted := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/delete-anonymous-user", cookie, nil)
	if status != http.StatusOK || deleted["success"] != true {
		t.Fatalf("secondary delete status=%d body=%#v", status, deleted)
	}
	if secondary.has(token) {
		t.Fatalf("secondary session %q survived delete", token)
	}
	status, _, after := exchangeHTTPValue(t, auth.Handler(), http.MethodGet, "/get-session", cookie, nil)
	if status != http.StatusOK || after != nil {
		t.Fatalf("secondary session after delete status=%d body=%#v", status, after)
	}
}

func TestTransportNeutralDescriptorRunsThroughDispatchFastHTTPAndFiber(t *testing.T) {
	auth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{})},
	})
	request := contract.NewRequest(http.MethodPost, "/api/auth/sign-in/anonymous", contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "auth.example.test",
	})
	response, err := auth.Dispatch(request)
	if err != nil || response.Status() != http.StatusOK || !strings.Contains(string(response.Body()), `"isAnonymous":true`) {
		t.Fatalf("transport-neutral status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}

	fastAuth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{})},
	})
	handler := fasthttptransport.NewHandler(fastAuth.Dispatcher())
	var fastRequest fasthttpserver.Request
	fastRequest.Header.SetMethod(http.MethodPost)
	fastRequest.SetRequestURI(testBaseURL + "/api/auth/sign-in/anonymous")
	var requestContext fasthttpserver.RequestCtx
	requestContext.Init(&fastRequest, nil, nil)
	handler(&requestContext)
	if requestContext.Response.StatusCode() != http.StatusOK ||
		!strings.Contains(string(requestContext.Response.Body()), `"isAnonymous":true`) ||
		len(requestContext.Response.Header.PeekAll("Set-Cookie")) == 0 {
		t.Fatalf("fasthttp status=%d body=%s cookies=%q", requestContext.Response.StatusCode(), requestContext.Response.Body(), requestContext.Response.Header.PeekAll("Set-Cookie"))
	}

	fiberAuth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{})},
	})
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(fiberAuth.Dispatcher()))
	fiberRequest, err := http.NewRequest(http.MethodPost, testBaseURL+"/api/auth/sign-in/anonymous", nil)
	if err != nil {
		t.Fatal(err)
	}
	fiberResponse, err := app.Test(fiberRequest, fiberframework.TestConfig{Timeout: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer fiberResponse.Body.Close()
	fiberBody, err := io.ReadAll(fiberResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if fiberResponse.StatusCode != http.StatusOK || !strings.Contains(string(fiberBody), `"isAnonymous":true`) ||
		len(fiberResponse.Header.Values("Set-Cookie")) == 0 {
		t.Fatalf("fiber status=%d body=%s cookies=%q", fiberResponse.StatusCode, fiberBody, fiberResponse.Header.Values("Set-Cookie"))
	}
}

func TestAnonymousUsesGlobalRateRuleAndDirectBypassesIt(t *testing.T) {
	enabled := true
	auth := mustAuth(t, singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret, Environment: "test",
		RateLimit:       singleauth.RateLimitOptions{Enabled: &enabled, Window: 60, Max: 1},
		PluginFactories: []singleauth.PluginFactory{anonymous.NewFactory(anonymous.Options{})},
	})
	for attempt := 1; attempt <= 3; attempt++ {
		status, _, result := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", "", nil)
		if status != http.StatusOK {
			t.Fatalf("rate attempt %d status=%d body=%#v", attempt, status, result)
		}
	}
	status, _, blocked := exchangeHTTP(t, auth.Handler(), http.MethodPost, "/sign-in/anonymous", "", nil)
	if status != http.StatusTooManyRequests || blocked["message"] != "Too many requests. Please try again later." {
		t.Fatalf("rate blocked status=%d body=%#v", status, blocked)
	}
	request := contract.NewRequest(http.MethodPost, "/api/auth/sign-in/anonymous", contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "auth.example.test",
	})
	direct, err := auth.Invoke("signInAnonymous", engine.DirectInput{Request: request})
	if err != nil || direct.Status() != http.StatusOK {
		t.Fatalf("direct rate bypass status=%d body=%s err=%v", direct.Status(), direct.Body(), err)
	}
}

func mustAuth(t *testing.T, options singleauth.Options) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func exchangeHTTP(
	t *testing.T,
	handler http.Handler,
	method, path, cookie string,
	body any,
) (int, http.Header, map[string]any) {
	t.Helper()
	status, headers, value := exchangeHTTPValue(t, handler, method, path, cookie, body)
	if value == nil {
		return status, headers, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("response %s %s = %#v, want object", method, path, value)
	}
	return status, headers, object
}

func exchangeHTTPValue(
	t *testing.T,
	handler http.Handler,
	method, path, cookie string,
	body any,
) (int, http.Header, any) {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(payload))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
		request.Header.Set("Origin", testBaseURL)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var value any
	decoder := json.NewDecoder(recorder.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode response status=%d body=%q: %v", recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, recorder.Header(), value
}

func object(t *testing.T, source map[string]any, field string) map[string]any {
	t.Helper()
	value, ok := source[field].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", field, source[field])
	}
	return value
}

type secondaryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newSecondaryStore() *secondaryStore {
	return &secondaryStore{values: map[string]string{}}
}

func (store *secondaryStore) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *secondaryStore) Set(_ context.Context, key, value string, _ int64) error {
	store.mu.Lock()
	store.values[key] = value
	store.mu.Unlock()
	return nil
}

func (store *secondaryStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	delete(store.values, key)
	store.mu.Unlock()
	return nil
}

func (store *secondaryStore) has(key string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, exists := store.values[key]
	return exists
}
