package bearer_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
)

const (
	integrationSecret     = "0123456789abcdef0123456789abcdef"
	integrationCookieName = "single-auth.session_token"
)

func TestRootHTTPAndDirectSessionFlows(t *testing.T) {
	plugin := bearer.MustNew(bearer.Options{Runtime: bearer.Runtime{
		Secret: integrationSecret, SessionCookieName: integrationCookieName,
	}})
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://example.test", Secret: integrationSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Plugins:          []singleauth.Plugin{plugin},
	})

	signUpBody := []byte(`{"name":"Bearer User","email":"bearer@example.com","password":"password123"}`)
	signUp := httptest.NewRequest(http.MethodPost, "http://example.test/api/auth/sign-up/email", bytes.NewReader(signUpBody))
	signUp.Header.Set("Content-Type", "application/json")
	signUpRecorder := httptest.NewRecorder()
	auth.ServeHTTP(signUpRecorder, signUp)
	if signUpRecorder.Code != http.StatusOK {
		t.Fatalf("sign up status=%d body=%s", signUpRecorder.Code, signUpRecorder.Body.String())
	}
	signedToken := signUpRecorder.Header().Get("set-auth-token")
	if signedToken == "" || !strings.Contains(signedToken, ".") {
		t.Fatalf("set-auth-token = %q", signedToken)
	}
	if exposed := signUpRecorder.Header().Get("Access-Control-Expose-Headers"); exposed != "set-auth-token" {
		t.Fatalf("exposed headers = %q", exposed)
	}

	assertHTTPSession := func(t *testing.T, token string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "http://example.test/api/auth/get-session", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("get session status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result["session"] == nil || result["user"] == nil {
			t.Fatalf("session result = %#v", result)
		}
	}
	assertHTTPSession(t, signedToken)
	assertHTTPSession(t, strings.SplitN(signedToken, ".", 2)[0])

	existingCookie := cookies.SetRequestCookie("", integrationCookieName, signedToken)
	invalidBearer := httptest.NewRequest(http.MethodGet, "http://example.test/api/auth/get-session", nil)
	invalidBearer.Header.Set("Authorization", "Bearer invalid.token")
	invalidBearer.Header.Set("Cookie", existingCookie)
	invalidRecorder := httptest.NewRecorder()
	auth.ServeHTTP(invalidRecorder, invalidBearer)
	if invalidRecorder.Code != http.StatusOK || !strings.Contains(invalidRecorder.Body.String(), `"session"`) {
		t.Fatalf("invalid bearer displaced cookie: status=%d body=%s", invalidRecorder.Code, invalidRecorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "http://example.test/api/auth/list-sessions", nil)
	list.Header.Set("Authorization", "bEaReR "+signedToken)
	listRecorder := httptest.NewRecorder()
	auth.ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list sessions status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	var sessions []any
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &sessions); err != nil || len(sessions) != 1 {
		t.Fatalf("sessions=%#v err=%v", sessions, err)
	}

	directRequest := contract.NewRequest(http.MethodGet, "/get-session", contract.RequestOptions{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Authorization", Value: "Bearer " + signedToken}),
	})
	directResponse, err := auth.Invoke("getSession", engine.DirectInput{Request: directRequest})
	if err != nil {
		t.Fatal(err)
	}
	var direct map[string]any
	if err := json.Unmarshal(directResponse.Body(), &direct); err != nil || direct["session"] == nil {
		t.Fatalf("direct session=%#v err=%v", direct, err)
	}

	signOut := httptest.NewRequest(http.MethodPost, "http://example.test/api/auth/sign-out", nil)
	signOut.Header.Set("Authorization", "Bearer "+signedToken)
	signOut.Header.Set("Origin", "http://example.test")
	signOutRecorder := httptest.NewRecorder()
	auth.ServeHTTP(signOutRecorder, signOut)
	if signOutRecorder.Code != http.StatusOK {
		t.Fatalf("sign out status=%d body=%s", signOutRecorder.Code, signOutRecorder.Body.String())
	}
	if token := signOutRecorder.Header().Get("set-auth-token"); token != "" {
		t.Fatalf("logout exposed token = %q", token)
	}
}

func TestRootFactoryBindsSecretAndSecureCookie(t *testing.T) {
	secure := true
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "https://example.test", Secret: integrationSecret,
		Advanced:         singleauth.AdvancedOptions{UseSecureCookies: &secure},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories:  []singleauth.PluginFactory{bearer.NewFactory(bearer.Options{})},
	})

	signUp := httptest.NewRequest(
		http.MethodPost,
		"https://example.test/api/auth/sign-up/email",
		bytes.NewReader([]byte(`{"name":"Factory User","email":"factory-bearer@example.com","password":"password123"}`)),
	)
	signUp.Header.Set("Content-Type", "application/json")
	signUpRecorder := httptest.NewRecorder()
	auth.ServeHTTP(signUpRecorder, signUp)
	if signUpRecorder.Code != http.StatusOK {
		t.Fatalf("sign up status=%d body=%s", signUpRecorder.Code, signUpRecorder.Body.String())
	}
	token := signUpRecorder.Header().Get("set-auth-token")
	if token == "" {
		t.Fatal("factory bearer did not expose the secure session token")
	}

	getSession := httptest.NewRequest(http.MethodGet, "https://example.test/api/auth/get-session", nil)
	getSession.Header.Set("Authorization", "Bearer "+token)
	getSessionRecorder := httptest.NewRecorder()
	auth.ServeHTTP(getSessionRecorder, getSession)
	if getSessionRecorder.Code != http.StatusOK || !strings.Contains(getSessionRecorder.Body.String(), `"session"`) {
		t.Fatalf("get session status=%d body=%s", getSessionRecorder.Code, getSessionRecorder.Body.String())
	}
}
