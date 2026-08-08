package username

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/storage"
)

const integrationSecret = "0123456789abcdef0123456789abcdef"

func TestFactorySignUpAvailabilityAndUsernameSignIn(t *testing.T) {
	auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
	status, signUpHeaders, signedUp := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Alice", "email": "alice@example.com", "password": "password123",
		"username": "Alice.User",
	})
	if status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%#v", status, signedUp)
	}
	user := usernameObject(t, signedUp, "user")
	if user["username"] != "alice.user" || user["displayUsername"] != "Alice.User" {
		t.Fatalf("sign-up user=%#v", user)
	}
	if len(signUpHeaders.Values("Set-Cookie")) == 0 {
		t.Fatal("sign-up did not issue a session cookie")
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "alice@example.com"}},
	})
	if err != nil || stored == nil || stored["username"] != "alice.user" || stored["displayUsername"] != "Alice.User" {
		t.Fatalf("stored user=%#v err=%v", stored, err)
	}

	status, _, availability := usernameExchange(t, auth, http.MethodPost, "/is-username-available", "", map[string]any{
		"username": "ALICE.USER",
	})
	if status != http.StatusOK || availability["available"] != false {
		t.Fatalf("availability status=%d body=%#v", status, availability)
	}

	callback := "/dashboard?tab=profile"
	status, headers, signedIn := usernameExchange(t, auth, http.MethodPost, "/sign-in/username", "", map[string]any{
		"username": "ALICE.USER", "password": "password123", "callbackURL": callback,
	})
	if status != http.StatusOK || signedIn["redirect"] != true || signedIn["url"] != callback {
		t.Fatalf("sign-in status=%d body=%#v", status, signedIn)
	}
	if token, _ := signedIn["token"].(string); token == "" {
		t.Fatalf("sign-in token=%#v", signedIn["token"])
	}
	if location := headers.Values("Location"); len(location) != 1 || location[0] != callback {
		t.Fatalf("Location=%#v", location)
	}
	cookieHeader := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, _, session := usernameExchange(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || usernameObject(t, session, "user")["username"] != "alice.user" {
		t.Fatalf("get-session status=%d body=%#v", status, session)
	}
}

func TestUsernameHooksFallbackDuplicateAndUpdateOwnership(t *testing.T) {
	auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
	status, firstHeaders, first := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "First", "email": "first@example.com", "password": "password123",
		"displayUsername": "First.User",
	})
	if status != http.StatusOK {
		t.Fatalf("display fallback status=%d body=%#v", status, first)
	}
	firstUser := usernameObject(t, first, "user")
	if firstUser["username"] != "first.user" || firstUser["displayUsername"] != "First.User" {
		t.Fatalf("fallback user=%#v", firstUser)
	}
	firstCookie := cookies.ApplySetCookies("", firstHeaders.Values("Set-Cookie"))

	status, _, second := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Second", "email": "second@example.com", "password": "password123",
		"username": "Second.User",
	})
	if status != http.StatusOK {
		t.Fatalf("second sign-up status=%d body=%#v", status, second)
	}

	status, _, duplicate := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Duplicate", "email": "duplicate@example.com", "password": "password123",
		"username": "FIRST.USER",
	})
	if status != http.StatusBadRequest || duplicate["code"] != CodeUsernameAlreadyTaken {
		t.Fatalf("duplicate status=%d body=%#v", status, duplicate)
	}

	status, _, takenUpdate := usernameExchange(t, auth, http.MethodPost, "/update-user", firstCookie, map[string]any{
		"username": "SECOND.USER",
	})
	if status != http.StatusBadRequest || takenUpdate["code"] != CodeUsernameAlreadyTaken {
		t.Fatalf("taken update status=%d body=%#v", status, takenUpdate)
	}
	status, updateHeaders, sameUpdate := usernameExchange(t, auth, http.MethodPost, "/update-user", firstCookie, map[string]any{
		"username": "FIRST.USER",
	})
	if status != http.StatusOK || sameUpdate["status"] != true {
		t.Fatalf("same-user update status=%d body=%#v", status, sameUpdate)
	}
	firstCookie = cookies.ApplySetCookies(firstCookie, updateHeaders.Values("Set-Cookie"))
	status, _, session := usernameExchange(t, auth, http.MethodGet, "/get-session", firstCookie, nil)
	if status != http.StatusOK || usernameObject(t, session, "user")["username"] != "first.user" {
		t.Fatalf("updated session status=%d body=%#v", status, session)
	}

	status, _, displayOnly := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Display only", "email": "display@example.com", "password": "password123",
		"displayUsername": "not valid because spaces",
	})
	if status != http.StatusOK {
		t.Fatalf("display-only status=%d body=%#v", status, displayOnly)
	}
	displayOnlyUser := usernameObject(t, displayOnly, "user")
	if username, exists := displayOnlyUser["username"]; !exists || username != nil || displayOnlyUser["displayUsername"] != "not valid because spaces" {
		t.Fatalf("display-only user=%#v", displayOnlyUser)
	}
}

func TestCustomNormalizationAndDisplayValidation(t *testing.T) {
	options := Options{
		UsernameNormalization: func(value string) string {
			return strings.ToLower(strings.ReplaceAll(value, "-", ""))
		},
		UsernameValidator: func(value string) (bool, error) {
			return !strings.Contains(value, " "), nil
		},
		DisplayUsernameNormalization: strings.TrimSpace,
		DisplayUsernameValidator: func(value string) (bool, error) {
			return strings.HasPrefix(value, "@"), nil
		},
		ValidationOrder: ValidationOrders{DisplayUsername: PostNormalization},
	}
	auth := newTestAuth(t, options, singleauth.EmailVerificationOptions{}, false)
	status, _, invalid := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Invalid", "email": "invalid-display@example.com", "password": "password123",
		"username": "Custom-Name", "displayUsername": " display ",
	})
	if status != http.StatusBadRequest || invalid["code"] != CodeInvalidDisplayUsername {
		t.Fatalf("invalid display status=%d body=%#v", status, invalid)
	}
	status, _, valid := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Valid", "email": "valid-display@example.com", "password": "password123",
		"username": "Custom-Name", "displayUsername": "  @Custom Name  ",
	})
	if status != http.StatusOK {
		t.Fatalf("custom sign-up status=%d body=%#v", status, valid)
	}
	user := usernameObject(t, valid, "user")
	if user["username"] != "customname" || user["displayUsername"] != "@Custom Name" {
		t.Fatalf("custom user=%#v", user)
	}
}

func TestUsernameSignInDoesNotLeakVerificationState(t *testing.T) {
	var mu sync.Mutex
	var messages []singleauth.EmailVerificationMessage
	emailOptions := singleauth.EmailVerificationOptions{
		SendOnSignIn: true,
		SendVerificationEmail: func(_ context.Context, message singleauth.EmailVerificationMessage) error {
			mu.Lock()
			messages = append(messages, message)
			mu.Unlock()
			return nil
		},
	}
	auth := newTestAuth(t, Options{}, emailOptions, true)
	status, _, signedUp := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Unverified", "email": "UPPER@example.com", "password": "password123",
		"username": "Unverified.User",
	})
	if status != http.StatusOK {
		t.Fatalf("unverified sign-up status=%d body=%#v", status, signedUp)
	}
	mu.Lock()
	messages = nil
	mu.Unlock()

	status, _, wrong := usernameExchange(t, auth, http.MethodPost, "/sign-in/username", "", map[string]any{
		"username": "Unverified.User", "password": "wrong-password", "callbackURL": "/after",
	})
	if status != http.StatusUnauthorized || wrong["code"] != CodeInvalidUsernameOrPassword {
		t.Fatalf("wrong password status=%d body=%#v", status, wrong)
	}
	mu.Lock()
	wrongMessages := len(messages)
	mu.Unlock()
	if wrongMessages != 0 {
		t.Fatalf("wrong password sent %d verification messages", wrongMessages)
	}

	callback := "/after?a=1&b=two+words"
	status, _, blocked := usernameExchange(t, auth, http.MethodPost, "/sign-in/username", "", map[string]any{
		"username": "Unverified.User", "password": "password123", "callbackURL": callback,
	})
	if status != http.StatusForbidden || blocked["code"] != CodeEmailNotVerified {
		t.Fatalf("unverified status=%d body=%#v", status, blocked)
	}
	mu.Lock()
	if len(messages) != 1 {
		mu.Unlock()
		t.Fatalf("verification messages=%d", len(messages))
	}
	message := messages[0]
	mu.Unlock()
	if !strings.Contains(message.URL, "&callbackURL=%2Fafter%3Fa%3D1%26b%3Dtwo%2Bwords") {
		t.Fatalf("verification URL=%q", message.URL)
	}
	claims, err := baCrypto.VerifyJWT(message.Token, integrationSecret)
	if err != nil || claims["email"] != "upper@example.com" {
		t.Fatalf("verification claims=%#v err=%v", claims, err)
	}
}

func newTestAuth(
	t *testing.T,
	pluginOptions Options,
	emailOptions singleauth.EmailVerificationOptions,
	requireVerification bool,
) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test/api/auth",
		Secret:  integrationSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true, RequireEmailVerification: requireVerification,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		EmailVerification: emailOptions,
		PluginFactories:   []singleauth.PluginFactory{NewFactory(pluginOptions)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func usernameExchange(
	t *testing.T,
	auth *singleauth.Auth,
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
	request := httptest.NewRequest(method, "http://auth.example.test/api/auth"+path, bytes.NewReader(encoded))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", "http://auth.example.test")
	}
	if cookieHeader != "" {
		request.Header.Set("Cookie", cookieHeader)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	headers := contract.Headers{}
	for name, values := range recorder.Header() {
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	if recorder.Body.Len() == 0 || bytes.Equal(bytes.TrimSpace(recorder.Body.Bytes()), []byte("null")) {
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

func usernameObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("%s in %#v is not an object", key, parent)
	}
	return value
}
