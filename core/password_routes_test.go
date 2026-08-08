package core

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/security/cookies"
)

func TestPasswordResetSingleUseAndVerification(t *testing.T) {
	var messages []PasswordResetMessage
	var messageMu sync.Mutex
	auth := MustNew(Options{
		Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{
			Enabled:               true,
			RevokeSessionsOnReset: true,
			SendResetPassword: func(_ context.Context, message PasswordResetMessage) error {
				messageMu.Lock()
				messages = append(messages, message)
				messageMu.Unlock()
				return nil
			},
		},
	})
	cookieHeader, _, _ := createSessionTestUser(t, auth, "reset@example.com")

	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/request-password-reset", "", map[string]any{
		"email": "missing@example.com", "redirectTo": "http://auth.test/reset-ui",
	})
	if status != http.StatusOK || value.(map[string]any)["message"] != genericPasswordResetMessage {
		t.Fatalf("unknown reset request status=%d value=%#v", status, value)
	}
	messageMu.Lock()
	if len(messages) != 0 {
		messageMu.Unlock()
		t.Fatal("unknown email invoked reset hook")
	}
	messageMu.Unlock()

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/request-password-reset", "", map[string]any{
		"email": "reset@example.com", "redirectTo": "http://auth.test/reset-ui",
	})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("reset request status=%d value=%#v", status, value)
	}
	messageMu.Lock()
	if len(messages) != 1 {
		messageMu.Unlock()
		t.Fatalf("reset messages = %d", len(messages))
	}
	message := messages[0]
	messageMu.Unlock()
	if message.Token == "" || !strings.Contains(message.URL, "/reset-password/"+message.Token) {
		t.Fatalf("reset message = %#v", message)
	}

	callbackPath := "/reset-password/" + message.Token + "?callbackURL=" + url.QueryEscape("http://auth.test/reset-ui")
	status, headers, _ := sessionTestRequest(t, auth, http.MethodGet, callbackPath, "", nil)
	if status != http.StatusFound {
		t.Fatalf("reset callback status=%d", status)
	}
	location, err := url.Parse(headers.Get("Location"))
	if err != nil || location.Query().Get("token") != message.Token {
		t.Fatalf("reset callback location=%q err=%v", headers.Get("Location"), err)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/reset-password", "", map[string]any{
		"token": message.Token, "newPassword": "replacement-password",
	})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("reset password status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/reset-password", "", map[string]any{
		"token": message.Token, "newPassword": "another-password",
	})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorInvalidToken) {
		t.Fatalf("replayed reset status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || value != nil {
		t.Fatalf("password reset did not revoke session: status=%d value=%#v", status, value)
	}

	newCookies, _, _ := signInSessionTestUserWithPassword(t, auth, "reset@example.com", "replacement-password")
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/verify-password", newCookies, map[string]any{
		"password": "replacement-password",
	})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("verify password status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/verify-password", newCookies, map[string]any{
		"password": "wrong-password",
	})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorInvalidPassword) {
		t.Fatalf("invalid verify status=%d value=%#v", status, value)
	}
}

func TestPasswordResetDisabled(t *testing.T) {
	auth := MustNew(Options{Secret: "0123456789abcdef0123456789abcdef"})
	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/request-password-reset", "", map[string]any{
		"email": "user@example.com",
	})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != "RESET_PASSWORD_DISABLED" {
		t.Fatalf("disabled reset status=%d value=%#v", status, value)
	}
}

func signInSessionTestUserWithPassword(
	t *testing.T,
	auth *Auth,
	email, password string,
) (string, string, map[string]any) {
	t.Helper()
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": email, "password": password,
	})
	if status != http.StatusOK {
		t.Fatalf("sign in status=%d value=%#v", status, value)
	}
	result := value.(map[string]any)
	return cookies.ApplySetCookies("", headers.Values("Set-Cookie")), objectString(t, result, "token"), result
}
