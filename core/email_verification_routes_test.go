package core

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/model"
)

func TestEmailVerificationAndAutoSignIn(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	var messages []EmailVerificationMessage
	var messageMu sync.Mutex
	beforeCalls, afterCalls := 0, 0
	auth := MustNew(Options{
		Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{
			Enabled:                  true,
			RequireEmailVerification: true,
		},
		EmailVerification: EmailVerificationOptions{
			AutoSignInAfterVerification: true,
			SendVerificationEmail: func(_ context.Context, message EmailVerificationMessage) error {
				messageMu.Lock()
				messages = append(messages, message)
				messageMu.Unlock()
				return nil
			},
			BeforeEmailVerification: func(context.Context, model.User) error {
				beforeCalls++
				return nil
			},
			AfterEmailVerification: func(context.Context, model.User) error {
				afterCalls++
				return nil
			},
		},
		Clock: func() time.Time { return now },
	})

	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Verify User", "email": "verify@example.com", "password": "password123",
	})
	if status != http.StatusOK || value.(map[string]any)["token"] != nil {
		t.Fatalf("verification sign-up status=%d value=%#v", status, value)
	}
	messageMu.Lock()
	if len(messages) != 1 {
		messageMu.Unlock()
		t.Fatalf("verification messages = %d", len(messages))
	}
	initial := messages[0]
	messageMu.Unlock()

	started := time.Now()
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/send-verification-email", "", map[string]any{
		"email": "verify@example.com", "callbackURL": "/verified",
	})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("send verification status=%d value=%#v", status, value)
	}
	if time.Since(started) < 450*time.Millisecond {
		t.Fatalf("unauthenticated anti-enumeration floor was too short: %v", time.Since(started))
	}
	messageMu.Lock()
	if len(messages) != 2 {
		messageMu.Unlock()
		t.Fatalf("verification messages after send = %d", len(messages))
	}
	messageMu.Unlock()

	status, headers, value := sessionTestRequest(t, auth, http.MethodGet, "/verify-email?token="+url.QueryEscape(initial.Token), "", nil)
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("verify email status=%d value=%#v", status, value)
	}
	if beforeCalls != 1 || afterCalls != 1 {
		t.Fatalf("verification callbacks before=%d after=%d", beforeCalls, afterCalls)
	}
	cookieHeader := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || value == nil {
		t.Fatalf("auto sign-in session status=%d value=%#v", status, value)
	}
	user := objectValue(t, value.(map[string]any), "user")
	if user["emailVerified"] != true {
		t.Fatalf("verified user = %#v", user)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/send-verification-email", cookieHeader, map[string]any{
		"email": "verify@example.com",
	})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorEmailAlreadyVerified) {
		t.Fatalf("verified resend status=%d value=%#v", status, value)
	}
}

func TestVerifyEmailInvalidTokenRedirect(t *testing.T) {
	auth := MustNew(Options{Secret: "0123456789abcdef0123456789abcdef"})
	callback := "http://auth.test/result?from=email"
	status, headers, _ := sessionTestRequest(
		t,
		auth,
		http.MethodGet,
		"/verify-email?token=invalid&callbackURL="+url.QueryEscape(callback),
		"",
		nil,
	)
	if status != http.StatusFound {
		t.Fatalf("invalid token redirect status=%d", status)
	}
	location := headers.Get("Location")
	if location != callback+"&error="+string(ErrorInvalidToken) {
		t.Fatalf("invalid token location=%q", location)
	}
}
