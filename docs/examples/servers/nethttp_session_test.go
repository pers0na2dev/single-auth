package servers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
)

func TestNetHTTPRequireSession(t *testing.T) {
	auth, advanceClock := newRefreshingDocumentationAuth(t)
	handler := protectedNetHTTPHandler(auth)

	guestRequest := httptest.NewRequest(
		http.MethodGet,
		"https://auth.example.com/api/private/me",
		nil,
	)
	guestResponse := httptest.NewRecorder()
	handler.ServeHTTP(guestResponse, guestRequest)
	if guestResponse.Code != http.StatusUnauthorized {
		t.Fatalf("guest GET /api/private/me status = %d, want %d", guestResponse.Code, http.StatusUnauthorized)
	}

	created, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name:     "Application Owner",
		Email:    "owner@example.com",
		Password: "correct-horse-battery-staple",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", created.Headers.Values("Set-Cookie"))
	advanceClock()

	userRequest := httptest.NewRequest(
		http.MethodGet,
		"https://auth.example.com/api/private/me",
		nil,
	)
	userRequest.Header.Set("Cookie", cookieHeader)
	userResponse := httptest.NewRecorder()
	handler.ServeHTTP(userResponse, userRequest)
	if userResponse.Code != http.StatusOK {
		t.Fatalf("authenticated GET /api/private/me status = %d, want %d", userResponse.Code, http.StatusOK)
	}
	if len(userResponse.Header().Values("Set-Cookie")) == 0 {
		t.Fatal("authenticated response did not forward refreshed session cookies")
	}

	var body struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResponse.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ID != created.User.ID || body.Email != created.User.Email {
		t.Fatalf("authenticated response = %#v, want user %#v", body, created.User)
	}
}
