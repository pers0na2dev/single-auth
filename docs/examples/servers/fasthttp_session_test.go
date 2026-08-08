package servers

import (
	"encoding/json"
	"net/http"
	"testing"

	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
)

func TestFastHTTPRequireSession(t *testing.T) {
	auth, advanceClock := newRefreshingDocumentationAuth(t)
	handler := protectedFastHTTPHandler(auth)

	var guestRequest fasthttpserver.Request
	guestRequest.Header.SetMethod(http.MethodGet)
	guestRequest.Header.SetHost("auth.example.com")
	guestRequest.SetRequestURI("/api/private/me")
	var guestContext fasthttpserver.RequestCtx
	guestContext.Init(&guestRequest, nil, nil)
	handler(&guestContext)
	if guestContext.Response.StatusCode() != http.StatusUnauthorized {
		t.Fatalf(
			"guest GET /api/private/me status = %d, want %d",
			guestContext.Response.StatusCode(),
			http.StatusUnauthorized,
		)
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

	var userRequest fasthttpserver.Request
	userRequest.Header.SetMethod(http.MethodGet)
	userRequest.Header.SetHost("auth.example.com")
	userRequest.Header.Set("Cookie", cookieHeader)
	userRequest.SetRequestURI("/api/private/me")
	var userContext fasthttpserver.RequestCtx
	userContext.Init(&userRequest, nil, nil)
	handler(&userContext)
	if userContext.Response.StatusCode() != http.StatusOK {
		t.Fatalf(
			"authenticated GET /api/private/me status = %d, want %d",
			userContext.Response.StatusCode(),
			http.StatusOK,
		)
	}
	if len(userContext.Response.Header.PeekAll("Set-Cookie")) == 0 {
		t.Fatal("authenticated response did not forward refreshed session cookies")
	}

	var body struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(userContext.Response.Body(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ID != created.User.ID || body.Email != created.User.Email {
		t.Fatalf("authenticated response = %#v, want user %#v", body, created.User)
	}

	var wrongMethodRequest fasthttpserver.Request
	wrongMethodRequest.Header.SetMethod(http.MethodPost)
	wrongMethodRequest.Header.SetHost("auth.example.com")
	wrongMethodRequest.Header.Set("Cookie", cookieHeader)
	wrongMethodRequest.SetRequestURI("/api/private/me")
	var wrongMethodContext fasthttpserver.RequestCtx
	wrongMethodContext.Init(&wrongMethodRequest, nil, nil)
	handler(&wrongMethodContext)
	if wrongMethodContext.Response.StatusCode() != http.StatusNotFound {
		t.Fatalf(
			"POST /api/private/me status = %d, want %d",
			wrongMethodContext.Response.StatusCode(),
			http.StatusNotFound,
		)
	}
}
