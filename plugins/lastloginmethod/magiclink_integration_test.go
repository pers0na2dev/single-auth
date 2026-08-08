package lastloginmethod

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/magiclink"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestMagicLinkSetsCookieAndDatabaseMethod(t *testing.T) {
	var sent magiclink.MagicLinkMessage
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  integrationSecret,
		PluginFactories: []singleauth.PluginFactory{
			NewFactory(Options{StoreInDatabase: true}),
			magiclink.NewFactory(magiclink.Options{SendMagicLink: func(
				_ context.Context,
				message magiclink.MagicLinkMessage,
				_ *engine.Context,
			) error {
				sent = message
				return nil
			}}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	send := httptest.NewRequest(
		http.MethodPost,
		"http://auth.example.test/api/auth/sign-in/magic-link",
		strings.NewReader(`{"email":"magic@example.com","name":"Magic User"}`),
	)
	send.Header.Set("Content-Type", "application/json")
	sendRecorder := httptest.NewRecorder()
	auth.ServeHTTP(sendRecorder, send)
	if sendRecorder.Code != http.StatusOK || sent.URL == "" {
		t.Fatalf("send status=%d body=%s message=%#v", sendRecorder.Code, sendRecorder.Body.String(), sent)
	}

	verifyRecorder := httptest.NewRecorder()
	auth.ServeHTTP(verifyRecorder, httptest.NewRequest(http.MethodGet, sent.URL, nil))
	if verifyRecorder.Code != http.StatusFound {
		t.Fatalf("verify status=%d body=%s", verifyRecorder.Code, verifyRecorder.Body.String())
	}
	response := contract.NewResponse(
		verifyRecorder.Code,
		headersFromHTTP(verifyRecorder.Header()),
		nil,
	)
	methodCookie, exists := responseCookie(response, DefaultCookieName)
	if !exists || methodCookie.Attributes.Value != "magic-link" {
		t.Fatalf("verify cookies = %#v", verifyRecorder.Header().Values("Set-Cookie"))
	}

	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "magic@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user["lastLoginMethod"] != "magic-link" {
		t.Fatalf("stored magic-link user = %#v", user)
	}
}
