package magiclink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/additionalfields"
	"github.com/pers0na2dev/single-auth/plugins/magiclink"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestRootFactoryMagicLinkCreatesSession(t *testing.T) {
	var sent magiclink.MagicLinkMessage
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  "0123456789abcdef0123456789abcdef",
		PluginFactories: []singleauth.PluginFactory{magiclink.NewFactory(magiclink.Options{
			SendMagicLink: func(_ context.Context, message magiclink.MagicLinkMessage, _ *engine.Context) error {
				sent = message
				return nil
			},
		})},
	})
	if err != nil {
		t.Fatal(err)
	}

	send := httptest.NewRequest(
		http.MethodPost,
		"http://auth.example.test/api/auth/sign-in/magic-link",
		bytes.NewBufferString(`{"email":"factory-magic@example.com","name":"Magic Factory"}`),
	)
	send.Header.Set("Content-Type", "application/json")
	sendRecorder := httptest.NewRecorder()
	auth.ServeHTTP(sendRecorder, send)
	if sendRecorder.Code != http.StatusOK {
		t.Fatalf("send status=%d body=%s", sendRecorder.Code, sendRecorder.Body.String())
	}
	if sent.Token == "" || !strings.HasPrefix(sent.URL, "http://auth.example.test/api/auth/magic-link/verify?") {
		t.Fatalf("magic-link message = %#v", sent)
	}

	verify := httptest.NewRequest(http.MethodGet, sent.URL, nil)
	verifyRecorder := httptest.NewRecorder()
	auth.ServeHTTP(verifyRecorder, verify)
	if verifyRecorder.Code != http.StatusFound {
		t.Fatalf("verify status=%d body=%s", verifyRecorder.Code, verifyRecorder.Body.String())
	}
	if !strings.Contains(strings.Join(verifyRecorder.Header().Values("Set-Cookie"), ";"), "single-auth.session_token=") {
		t.Fatalf("verify cookies = %#v", verifyRecorder.Header().Values("Set-Cookie"))
	}
}

func TestMagicLinkSerializesAdditionalUserFields(t *testing.T) {
	var sent magiclink.MagicLinkMessage
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://auth.example.test", Secret: "0123456789abcdef0123456789abcdef",
		PluginFactories: []singleauth.PluginFactory{
			additionalfields.NewFactory(additionalfields.Options{User: additionalfields.Fields{{
				Name: "foo", Attribute: storage.FieldAttribute{
					Type: storage.FieldString, Required: storage.Bool(false),
				},
			}}}),
			magiclink.NewFactory(magiclink.Options{SendMagicLink: func(
				_ context.Context, message magiclink.MagicLinkMessage, _ *engine.Context,
			) error {
				sent = message
				return nil
			}}),
		},
	})

	postJSON := func(path, cookie string, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(
			http.MethodPost, "http://auth.example.test/api/auth"+path, bytes.NewBufferString(body),
		)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://auth.example.test")
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		return recorder
	}
	verify := func() (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		request := httptest.NewRequest(
			http.MethodGet,
			"http://auth.example.test/api/auth/magic-link/verify?token="+url.QueryEscape(sent.Token),
			nil,
		)
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("verify response %q: %v", recorder.Body.String(), err)
		}
		return recorder, body
	}

	response := postJSON("/sign-in/magic-link", "", `{"email":"fields@example.com"}`)
	if response.Code != http.StatusOK || sent.Token == "" {
		t.Fatalf("send status=%d body=%s message=%#v", response.Code, response.Body.String(), sent)
	}
	first, firstBody := verify()
	if first.Code != http.StatusOK {
		t.Fatalf("first verify status=%d body=%s", first.Code, first.Body.String())
	}
	firstUser, _ := firstBody["user"].(map[string]any)
	if value, exists := firstUser["foo"]; !exists || value != nil {
		t.Fatalf("first user additional field = %#v", firstUser)
	}
	cookie := cookies.ApplySetCookies("", first.Header().Values("Set-Cookie"))
	updated := postJSON("/update-user", cookie, `{"foo":"bar"}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	cookie = cookies.ApplySetCookies(cookie, updated.Header().Values("Set-Cookie"))

	response = postJSON("/sign-in/magic-link", cookie, `{"email":"fields@example.com"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("second send status=%d body=%s", response.Code, response.Body.String())
	}
	second, secondBody := verify()
	if second.Code != http.StatusOK {
		t.Fatalf("second verify status=%d body=%s", second.Code, second.Body.String())
	}
	secondUser, _ := secondBody["user"].(map[string]any)
	if secondUser["foo"] != "bar" {
		t.Fatalf("second user additional field = %#v", secondUser)
	}
}
