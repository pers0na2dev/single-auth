package admin

import (
	"crypto/sha1" // #nosec G505 -- the HIBP range protocol requires SHA-1.
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/haveibeenpwned"
)

func TestAdminPasswordEndpointsInteroperateWithHaveIBeenPwned(t *testing.T) {
	const compromised = "admin-compromised-password"
	stub := newAdminRangeStub(compromised)
	auth := newRootAuthConfigured(t, Options{}, func(options *singleauth.Options) {
		options.HTTPClient = stub.client()
	}, haveibeenpwned.NewFactory(haveibeenpwned.Options{}))
	admin := signUpIdentity(t, auth, "Admin", "admin-hibp@example.com", "safe-password")

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"email": "compromised-create@example.com", "password": compromised, "name": "Compromised Create",
	})
	assertError(t, status, body, http.StatusBadRequest, haveibeenpwned.ErrorPasswordCompromised)
	if body["message"] != haveibeenpwned.DefaultCompromisedMessage {
		t.Fatalf("create compromised message=%#v", body)
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"email": "passwordless-hibp@example.com", "name": "Passwordless HIBP",
	})
	if status != http.StatusOK {
		t.Fatalf("passwordless create status=%d body=%#v", status, body)
	}
	userID, _ := objectField(t, body, "user")["id"].(string)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-user-password", admin.Cookie, map[string]any{
		"userId": userID, "newPassword": compromised,
	})
	assertError(t, status, body, http.StatusBadRequest, haveibeenpwned.ErrorPasswordCompromised)
	if body["message"] != haveibeenpwned.DefaultCompromisedMessage {
		t.Fatalf("set compromised message=%#v", body)
	}

	stub.mu.Lock()
	calls := stub.calls
	stub.mu.Unlock()
	if calls != 3 { // admin sign-up plus the two admin password endpoints
		t.Fatalf("HIBP range calls=%d, want 3", calls)
	}
}

type adminRangeStub struct {
	mu     sync.Mutex
	prefix string
	suffix string
	calls  int
}

func newAdminRangeStub(password string) *adminRangeStub {
	digest := sha1.Sum([]byte(password)) // #nosec G401 -- HIBP protocol hash.
	hash := strings.ToUpper(hex.EncodeToString(digest[:]))
	return &adminRangeStub{prefix: hash[:5], suffix: hash[5:]}
}

func (stub *adminRangeStub) client() *http.Client {
	return &http.Client{Transport: adminRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		stub.mu.Lock()
		stub.calls++
		stub.mu.Unlock()
		body := ""
		if strings.TrimPrefix(request.URL.Path, "/range/") == stub.prefix {
			body = stub.suffix + ":42\n"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})}
}

type adminRoundTripFunc func(*http.Request) (*http.Response, error)

func (function adminRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
