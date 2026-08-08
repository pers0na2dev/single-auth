package phonenumber

import (
	"crypto/sha1" // #nosec G505 -- the HIBP range protocol requires SHA-1.
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/haveibeenpwned"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHaveIBeenPwnedRejectsCompromisedPhonePasswordReset(t *testing.T) {
	store := newCaptureStore()
	phoneOptions := standardOptions(store)
	breached := "breached-via-phone-otp"
	digest := sha1.Sum([]byte(breached)) // #nosec G401 -- HIBP protocol hash.
	hash := strings.ToUpper(hex.EncodeToString(digest[:]))
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Add-Padding") != "true" || request.Header.Get("User-Agent") != "Reference Password Checker" {
			t.Fatalf("HIBP headers = %#v", request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(hash[5:] + ":42\n")),
		}, nil
	})}
	auth, _ := newRootHarness(t, phoneOptions, func(root *singleauth.Options) {
		root.PluginFactories = []singleauth.PluginFactory{
			haveibeenpwned.NewFactory(haveibeenpwned.Options{HTTPClient: client}),
			NewFactory(phoneOptions),
		}
	})
	phone := "+15551234567"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone), "disableSession": true,
	})
	if verified.status != http.StatusOK {
		t.Fatalf("verify status=%d body=%#v", verified.status, verified.body)
	}
	exchange(t, auth, http.MethodPost, "/phone-number/request-password-reset", "", map[string]any{"phoneNumber": phone})
	result := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
		"phoneNumber": phone, "otp": store.resetCode(phone), "newPassword": breached,
	})
	if result.status != http.StatusBadRequest || errorCode(result) != haveibeenpwned.ErrorPasswordCompromised {
		t.Fatalf("status=%d body=%#v", result.status, result.body)
	}
}
