package oauthproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

func TestPassthroughPayloadContainsNormalizedProfileAndAccountTokens(t *testing.T) {
	preview := testAuth(t, previewBase, previewSecret, Options{
		ProductionURL: productionBase, Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	production := testAuth(t, productionBase, productionSecret, Options{
		Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	authorizationURL := startSocial(t, preview, previewBase, "google", nil)
	callback := exchange(t, production, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+
			url.QueryEscape(authorizationURL.Query().Get("state")), nil, nil)
	callbackURL, encryptedProfile := extractProfile(t, callback.Header.Get("Location"))
	plain, err := baCrypto.Decrypt(sharedSecret, encryptedProfile)
	if err != nil {
		t.Fatal(err)
	}
	payload, valid := decodePassthroughPayload(plain)
	if !valid {
		t.Fatalf("payload invalid: %s", plain)
	}
	if callbackURL != "/dashboard" || payload.CallbackURL != "/dashboard" ||
		payload.UserInfo.Email != "user@email.com" || payload.UserInfo.ID != "1234567890" ||
		payload.Account.ProviderID != "google" || payload.Account.AccountID != "1234567890" ||
		payload.Account.AccessToken != "test-access" || payload.Account.RefreshToken != "test-refresh" ||
		payload.State == "" || payload.Timestamp == 0 {
		t.Fatalf("payload=%#v callbackURL=%q", payload, callbackURL)
	}
}

func TestDatabaseProxyCallbackDoesNotRequireStateCookieDuringCleanup(t *testing.T) {
	// A single instance models the shared-database deployment from the frozen
	// upstream regression: proxy callback deliberately receives no cookies.
	auth := testAuth(t, productionBase, productionSecret, Options{
		CurrentURL: previewBase, ProductionURL: productionBase,
	}, singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	authorizationURL := startSocial(t, auth, productionBase, "google", nil)
	callback := exchange(t, auth, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+
			url.QueryEscape(authorizationURL.Query().Get("state")), nil, nil)
	final := exchange(t, auth, http.MethodGet, callback.Header.Get("Location"), nil, nil)
	if final.Header.Get("Location") != "/dashboard" || len(records(t, auth, "user")) != 1 {
		t.Fatalf("cookie-less DB cleanup location=%q users=%#v", final.Header.Get("Location"), records(t, auth, "user"))
	}
}

func TestDatabaseModeAcceptsUUIDGeneratedVerificationIDs(t *testing.T) {
	var sequence atomic.Uint64
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: productionBase, Secret: productionSecret,
		Account:         singleauth.AccountOptions{StoreStateStrategy: "database"},
		SocialProviders: map[string]*providers.Provider{"google": testGoogleProvider(t)},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{CurrentURL: previewBase})},
		GenerateID: func(_ string, _ int) (string, bool, error) {
			return fmt.Sprintf("00000000-0000-4000-8000-%012d", sequence.Add(1)), true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL := startSocial(t, auth, productionBase, "google", nil)
	callback := exchange(t, auth, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+
			url.QueryEscape(authorizationURL.Query().Get("state")), nil, nil)
	_, profile := extractProfile(t, callback.Header.Get("Location"))
	if profile == "" {
		t.Fatalf("UUID database flow did not emit profile: %q", callback.Header.Get("Location"))
	}
}

func TestFormPostReadsCodeFromBodyAndPreservesAppleUser(t *testing.T) {
	for _, test := range []struct {
		name       string
		providerID string
		provider   *providers.Provider
		body       func(string) url.Values
		wantName   string
	}{
		{
			name: "code in form body", providerID: "google", provider: testGoogleProvider(t),
			body: func(state string) url.Values {
				return url.Values{"code": {"test"}, "state": {state}}
			},
			wantName: "First Last",
		},
		{
			name: "Apple user object", providerID: "apple", provider: testAppleProvider(t),
			body: func(state string) url.Values {
				return url.Values{
					"code": {"apple-test-code"}, "state": {state},
					"user": {`{"name":{"firstName":"Jane","lastName":"Doe"},"email":"jane@privaterelay.appleid.com"}`},
				}
			},
			wantName: "Jane Doe",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := testAuth(t, productionBase, productionSecret, Options{CurrentURL: previewBase},
				singleauth.AccountOptions{StoreStateStrategy: "cookie"}, test.provider)
			authorizationURL := startSocial(t, auth, productionBase, test.providerID, make(map[string]string))
			state := authorizationURL.Query().Get("state")
			callback := exchange(t, auth, http.MethodPost,
				productionBase+"/api/auth/callback/"+test.providerID,
				test.body(state).Encode(), nil)
			location := callback.Header.Get("Location")
			if callback.Status != http.StatusFound || !strings.Contains(location, "/oauth-proxy-callback") ||
				!strings.Contains(location, "profile=") || strings.Contains(location, "error=no_code") {
				t.Fatalf("form callback=%d location=%q body=%s", callback.Status, location, callback.Body)
			}
			_, encryptedProfile := extractProfile(t, location)
			plain, err := baCrypto.Decrypt(productionSecret, encryptedProfile)
			if err != nil {
				t.Fatal(err)
			}
			payload, valid := decodePassthroughPayload(plain)
			if !valid || payload.UserInfo.Name != test.wantName {
				t.Fatalf("form payload=%s parsed=%#v", plain, payload)
			}
		})
	}
}

func TestCurrentURLTrustAndVendorFallback(t *testing.T) {
	for _, test := range []struct {
		name           string
		requestOrigin  string
		trustedOrigins []string
		vendorName     string
		vendorValue    string
		wantReceiver   string
	}{
		{
			name:          "untrusted request origin falls back to base URL",
			requestOrigin: "https://untrusted.example", wantReceiver: "https://myapp.com",
		},
		{
			name:           "explicitly trusted request origin is used",
			requestOrigin:  "https://preview.myapp.com",
			trustedOrigins: []string{"https://preview.myapp.com"},
			wantReceiver:   "https://preview.myapp.com",
		},
		{
			name:          "bare vendor function name falls back to base URL",
			requestOrigin: "https://untrusted.example",
			vendorName:    "AWS_LAMBDA_FUNCTION_NAME", vendorValue: "my-lambda-function",
			wantReceiver: "https://myapp.com",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.vendorName != "" {
				old, existed := os.LookupEnv(test.vendorName)
				if err := os.Setenv(test.vendorName, test.vendorValue); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if existed {
						_ = os.Setenv(test.vendorName, old)
					} else {
						_ = os.Unsetenv(test.vendorName)
					}
				})
			}
			auth, err := singleauth.New(singleauth.Options{
				BaseURL: "https://myapp.com", Secret: productionSecret,
				TrustedOrigins:  test.trustedOrigins,
				Account:         singleauth.AccountOptions{StoreStateStrategy: "database"},
				SocialProviders: map[string]*providers.Provider{"google": testGoogleProvider(t)},
				PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
					ProductionURL: "https://login.myapp.com",
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			signIn := exchange(t, auth, http.MethodPost,
				test.requestOrigin+"/api/auth/sign-in/social",
				map[string]any{"provider": "google", "callbackURL": "/dashboard", "disableRedirect": true}, nil)
			var signInBody struct {
				URL string `json:"url"`
			}
			if json.Unmarshal(signIn.Body, &signInBody) != nil || signInBody.URL == "" {
				t.Fatalf("sign-in=%d %s", signIn.Status, signIn.Body)
			}
			state := mustParseURL(t, signInBody.URL).Query().Get("state")
			callback := exchange(t, auth, http.MethodGet,
				"https://login.myapp.com/api/auth/callback/google?code=test&state="+url.QueryEscape(state), nil, nil)
			if !strings.Contains(callback.Header.Get("Location"), test.wantReceiver+"/api/auth/oauth-proxy-callback") {
				t.Fatalf("receiver location=%q want origin=%q", callback.Header.Get("Location"), test.wantReceiver)
			}
			if strings.Contains(callback.Header.Get("Location"), "untrusted.example") &&
				test.wantReceiver != "https://untrusted.example" {
				t.Fatalf("untrusted origin leaked into receiver: %q", callback.Header.Get("Location"))
			}
		})
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
