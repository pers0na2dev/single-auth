package genericoauth

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
)

func TestRFC9207IssuerValidation(t *testing.T) {
	tests := []struct {
		name             string
		explicitIssuer   string
		discoveryIssuer  string
		requireIssuer    bool
		callbackIssuer   *string
		withoutDiscovery bool
		wantError        string
	}{
		{name: "matching configured issuer", explicitIssuer: "https://issuer.example", callbackIssuer: stringRef("https://issuer.example")},
		{name: "mismatching configured issuer", explicitIssuer: "https://issuer.example", callbackIssuer: stringRef("https://evil.example"), wantError: "issuer_mismatch"},
		{name: "issuer from discovery", discoveryIssuer: "https://discovered.example", callbackIssuer: stringRef("https://discovered.example")},
		{name: "not configured", callbackIssuer: stringRef("https://ignored.example"), withoutDiscovery: true},
		{name: "required issuer missing", explicitIssuer: "https://issuer.example", requireIssuer: true, wantError: "issuer_missing"},
		{name: "optional issuer missing", explicitIssuer: "https://issuer.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newGenericOAuthServer(t, Profile{
				"sub":   "issuer-" + strings.ReplaceAll(test.name, " ", "-"),
				"email": strings.ReplaceAll(test.name, " ", "-") + "@test.com", "name": "Issuer User",
			})
			server.mu.Lock()
			server.discovery.Issuer = test.discoveryIssuer
			server.mu.Unlock()
			config := server.config("issuer")
			config.Issuer = test.explicitIssuer
			config.RequireIssuerValidation = test.requireIssuer
			if test.withoutDiscovery {
				config.DiscoveryURL = ""
				config.AuthorizationURL = server.server.URL + "/authorize"
				config.TokenURL = server.server.URL + "/token"
				config.UserInfoURL = server.server.URL + "/userinfo"
			}
			auth := genericTestAuth(t, config, nil)
			flow := startGenericFlow(t, auth, "issuer", genericBaseURL+"/done", "", genericBaseURL+"/error", nil)
			extra := url.Values{}
			if test.callbackIssuer != nil {
				extra.Set("iss", *test.callbackIssuer)
			}
			callback := finishGenericFlow(t, auth, "issuer", flow, extra)
			location, _ := url.Parse(callback.Header.Get("Location"))
			if test.wantError != "" {
				if location.Path != "/error" || location.Query().Get("error") != test.wantError {
					t.Fatalf("issuer rejection location=%q", callback.Header.Get("Location"))
				}
				return
			}
			if callback.Header.Get("Location") != genericBaseURL+"/done" {
				t.Fatalf("issuer success location=%q", callback.Header.Get("Location"))
			}
		})
	}
}

func TestCookieBackedOAuthStateSuccessMismatchAndMissingState(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "cookie-state", "email": "cookie-state@test.com", "name": "Cookie State",
	})
	config := server.config("cookie-state")
	auth := genericTestAuth(t, config, func(options *singleauth.Options) {
		options.Account.StoreStateStrategy = "cookie"
	})
	flow := startGenericFlow(t, auth, "cookie-state", genericBaseURL+"/done", genericBaseURL+"/new", "", nil)
	callback := finishGenericFlow(t, auth, "cookie-state", flow, nil)
	if callback.Header.Get("Location") != genericBaseURL+"/new" || len(genericRecords(t, auth, "user")) != 1 {
		t.Fatalf("cookie state callback=%q users=%#v", callback.Header.Get("Location"), genericRecords(t, auth, "user"))
	}

	mismatchAuth := genericTestAuth(t, config, func(options *singleauth.Options) {
		options.Account.StoreStateStrategy = "cookie"
	})
	mismatch := startGenericFlow(t, mismatchAuth, "cookie-state", genericBaseURL+"/done", "", "", nil)
	mismatch.State = "attacker-controlled-state"
	mismatchCallback := finishGenericFlow(t, mismatchAuth, "cookie-state", mismatch, nil)
	mismatchURL, _ := url.Parse(mismatchCallback.Header.Get("Location"))
	if mismatchCallback.Status != http.StatusFound || mismatchURL.Query().Get("error") != "state_mismatch" ||
		len(genericRecords(t, mismatchAuth, "user")) != 0 {
		t.Fatalf("cookie mismatch location=%q users=%#v", mismatchCallback.Header.Get("Location"), genericRecords(t, mismatchAuth, "user"))
	}

	missing := genericExchange(
		t, mismatchAuth, http.MethodGet, "/oauth2/callback/cookie-state?code=dummy", nil, nil,
	)
	missingURL, _ := url.Parse(missing.Header.Get("Location"))
	if missing.Status != http.StatusFound || missingURL.Query().Get("error") != "state_not_found" ||
		strings.Contains(missing.Header.Get("Location"), "please_restart_the_process") {
		t.Fatalf("missing-state location=%q", missing.Header.Get("Location"))
	}
}

func TestHashedDatabaseOAuthStateCompletesAndIsSingleUseUnderConcurrency(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "hashed-state", "email": "hashed-state@test.com", "name": "Hashed State",
	})
	auth := genericTestAuth(t, server.config("hashed-state"), func(options *singleauth.Options) {
		options.Verification.StoreIdentifier = singleauth.VerificationIdentifierStorage{
			Strategy: singleauth.VerificationIdentifierHashed,
		}
	})
	flow := startGenericFlow(t, auth, "hashed-state", genericBaseURL+"/done", "", "", nil)
	verifications := genericRecords(t, auth, "verification")
	if len(verifications) != 1 || verifications[0]["identifier"] == flow.State {
		t.Fatalf("OAuth state was not hashed at rest: %#v", verifications)
	}

	const racers = 24
	var successes atomic.Int32
	var mismatches atomic.Int32
	var wait sync.WaitGroup
	wait.Add(racers)
	for range racers {
		go func() {
			defer wait.Done()
			jar := cloneCookieJar(flow.Jar)
			response := genericExchange(t, auth, http.MethodGet,
				"/oauth2/callback/hashed-state?code=valid-code&state="+url.QueryEscape(flow.State), nil, jar)
			location := response.Header.Get("Location")
			if location == genericBaseURL+"/done" {
				successes.Add(1)
			} else if parsed, err := url.Parse(location); err == nil && parsed.Query().Get("error") == "state_mismatch" {
				mismatches.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || mismatches.Load() != racers-1 || len(genericRecords(t, auth, "user")) != 1 {
		t.Fatalf("successes=%d mismatches=%d users=%#v", successes.Load(), mismatches.Load(), genericRecords(t, auth, "user"))
	}
}

func TestAdditionalDataCannotOverrideOAuthSecurityState(t *testing.T) {
	server := newGenericOAuthServer(t, Profile{
		"sub": "reserved-state", "email": "reserved@test.com", "name": "Reserved",
	})
	auth := genericTestAuth(t, server.config("reserved"), nil)
	flow := startGenericFlow(t, auth, "reserved", genericBaseURL+"/safe", "", "", map[string]any{
		"additionalData": map[string]any{
			"callbackURL": "https://evil.example/callback", "oauthState": "attacker-state",
			"expiresAt": 1, "link": map[string]any{"userId": "victim", "email": "victim@test.com"},
			"tenant": "kept",
		},
	})
	callback := finishGenericFlow(t, auth, "reserved", flow, nil)
	if callback.Header.Get("Location") != genericBaseURL+"/safe" || len(genericRecords(t, auth, "account")) != 1 {
		t.Fatalf("reserved state override callback=%q accounts=%#v", callback.Header.Get("Location"), genericRecords(t, auth, "account"))
	}
}

func cloneCookieJar(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func stringRef(value string) *string { return &value }
