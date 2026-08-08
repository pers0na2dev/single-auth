package oauthproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

func TestDatabaseStateIsConsumedExactlyOnceUnderConcurrentReplay(t *testing.T) {
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
	location := callback.Header.Get("Location")

	const attempts = 24
	var successes atomic.Int32
	var mismatches atomic.Int32
	var wait sync.WaitGroup
	wait.Add(attempts)
	for range attempts {
		go func() {
			defer wait.Done()
			response := exchange(t, preview, http.MethodGet, location, nil, nil)
			switch redirectTo := response.Header.Get("Location"); {
			case redirectTo == "/dashboard":
				successes.Add(1)
			case strings.Contains(redirectTo, "error=state_mismatch"):
				mismatches.Add(1)
			default:
				t.Errorf("unexpected replay redirect=%q", redirectTo)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || mismatches.Load() != attempts-1 {
		t.Fatalf("successes=%d mismatches=%d", successes.Load(), mismatches.Load())
	}
	if len(records(t, preview, "user")) != 1 || len(records(t, preview, "session")) != 1 {
		t.Fatalf("concurrent replay duplicated identity/session")
	}
}

func TestOAuthStatePackageIsBoundToInnerState(t *testing.T) {
	preview := testAuth(t, previewBase, previewSecret, Options{
		ProductionURL: productionBase, Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	production := testAuth(t, productionBase, productionSecret, Options{
		Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	authorizationURL := startSocial(t, preview, previewBase, "google", nil)
	plain, err := baCrypto.Decrypt(sharedSecret, authorizationURL.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	var statePackage oauthProxyStatePackage
	if json.Unmarshal(plain, &statePackage) != nil {
		t.Fatalf("state package=%s", plain)
	}
	statePackage.State = "substituted-state"
	encoded, _ := json.Marshal(statePackage)
	tampered, err := baCrypto.Encrypt(sharedSecret, encoded)
	if err != nil {
		t.Fatal(err)
	}
	callback := exchange(t, production, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+url.QueryEscape(tampered), nil, nil)
	if !strings.Contains(callback.Header.Get("Location"), "error=state_mismatch") {
		t.Fatalf("state-binding redirect=%q", callback.Header.Get("Location"))
	}
	legitimate := exchange(t, production, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+
			url.QueryEscape(authorizationURL.Query().Get("state")), nil, nil)
	if !strings.Contains(legitimate.Header.Get("Location"), "profile=") {
		t.Fatalf("binding mismatch consumed legitimate state: %q", legitimate.Header.Get("Location"))
	}
}
