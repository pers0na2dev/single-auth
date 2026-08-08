package oauthproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

func TestCrossOriginPassthroughCreatesStateProfileUserAndSessionOnlyOnPreview(t *testing.T) {
	previewJar := make(map[string]string)
	preview := testAuth(t, previewBase, previewSecret, Options{
		ProductionURL: productionBase, Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	production := testAuth(t, productionBase, productionSecret, Options{
		Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)

	authorizationURL := startSocial(t, preview, previewBase, "google", previewJar)
	encryptedState := authorizationURL.Query().Get("state")
	if len(encryptedState) <= 50 {
		t.Fatalf("proxy state was not encrypted: %q", encryptedState)
	}
	if got := authorizationURL.Query().Get("redirect_uri"); got != productionBase+"/api/auth/callback/google" {
		t.Fatalf("redirect_uri=%q", got)
	}

	callback := exchange(t, production, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+url.QueryEscape(encryptedState), nil, nil)
	if callback.Status != http.StatusFound {
		t.Fatalf("production callback status=%d body=%s", callback.Status, callback.Body)
	}
	location := callback.Header.Get("Location")
	if !strings.Contains(location, previewBase+"/api/auth/oauth-proxy-callback") ||
		!strings.Contains(location, "profile=") {
		t.Fatalf("production redirect=%q", location)
	}
	if users := records(t, production, "user"); len(users) != 0 {
		t.Fatalf("production created users: %#v", users)
	}

	final := exchange(t, preview, http.MethodGet, location, nil, previewJar)
	if final.Status != http.StatusFound || final.Header.Get("Location") != "/dashboard" {
		t.Fatalf("preview callback status=%d location=%q body=%s", final.Status, final.Header.Get("Location"), final.Body)
	}
	users := records(t, preview, "user")
	accounts := records(t, preview, "account")
	sessions := records(t, preview, "session")
	if len(users) != 1 || users[0]["email"] != "user@email.com" ||
		len(accounts) != 1 || accounts[0]["providerId"] != "google" || len(sessions) != 1 {
		t.Fatalf("preview data users=%#v accounts=%#v sessions=%#v", users, accounts, sessions)
	}
	if previewJar["single-auth.session_token"] == "" {
		t.Fatalf("session cookie missing: %#v", previewJar)
	}
	if !strings.Contains(strings.Join(final.Header.Values("Set-Cookie"), "\n"),
		"single-auth.state=; Max-Age=0") {
		t.Fatalf("database state cookie was not expired: %#v", final.Header.Values("Set-Cookie"))
	}

	replay := exchange(t, preview, http.MethodGet, location, nil, previewJar)
	if replay.Status != http.StatusFound || !strings.Contains(replay.Header.Get("Location"), "error=state_mismatch") {
		t.Fatalf("replay status=%d location=%q", replay.Status, replay.Header.Get("Location"))
	}
}

func TestSameOriginSkipsProxyWithAndWithoutExplicitProductionURL(t *testing.T) {
	for _, pluginOptions := range []Options{{}, {ProductionURL: productionBase}} {
		auth := testAuth(t, productionBase, productionSecret, pluginOptions,
			singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
		jar := make(map[string]string)
		authorizationURL := startSocial(t, auth, productionBase, "google", jar)
		state := authorizationURL.Query().Get("state")
		if len(state) >= 50 {
			t.Fatalf("same-origin state unexpectedly wrapped: %q", state)
		}
		callback := exchange(t, auth, http.MethodGet,
			productionBase+"/api/auth/callback/google?code=test&state="+url.QueryEscape(state), nil, jar)
		if callback.Status != http.StatusFound || callback.Header.Get("Location") != "/dashboard" {
			t.Fatalf("same-origin callback=%d location=%q", callback.Status, callback.Header.Get("Location"))
		}
	}
}

func TestMissingStateCookieFallsBackToRegularCallback(t *testing.T) {
	auth := testAuth(t, productionBase, productionSecret,
		Options{ProductionURL: productionBase},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, nil)
	authorizationURL := startSocial(t, auth, productionBase, "google", nil)
	state := authorizationURL.Query().Get("state")
	callback := exchange(t, auth, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+url.QueryEscape(state), nil, nil)
	if !strings.Contains(callback.Header.Get("Location"), "state_mismatch") {
		t.Fatalf("missing state cookie redirect=%q", callback.Header.Get("Location"))
	}
}

func TestCookieStateStrategyWrapsAndRequiresPreviewCookie(t *testing.T) {
	previewJar := make(map[string]string)
	preview := testAuth(t, previewBase, previewSecret, Options{
		ProductionURL: productionBase, Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "cookie"}, nil)
	production := testAuth(t, productionBase, productionSecret, Options{
		Secret: sharedSecret,
	}, singleauth.AccountOptions{StoreStateStrategy: "cookie"}, nil)
	authorizationURL := startSocial(t, preview, previewBase, "google", previewJar)
	encryptedState := authorizationURL.Query().Get("state")
	plainPackage, err := baCrypto.Decrypt(sharedSecret, encryptedState)
	if err != nil {
		t.Fatal(err)
	}
	var statePackage oauthProxyStatePackage
	if json.Unmarshal(plainPackage, &statePackage) != nil || !statePackage.IsOAuthProxy ||
		statePackage.State == "" || statePackage.StateCookie == "" {
		t.Fatalf("state package=%s", plainPackage)
	}
	inner, err := baCrypto.Decrypt(sharedSecret, statePackage.StateCookie)
	if err != nil {
		t.Fatal(err)
	}
	stateData, err := parseStateData(inner)
	if err != nil || stateData.OAuthState != statePackage.State {
		t.Fatalf("inner state=%s parsed=%#v err=%v", inner, stateData, err)
	}

	callback := exchange(t, production, http.MethodGet,
		productionBase+"/api/auth/callback/google?code=test&state="+url.QueryEscape(encryptedState), nil, nil)
	location := callback.Header.Get("Location")
	withoutCookie := exchange(t, preview, http.MethodGet, location, nil, nil)
	if !strings.Contains(withoutCookie.Header.Get("Location"), "error=state_mismatch") || len(records(t, preview, "user")) != 0 {
		t.Fatalf("cookie-less callback location=%q", withoutCookie.Header.Get("Location"))
	}
	withCookie := exchange(t, preview, http.MethodGet, location, nil, previewJar)
	if withCookie.Header.Get("Location") != "/dashboard" || len(records(t, preview, "user")) != 1 {
		t.Fatalf("cookie callback location=%q users=%#v", withCookie.Header.Get("Location"), records(t, preview, "user"))
	}
}

func TestDedicatedSecretSeparatesProxyPayloadFromGlobalSecret(t *testing.T) {
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
	_, encryptedProfile := extractProfile(t, callback.Header.Get("Location"))
	plain, err := baCrypto.Decrypt(sharedSecret, encryptedProfile)
	if err != nil || !strings.Contains(string(plain), "user@email.com") {
		t.Fatalf("dedicated decrypt=%s err=%v", plain, err)
	}
	if _, err := baCrypto.Decrypt(productionSecret, encryptedProfile); err == nil {
		t.Fatal("global secret decrypted dedicated proxy payload")
	}
}

func TestProductionRewritePreservesProviderDedicatedRedirectURI(t *testing.T) {
	provider := testGoogleProvider(t, providers.Options{
		ClientID: "test", ClientSecret: "test",
		RedirectURI: "https://oauth.example.com/dedicated-callback",
	})
	preview := testAuth(t, previewBase, previewSecret,
		Options{ProductionURL: productionBase, Secret: sharedSecret},
		singleauth.AccountOptions{StoreStateStrategy: "database"}, provider)
	authorizationURL := startSocial(t, preview, previewBase, "google", nil)
	if got := authorizationURL.Query().Get("redirect_uri"); got != "https://oauth.example.com/dedicated-callback" {
		t.Fatalf("provider redirect URI was overwritten: %q", got)
	}
}
