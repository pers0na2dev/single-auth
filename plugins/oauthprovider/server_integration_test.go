package oauthprovider

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
)

type serverIntegrationHarness struct {
	t       *testing.T
	auth    *singleauth.Auth
	factory *Factory
	now     time.Time
	cookie  string
	userID  string
}

func newServerIntegrationHarness(t *testing.T, mutate func(*Options)) *serverIntegrationHarness {
	return newServerIntegrationHarnessWithFactories(t, mutate)
}

func newServerIntegrationHarnessWithFactories(
	t *testing.T,
	mutate func(*Options),
	precedingFactories ...singleauth.PluginFactory,
) *serverIntegrationHarness {
	t.Helper()
	now := time.Date(2028, time.March, 4, 5, 6, 7, 0, time.UTC)
	options := Options{
		LoginPage: "/login", ConsentPage: "/consent",
		DisableJWTPlugin: true, AllowDynamicClientRegistration: true,
		Scopes: []string{"openid", "profile", "email", "offline_access", "read:data", "write:data"},
	}
	if mutate != nil {
		mutate(&options)
	}
	factory := NewFactory(options)
	factories := append([]singleauth.PluginFactory(nil), precedingFactories...)
	factories = append(factories, factory)
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
		Clock: func() time.Time { return now },
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
				Verify: func(hash, value string) bool { return hash == "hashed:"+value },
			},
		},
		PluginFactories: factories,
	})
	if err != nil {
		t.Fatal(err)
	}
	signedUp, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "OAuth User", Email: "oauth-server@test.invalid", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &serverIntegrationHarness{
		t: t, auth: auth, factory: factory, now: now,
		cookie: cookies.ApplySetCookies("", signedUp.Headers.Values("Set-Cookie")),
		userID: signedUp.User.ID,
	}
}

func (h *serverIntegrationHarness) headers() contract.Headers {
	return contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: h.cookie})
}

func (h *serverIntegrationHarness) call(name, method string, headers contract.Headers, body any, query url.Values) (singleauth.DirectCallResult, error) {
	h.t.Helper()
	return h.auth.API().Call(h.t.Context(), name, singleauth.DirectCallInput{
		Method: method, Scheme: "http", Host: "localhost:3000", Headers: headers,
		Body: body, Query: query,
	})
}

func (h *serverIntegrationHarness) createClient(body map[string]any) map[string]any {
	h.t.Helper()
	result, err := h.call("createOAuthClient", http.MethodPost, h.headers(), body, nil)
	if err != nil {
		h.t.Fatalf("create client: %v body=%s", err, result.Response.Body())
	}
	if result.Response.Status() != http.StatusCreated {
		h.t.Fatalf("create client status=%d body=%s", result.Response.Status(), result.Response.Body())
	}
	object, ok := result.Value.(map[string]any)
	if !ok {
		h.t.Fatalf("create client value=%#v", result.Value)
	}
	return object
}

func (h *serverIntegrationHarness) authorizeAndConsent(clientID, redirectURI, verifier string) string {
	h.t.Helper()
	query := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid profile email offline_access read:data"}, "state": {"state-123"},
		"code_challenge": {serverPKCEChallenge(verifier)}, "code_challenge_method": {"S256"},
		"nonce": {"nonce-123"},
	}
	authorized, err := h.call("oauth2Authorize", http.MethodGet, h.headers(), nil, query)
	if err != nil {
		if apiErr, ok := contract.AsAPIError(err); ok {
			h.t.Fatalf("authorize: %v cause=%v body=%s", err, apiErr.Cause, authorized.Response.Body())
		}
		h.t.Fatalf("authorize: %v body=%s", err, authorized.Response.Body())
	}
	if authorized.Response.Status() != http.StatusFound {
		h.t.Fatalf("authorize status=%d body=%s", authorized.Response.Status(), authorized.Response.Body())
	}
	location, _ := authorized.Response.Headers().Get("Location")
	consentURL, err := url.Parse(location)
	if err != nil || consentURL.Path != "/consent" || consentURL.Query().Get("oauth_query") == "" {
		h.t.Fatalf("consent location=%q err=%v", location, err)
	}
	consented, err := h.call("oauth2Consent", http.MethodPost, h.headers(), map[string]any{
		"accept": true, "oauth_query": consentURL.Query().Get("oauth_query"),
	}, nil)
	if err != nil {
		if apiErr, ok := contract.AsAPIError(err); ok {
			h.t.Fatalf("consent: %v cause=%v body=%s", err, apiErr.Cause, consented.Response.Body())
		}
		h.t.Fatalf("consent: %v body=%s", err, consented.Response.Body())
	}
	object := consented.Value.(map[string]any)
	callback, err := url.Parse(object["redirect_uri"].(string))
	if err != nil || callback.Query().Get("state") != "state-123" || callback.Query().Get("iss") == "" {
		h.t.Fatalf("callback=%#v err=%v", object, err)
	}
	code := callback.Query().Get("code")
	if code == "" {
		h.t.Fatal("authorization callback omitted code")
	}
	return code
}

func TestOAuthAuthorizationServerEndToEnd(t *testing.T) {
	h := newServerIntegrationHarness(t, nil)
	redirectURI := "http://127.0.0.1:4321/callback"
	client := h.createClient(map[string]any{
		"client_name": "integration client", "redirect_uris": []string{redirectURI},
		"scope":          "openid profile email offline_access read:data write:data",
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_basic",
		"type": "web",
	})
	clientID, clientSecret := client["client_id"].(string), client["client_secret"].(string)
	verifier := strings.Repeat("v", 64)
	code := h.authorizeAndConsent(clientID, redirectURI, verifier)

	tokenResult, err := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID, "client_secret": clientSecret,
		"code": code, "redirect_uri": redirectURI, "code_verifier": verifier,
	}, nil)
	if err != nil {
		t.Fatalf("token: %v body=%s", err, tokenResult.Response.Body())
	}
	tokens := tokenResult.Value.(map[string]any)
	accessToken, _ := tokens["access_token"].(string)
	refreshToken, _ := tokens["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" || tokens["id_token"] == "" || tokens["token_type"] != "Bearer" ||
		tokens["scope"] != "openid profile email offline_access read:data" {
		t.Fatalf("tokens=%#v", tokens)
	}
	if cache, _ := tokenResult.Response.Headers().Get("Cache-Control"); cache != "no-store" {
		t.Fatalf("token cache-control=%q", cache)
	}

	info, err := h.call("oauth2UserInfo", http.MethodGet, contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + accessToken},
	), nil, nil)
	if err != nil {
		t.Fatalf("userinfo: %v body=%s", err, info.Response.Body())
	}
	profile := info.Value.(map[string]any)
	if profile["sub"] != h.userID || profile["email"] != "oauth-server@test.invalid" || profile["name"] != "OAuth User" {
		t.Fatalf("userinfo=%#v", profile)
	}

	introspected, err := h.call("oauth2Introspect", http.MethodPost, contract.Headers{}, map[string]any{
		"client_id": clientID, "client_secret": clientSecret,
		"token": accessToken, "token_type_hint": "access_token",
	}, nil)
	if err != nil || introspected.Value.(map[string]any)["active"] != true {
		t.Fatalf("introspect err=%v value=%#v", err, introspected.Value)
	}

	refreshed, err := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "refresh_token", "client_id": clientID, "client_secret": clientSecret,
		"refresh_token": refreshToken, "scope": "openid email read:data",
	}, nil)
	if err != nil {
		t.Fatalf("refresh: %v body=%s", err, refreshed.Response.Body())
	}
	rotated := refreshed.Value.(map[string]any)
	if rotated["refresh_token"] == "" || rotated["access_token"] == accessToken || rotated["scope"] != "openid email read:data" {
		t.Fatalf("rotated=%#v", rotated)
	}

	replay, replayErr := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "refresh_token", "client_id": clientID, "client_secret": clientSecret,
		"refresh_token": refreshToken,
	}, nil)
	if replayErr == nil || replay.Response.Status() != http.StatusBadRequest || !strings.Contains(string(replay.Response.Body()), "invalid_grant") {
		t.Fatalf("refresh replay status=%d err=%v body=%s", replay.Response.Status(), replayErr, replay.Response.Body())
	}
}

func TestOAuthAuthorizationCodeIsSingleUseUnderConcurrency(t *testing.T) {
	h := newServerIntegrationHarness(t, nil)
	redirectURI := "https://client.example/callback"
	client := h.createClient(map[string]any{
		"client_name": "concurrent client", "redirect_uris": []string{redirectURI},
		"scope": "openid", "grant_types": []string{"authorization_code"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_basic", "type": "web",
		"skip_consent": true,
	})
	verifier := strings.Repeat("p", 64)
	query := url.Values{
		"client_id": {client["client_id"].(string)}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid"}, "code_challenge": {serverPKCEChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	authorized, err := h.call("oauth2Authorize", http.MethodGet, h.headers(), nil, query)
	if err != nil {
		t.Fatal(err)
	}
	location, _ := authorized.Response.Headers().Get("Location")
	callback, _ := url.Parse(location)
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize location=%q", location)
	}

	const racers = 12
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(racers)
	statuses := make(chan int, racers)
	for range racers {
		go func() {
			defer wait.Done()
			<-start
			result, _ := h.auth.API().Call(t.Context(), "oauth2Token", singleauth.DirectCallInput{
				Method: http.MethodPost, Scheme: "https", Host: "auth.example",
				Body: map[string]any{
					"grant_type": "authorization_code", "client_id": client["client_id"], "client_secret": client["client_secret"],
					"code": code, "redirect_uri": redirectURI, "code_verifier": verifier,
				},
			})
			statuses <- result.Response.Status()
		}()
	}
	close(start)
	wait.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful redemptions=%d want=1", successes)
	}
}

func TestOAuthClientLifecycleEnforcesOwnershipAndSecretRotation(t *testing.T) {
	h := newServerIntegrationHarness(t, nil)
	client := h.createClient(map[string]any{
		"client_name": "owned", "redirect_uris": []string{"https://owned.example/callback"},
		"scope": "openid", "grant_types": []string{"authorization_code"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "client_secret_post", "type": "web",
	})
	clientID := client["client_id"].(string)
	got, err := h.call("getOAuthClient", http.MethodGet, h.headers(), nil, url.Values{"client_id": {clientID}})
	if err != nil || got.Value.(map[string]any)["client_secret"] != nil {
		t.Fatalf("get client err=%v value=%#v", err, got.Value)
	}
	updated, err := h.call("updateOAuthClient", http.MethodPost, h.headers(), map[string]any{
		"client_id": clientID, "update": map[string]any{"client_name": "updated"},
	}, nil)
	if err != nil || updated.Value.(map[string]any)["client_name"] != "updated" {
		t.Fatalf("update err=%v value=%#v", err, updated.Value)
	}
	rotated, err := h.call("rotateClientSecret", http.MethodPost, h.headers(), map[string]any{"client_id": clientID}, nil)
	if err != nil || rotated.Value.(map[string]any)["client_secret"] == "" || rotated.Value.(map[string]any)["client_secret"] == client["client_secret"] {
		t.Fatalf("rotate err=%v value=%#v", err, rotated.Value)
	}
	listed, err := h.call("getOAuthClients", http.MethodGet, h.headers(), nil, nil)
	if err != nil || len(listed.Value.([]any)) != 1 {
		t.Fatalf("list err=%v value=%#v", err, listed.Value)
	}
	deleted, err := h.call("deleteOAuthClient", http.MethodPost, h.headers(), map[string]any{"client_id": clientID}, nil)
	if err != nil || deleted.Response.Status() != http.StatusOK {
		t.Fatalf("delete status=%d err=%v", deleted.Response.Status(), err)
	}
}

func TestOAuthClientCredentialsGrantEnforcesAuthenticationAndScope(t *testing.T) {
	h := newServerIntegrationHarness(t, func(options *Options) {
		options.ClientCredentialGrantDefaultScopes = []string{"read:data"}
	})
	client := h.createClient(map[string]any{
		"client_name": "machine client", "grant_types": []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic", "type": "web",
	})
	clientID := client["client_id"].(string)
	clientSecret := client["client_secret"].(string)

	wrong, wrongErr := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "client_credentials", "client_id": clientID, "client_secret": "wrong-secret",
	}, nil)
	if wrongErr == nil || wrong.Response.Status() != http.StatusUnauthorized {
		t.Fatalf("wrong client secret status=%d err=%v body=%s", wrong.Response.Status(), wrongErr, wrong.Response.Body())
	}
	issued, err := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "client_credentials", "client_id": clientID, "client_secret": clientSecret,
	}, nil)
	if err != nil {
		t.Fatalf("client credentials: %v body=%s", err, issued.Response.Body())
	}
	tokens := issued.Value.(map[string]any)
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" || tokens["scope"] != "read:data" || tokens["refresh_token"] != nil || tokens["id_token"] != nil {
		t.Fatalf("client-credentials tokens=%#v", tokens)
	}
	invalidScope, invalidScopeErr := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "client_credentials", "client_id": clientID, "client_secret": clientSecret,
		"scope": "openid",
	}, nil)
	if invalidScopeErr == nil || invalidScope.Response.Status() != http.StatusBadRequest ||
		!strings.Contains(string(invalidScope.Response.Body()), "invalid_scope") {
		t.Fatalf("OIDC machine scope status=%d err=%v body=%s", invalidScope.Response.Status(), invalidScopeErr, invalidScope.Response.Body())
	}
	wrongIntrospection, wrongIntrospectionErr := h.call("oauth2Introspect", http.MethodPost, contract.Headers{}, map[string]any{
		"client_id": clientID, "client_secret": "wrong-secret", "token": accessToken,
	}, nil)
	if wrongIntrospectionErr == nil || wrongIntrospection.Response.Status() != http.StatusUnauthorized {
		t.Fatalf("wrong introspection credentials status=%d err=%v body=%s", wrongIntrospection.Response.Status(), wrongIntrospectionErr, wrongIntrospection.Response.Body())
	}
	introspected, err := h.call("oauth2Introspect", http.MethodPost, contract.Headers{}, map[string]any{
		"client_id": clientID, "client_secret": clientSecret, "token": accessToken,
	}, nil)
	if err != nil || introspected.Value.(map[string]any)["active"] != true {
		t.Fatalf("machine introspection err=%v value=%#v", err, introspected.Value)
	}
}

func TestOAuthUnauthenticatedRegistrationCreatesPublicPKCEClient(t *testing.T) {
	h := newServerIntegrationHarness(t, func(options *Options) {
		options.AllowUnauthenticatedClientRegistration = true
	})
	redirectURI := "http://127.0.0.1:4721/callback"
	registered, err := h.call("registerOAuthClient", http.MethodPost, contract.Headers{}, map[string]any{
		"client_name": "public native client", "redirect_uris": []string{redirectURI},
		"scope": "openid email", "grant_types": []string{"authorization_code"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_post", "type": "native",
	}, nil)
	if err != nil || registered.Response.Status() != http.StatusCreated {
		t.Fatalf("public registration status=%d err=%v body=%s", registered.Response.Status(), err, registered.Response.Body())
	}
	client := registered.Value.(map[string]any)
	clientID, _ := client["client_id"].(string)
	if clientID == "" || client["token_endpoint_auth_method"] != "none" || client["public"] != true || client["client_secret"] != nil {
		t.Fatalf("public client=%#v", client)
	}

	missingPKCEQuery := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {"openid email"},
	}
	missingPKCE, missingErr := h.call("oauth2Authorize", http.MethodGet, h.headers(), nil, missingPKCEQuery)
	if missingErr != nil || missingPKCE.Response.Status() != http.StatusFound {
		t.Fatalf("missing PKCE status=%d err=%v body=%s", missingPKCE.Response.Status(), missingErr, missingPKCE.Response.Body())
	}
	missingLocation, _ := missingPKCE.Response.Headers().Get("Location")
	missingCallback, _ := url.Parse(missingLocation)
	if missingCallback.Query().Get("error") != "invalid_request" || missingCallback.Query().Get("code") != "" {
		t.Fatalf("missing PKCE redirect=%q", missingLocation)
	}

	authorize := func(verifier string) string {
		t.Helper()
		query := url.Values{
			"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
			"scope": {"openid email"}, "code_challenge": {serverPKCEChallenge(verifier)}, "code_challenge_method": {"S256"},
		}
		result, callErr := h.call("oauth2Authorize", http.MethodGet, h.headers(), nil, query)
		if callErr != nil {
			t.Fatal(callErr)
		}
		location, _ := result.Response.Headers().Get("Location")
		consentURL, parseErr := url.Parse(location)
		if parseErr != nil {
			t.Fatalf("public consent location=%q err=%v", location, parseErr)
		}
		if code := consentURL.Query().Get("code"); code != "" {
			return code
		}
		if consentURL.Query().Get("oauth_query") == "" {
			t.Fatalf("public consent location=%q omitted code and oauth_query", location)
		}
		consent, consentErr := h.call("oauth2Consent", http.MethodPost, h.headers(), map[string]any{
			"accept": true, "oauth_query": consentURL.Query().Get("oauth_query"),
		}, nil)
		if consentErr != nil {
			t.Fatal(consentErr)
		}
		callback, parseErr := url.Parse(consent.Value.(map[string]any)["redirect_uri"].(string))
		if parseErr != nil || callback.Query().Get("code") == "" {
			t.Fatalf("public callback=%#v err=%v", consent.Value, parseErr)
		}
		return callback.Query().Get("code")
	}
	verifier := strings.Repeat("u", 64)
	badCode := authorize(verifier)
	badVerifier, badVerifierErr := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID, "code": badCode,
		"redirect_uri": redirectURI, "code_verifier": strings.Repeat("x", 64),
	}, nil)
	if badVerifierErr == nil || badVerifier.Response.Status() != http.StatusUnauthorized ||
		!strings.Contains(string(badVerifier.Response.Body()), "code verification failed") {
		t.Fatalf("bad verifier status=%d err=%v body=%s", badVerifier.Response.Status(), badVerifierErr, badVerifier.Response.Body())
	}
	code := authorize(verifier)
	issued, err := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID, "code": code,
		"redirect_uri": redirectURI, "code_verifier": verifier,
	}, nil)
	if err != nil {
		t.Fatalf("public token: %v body=%s", err, issued.Response.Body())
	}
	tokens := issued.Value.(map[string]any)
	if tokens["access_token"] == "" || tokens["id_token"] != nil || tokens["refresh_token"] != nil {
		t.Fatalf("public tokens=%#v", tokens)
	}
	replay, replayErr := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID, "code": code,
		"redirect_uri": redirectURI, "code_verifier": verifier,
	}, nil)
	if replayErr == nil || replay.Response.Status() != http.StatusUnauthorized || !strings.Contains(string(replay.Response.Body()), "invalid_grant") {
		t.Fatalf("public code replay status=%d err=%v body=%s", replay.Response.Status(), replayErr, replay.Response.Body())
	}
}

func TestOAuthAuthorizationServerUsesJWTPluginForResourceAndIDTokens(t *testing.T) {
	h := newServerIntegrationHarnessWithFactories(t, func(options *Options) {
		options.DisableJWTPlugin = false
		options.ValidAudiences = []string{"https://resource.example"}
	}, jwtplugin.NewFactory(jwtplugin.Options{}))
	redirectURI := "https://jwt-client.example/callback"
	client := h.createClient(map[string]any{
		"client_name": "JWT client", "redirect_uris": []string{redirectURI},
		"scope":          "openid profile email offline_access read:data",
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_basic", "type": "web",
	})
	clientID, clientSecret := client["client_id"].(string), client["client_secret"].(string)
	verifier := strings.Repeat("j", 64)
	code := h.authorizeAndConsent(clientID, redirectURI, verifier)
	issued, err := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID, "client_secret": clientSecret,
		"code": code, "redirect_uri": redirectURI, "code_verifier": verifier,
		"resource": "https://resource.example",
	}, nil)
	if err != nil {
		t.Fatalf("JWT token: %v body=%s", err, issued.Response.Body())
	}
	tokens := issued.Value.(map[string]any)
	accessToken, _ := tokens["access_token"].(string)
	idToken, _ := tokens["id_token"].(string)
	if strings.Count(accessToken, ".") != 2 || strings.Count(idToken, ".") != 2 {
		t.Fatalf("JWT tokens=%#v", tokens)
	}
	accessClaims := decodeServerTokenPayload(t, accessToken)
	if accessClaims["sub"] != h.userID || accessClaims["client_id"] != clientID ||
		accessClaims["aud"] != "https://resource.example" || accessClaims["scope"] != "openid profile email offline_access read:data" {
		t.Fatalf("access claims=%#v", accessClaims)
	}
	idClaims := decodeServerTokenPayload(t, idToken)
	if idClaims["sub"] != h.userID || idClaims["aud"] != clientID {
		t.Fatalf("ID claims=%#v", idClaims)
	}
	info, err := h.call("oauth2UserInfo", http.MethodGet, contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + accessToken},
	), nil, nil)
	if err != nil || info.Value.(map[string]any)["email"] != "oauth-server@test.invalid" {
		t.Fatalf("JWT userinfo err=%v value=%#v body=%s", err, info.Value, info.Response.Body())
	}
	introspected, err := h.call("oauth2Introspect", http.MethodPost, contract.Headers{}, map[string]any{
		"client_id": clientID, "client_secret": clientSecret,
		"token": accessToken, "token_type_hint": "access_token",
	}, nil)
	if err != nil || introspected.Value.(map[string]any)["active"] != true {
		t.Fatalf("JWT introspection err=%v value=%#v", err, introspected.Value)
	}
}

func decodeServerTokenPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token=%q", token)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
