package singleauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	ssoplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const oidcAuthBaseURL = "http://oidc-auth.test"

type ssoOIDCServer struct {
	server *httptest.Server

	mu            sync.Mutex
	tokenRequests []url.Values
	tokenHeaders  []http.Header
	profile       map[string]any
	tokenResponse map[string]any
	discoveryHits int
}

func newSSOOIDCServer(t *testing.T) *ssoOIDCServer {
	t.Helper()
	fixture := &ssoOIDCServer{
		profile: map[string]any{
			"sub": "enterprise-user", "email": "Enterprise.User@corp.example",
			"name": "Enterprise User", "picture": "https://images.example/user.png",
			"email_verified": true, "department": "security",
		},
		tokenResponse: map[string]any{
			"access_token": "oidc-access", "refresh_token": "oidc-refresh",
			"token_type": "Bearer", "scope": "openid email profile", "expires_in": 3600,
		},
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			fixture.mu.Lock()
			fixture.discoveryHits++
			fixture.mu.Unlock()
			writeOIDCJSON(t, writer, map[string]any{
				"issuer": fixture.server.URL, "authorization_endpoint": fixture.server.URL + "/authorize",
				"token_endpoint": fixture.server.URL + "/token", "jwks_uri": fixture.server.URL + "/jwks",
				"userinfo_endpoint":                     fixture.server.URL + "/userinfo",
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			})
		case "/token":
			if err := request.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			fixture.mu.Lock()
			fixture.tokenRequests = append(fixture.tokenRequests, cloneURLValues(request.PostForm))
			fixture.tokenHeaders = append(fixture.tokenHeaders, request.Header.Clone())
			response := cloneAnyRecord(fixture.tokenResponse)
			fixture.mu.Unlock()
			writeOIDCJSON(t, writer, response)
		case "/userinfo":
			if request.Header.Get("Authorization") != "Bearer oidc-access" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			fixture.mu.Lock()
			profile := cloneAnyRecord(fixture.profile)
			fixture.mu.Unlock()
			writeOIDCJSON(t, writer, profile)
		case "/jwks":
			writeOIDCJSON(t, writer, map[string]any{"keys": []any{}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (server *ssoOIDCServer) resetRequests() {
	server.mu.Lock()
	server.tokenRequests = nil
	server.tokenHeaders = nil
	server.mu.Unlock()
}

func (server *ssoOIDCServer) explicitConfig(providerID string) ssoplugin.OIDCConfig {
	pkce := true
	return ssoplugin.OIDCConfig{
		Issuer: server.server.URL, ClientID: "enterprise-client", ClientSecret: "enterprise-secret",
		AuthorizationEndpoint: server.server.URL + "/authorize", TokenEndpoint: server.server.URL + "/token",
		UserInfoEndpoint: server.server.URL + "/userinfo", JWKSEndpoint: server.server.URL + "/jwks",
		DiscoveryEndpoint:           server.server.URL + "/.well-known/openid-configuration",
		TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce,
		Mapping: ssoplugin.OIDCMapping{ExtraFields: map[string]string{"department": "department"}},
	}
}

func newSSOOIDCAuth(
	t *testing.T,
	server *ssoOIDCServer,
	config ssoplugin.OIDCConfig,
	mutate func(*singleauth.Options, *ssoplugin.Options),
) (*singleauth.Auth, *memory.Adapter) {
	t.Helper()
	adapter := memory.MustNew()
	pluginOptions := ssoplugin.Options{
		DefaultSSO: []ssoplugin.DefaultProvider{{
			ProviderID: "enterprise", Domain: "corp.example", OIDCConfig: &config,
		}},
		OIDC:               ssoplugin.OIDCRuntimeOptions{HTTPClient: server.server.Client()},
		TrustEmailVerified: true,
	}
	options := singleauth.Options{
		BaseURL: oidcAuthBaseURL, Secret: "sso-oidc-test-secret-at-least-32-bytes",
		Database: adapter, TrustedOrigins: []string{server.server.URL},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Clock:            func() time.Time { return time.Date(2026, time.August, 10, 4, 0, 0, 0, time.UTC) },
	}
	if mutate != nil {
		mutate(&options, &pluginOptions)
	}
	options.PluginFactories = []singleauth.PluginFactory{ssoplugin.NewFactory(pluginOptions)}
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth, adapter
}

func TestSSOOIDCLifecycleAcrossHTTPTransports(t *testing.T) {
	server := newSSOOIDCServer(t)
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			server.resetRequests()
			auth, adapter := newSSOOIDCAuth(t, server, server.explicitConfig("enterprise"), nil)
			cookies := make(map[string]string)
			started := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sign-in/sso", []byte(`{
				"providerId":"enterprise","callbackURL":"/dashboard","newUserCallbackURL":"/welcome",
				"loginHint":"person@corp.example"
			}`), cookies)
			if started.status != http.StatusOK {
				t.Fatalf("start status=%d body=%s", started.status, started.body)
			}
			var startBody struct {
				URL      string `json:"url"`
				Redirect bool   `json:"redirect"`
			}
			if err := json.Unmarshal(started.body, &startBody); err != nil {
				t.Fatal(err)
			}
			authorizationURL, err := url.Parse(startBody.URL)
			if err != nil {
				t.Fatal(err)
			}
			query := authorizationURL.Query()
			if !startBody.Redirect || authorizationURL.Path != "/authorize" ||
				query.Get("client_id") != "enterprise-client" || query.Get("login_hint") != "person@corp.example" ||
				query.Get("redirect_uri") != oidcAuthBaseURL+"/api/auth/sso/callback/enterprise" ||
				query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
				t.Fatalf("authorization URL=%s", authorizationURL)
			}
			callback := ssoOIDCExchange(t, auth, transport, http.MethodGet,
				"/sso/callback/enterprise?code=valid-code&state="+url.QueryEscape(query.Get("state")), nil, cookies)
			if callback.status != http.StatusFound || callback.header.Get("Location") != "/welcome" {
				t.Fatalf("callback status=%d location=%q body=%s", callback.status, callback.header.Get("Location"), callback.body)
			}
			users := oidcRecords(t, adapter, "user")
			accounts := oidcRecords(t, adapter, "account")
			sessions := oidcRecords(t, adapter, "session")
			if len(users) != 1 || len(accounts) != 1 || len(sessions) != 1 ||
				users[0]["email"] != "enterprise.user@corp.example" ||
				accounts[0]["providerId"] != "enterprise" || accounts[0]["accountId"] != "enterprise-user" ||
				accounts[0]["refreshToken"] != "oidc-refresh" {
				t.Fatalf("users=%#v accounts=%#v sessions=%#v", users, accounts, sessions)
			}
			server.mu.Lock()
			if len(server.tokenRequests) != 1 || server.tokenRequests[0].Get("code_verifier") == "" ||
				server.tokenRequests[0].Get("redirect_uri") != oidcAuthBaseURL+"/api/auth/sso/callback/enterprise" ||
				server.tokenHeaders[0].Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("enterprise-client:enterprise-secret")) {
				t.Fatalf("token requests=%#v headers=%#v", server.tokenRequests, server.tokenHeaders)
			}
			if oauth2.GenerateCodeChallenge(server.tokenRequests[0].Get("code_verifier")) != query.Get("code_challenge") {
				t.Fatalf("PKCE verifier does not match challenge")
			}
			server.mu.Unlock()
		})
	}
}

func TestSSOOIDCStateIsSingleUseUnderConcurrency(t *testing.T) {
	server := newSSOOIDCServer(t)
	auth, adapter := newSSOOIDCAuth(t, server, server.explicitConfig("enterprise"), nil)
	cookies := make(map[string]string)
	started := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"enterprise","callbackURL":"/done"}`), cookies)
	var body map[string]any
	if err := json.Unmarshal(started.body, &body); err != nil {
		t.Fatal(err)
	}
	authorizationURL, _ := url.Parse(body["url"].(string))
	state := authorizationURL.Query().Get("state")

	const racers = 24
	var successes atomic.Int32
	var replays atomic.Int32
	var wait sync.WaitGroup
	wait.Add(racers)
	for range racers {
		go func() {
			defer wait.Done()
			jar := cloneCookieValues(cookies)
			response := ssoOIDCExchange(t, auth, "net/http", http.MethodGet,
				"/sso/callback/enterprise?code=valid-code&state="+url.QueryEscape(state), nil, jar)
			location := response.header.Get("Location")
			if location == "/done" {
				successes.Add(1)
			} else if parsed, err := url.Parse(location); err == nil && parsed.Query().Get("error") == "state_mismatch" {
				replays.Add(1)
			}
		}()
	}
	wait.Wait()
	server.mu.Lock()
	tokenCalls := len(server.tokenRequests)
	server.mu.Unlock()
	if successes.Load() != 1 || replays.Load() != racers-1 || tokenCalls != 1 || len(oidcRecords(t, adapter, "user")) != 1 {
		t.Fatalf("successes=%d replays=%d tokenCalls=%d users=%#v", successes.Load(), replays.Load(), tokenCalls, oidcRecords(t, adapter, "user"))
	}
}

func TestSSOOIDCInvalidStateRejectedAcrossHTTPTransports(t *testing.T) {
	server := newSSOOIDCServer(t)
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			server.resetRequests()
			auth, adapter := newSSOOIDCAuth(t, server, server.explicitConfig("enterprise"), nil)
			cookies := make(map[string]string)
			started := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sign-in/sso",
				[]byte(`{"providerId":"enterprise","callbackURL":"/done","errorCallbackURL":"/error"}`), cookies)
			if started.status != http.StatusOK {
				t.Fatalf("start status=%d body=%s", started.status, started.body)
			}
			callback := ssoOIDCExchange(t, auth, transport, http.MethodGet,
				"/sso/callback/enterprise?code=attacker&state=attacker-controlled-state", nil, cookies)
			location, _ := url.Parse(callback.header.Get("Location"))
			server.mu.Lock()
			tokenCalls := len(server.tokenRequests)
			server.mu.Unlock()
			if callback.status != http.StatusFound || location.Path != "/api/auth/error" || location.Query().Get("error") != "state_mismatch" ||
				tokenCalls != 0 || len(oidcRecords(t, adapter, "user")) != 0 {
				t.Fatalf("callback=%q tokenCalls=%d users=%#v", callback.header.Get("Location"), tokenCalls, oidcRecords(t, adapter, "user"))
			}
		})
	}
}

func TestSSOOIDCSharedRedirectClientSecretPostAndSignupPolicy(t *testing.T) {
	server := newSSOOIDCServer(t)
	config := server.explicitConfig("enterprise")
	config.TokenEndpointAuthentication = "client_secret_post"
	auth, adapter := newSSOOIDCAuth(t, server, config, func(_ *singleauth.Options, options *ssoplugin.Options) {
		options.RedirectURI = "/sso/callback"
		options.DisableImplicitSignUp = true
	})
	cookies := make(map[string]string)
	blocked := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"enterprise","callbackURL":"/done","errorCallbackURL":"/error"}`), cookies)
	var blockedBody map[string]any
	_ = json.Unmarshal(blocked.body, &blockedBody)
	blockedURL, _ := url.Parse(blockedBody["url"].(string))
	if blockedURL.Query().Get("redirect_uri") != oidcAuthBaseURL+"/api/auth/sso/callback" {
		t.Fatalf("shared redirect=%s", blockedURL)
	}
	blockedCallback := ssoOIDCExchange(t, auth, "net/http", http.MethodGet,
		"/sso/callback?code=blocked&state="+url.QueryEscape(blockedURL.Query().Get("state")), nil, cookies)
	blockedLocation, _ := url.Parse(blockedCallback.header.Get("Location"))
	if blockedLocation.Path != "/error" || blockedLocation.Query().Get("error") != "signup_disabled" || len(oidcRecords(t, adapter, "user")) != 0 {
		t.Fatalf("blocked location=%q users=%#v", blockedCallback.header.Get("Location"), oidcRecords(t, adapter, "user"))
	}

	cookies = make(map[string]string)
	requested := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"enterprise","callbackURL":"/done","requestSignUp":true}`), cookies)
	var requestedBody map[string]any
	_ = json.Unmarshal(requested.body, &requestedBody)
	requestedURL, _ := url.Parse(requestedBody["url"].(string))
	callback := ssoOIDCExchange(t, auth, "net/http", http.MethodGet,
		"/sso/callback?code=allowed&state="+url.QueryEscape(requestedURL.Query().Get("state")), nil, cookies)
	if callback.header.Get("Location") != "/done" || len(oidcRecords(t, adapter, "user")) != 1 {
		t.Fatalf("requested callback=%q users=%#v", callback.header.Get("Location"), oidcRecords(t, adapter, "user"))
	}
	server.mu.Lock()
	lastForm := server.tokenRequests[len(server.tokenRequests)-1]
	lastHeader := server.tokenHeaders[len(server.tokenHeaders)-1]
	server.mu.Unlock()
	if lastForm.Get("client_id") != "enterprise-client" || lastForm.Get("client_secret") != "enterprise-secret" || lastHeader.Get("Authorization") != "" {
		t.Fatalf("post auth form=%#v headers=%#v", lastForm, lastHeader)
	}
}

func TestSSOOIDCIDTokenJWKSVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := newSSOOIDCServer(t)
	server.server.Close()
	var issuer string
	var invalidAudience atomic.Bool
	server.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			audience := "enterprise-client"
			if invalidAudience.Load() {
				audience = "attacker-client"
			}
			writeOIDCJSON(t, writer, map[string]any{
				"access_token": "id-token-access", "id_token": signSSOOIDCToken(t, privateKey, map[string]any{
					"iss": issuer, "aud": audience, "sub": "id-token-sub",
					"email": "id-token@corp.example", "name": "ID Token User", "email_verified": true,
					"exp": time.Now().Add(time.Hour).Unix(),
				}),
			})
		case "/jwks":
			writeOIDCJSON(t, writer, map[string]any{"keys": []any{rsaSSOJWK(&privateKey.PublicKey)}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	issuer = server.server.URL
	t.Cleanup(server.server.Close)
	config := server.explicitConfig("enterprise")
	config.Issuer = issuer
	config.AuthorizationEndpoint = issuer + "/authorize"
	config.TokenEndpoint = issuer + "/token"
	config.JWKSEndpoint = issuer + "/jwks"
	config.DiscoveryEndpoint = issuer + "/.well-known/openid-configuration"
	config.UserInfoEndpoint = ""
	auth, adapter := newSSOOIDCAuth(t, server, config, nil)
	cookies := make(map[string]string)
	started := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"enterprise","callbackURL":"/done"}`), cookies)
	var body map[string]any
	_ = json.Unmarshal(started.body, &body)
	startedURL, _ := url.Parse(body["url"].(string))
	callback := ssoOIDCExchange(t, auth, "net/http", http.MethodGet,
		"/sso/callback/enterprise?code=id-token&state="+url.QueryEscape(startedURL.Query().Get("state")), nil, cookies)
	if callback.header.Get("Location") != "/done" || len(oidcRecords(t, adapter, "user")) != 1 || oidcRecords(t, adapter, "user")[0]["email"] != "id-token@corp.example" {
		t.Fatalf("callback=%q users=%#v", callback.header.Get("Location"), oidcRecords(t, adapter, "user"))
	}

	invalidAudience.Store(true)
	rejectedAuth, rejectedAdapter := newSSOOIDCAuth(t, server, config, nil)
	rejectedCookies := make(map[string]string)
	rejectedStart := ssoOIDCExchange(t, rejectedAuth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"enterprise","callbackURL":"/done","errorCallbackURL":"/error"}`), rejectedCookies)
	var rejectedBody map[string]any
	_ = json.Unmarshal(rejectedStart.body, &rejectedBody)
	rejectedURL, _ := url.Parse(rejectedBody["url"].(string))
	rejected := ssoOIDCExchange(t, rejectedAuth, "net/http", http.MethodGet,
		"/sso/callback/enterprise?code=bad-audience&state="+url.QueryEscape(rejectedURL.Query().Get("state")), nil, rejectedCookies)
	rejectedLocation, _ := url.Parse(rejected.header.Get("Location"))
	if rejectedLocation.Path != "/error" || rejectedLocation.Query().Get("error_description") != "token_not_verified" || len(oidcRecords(t, rejectedAdapter, "user")) != 0 {
		t.Fatalf("rejected location=%q users=%#v", rejected.header.Get("Location"), oidcRecords(t, rejectedAdapter, "user"))
	}
}

func TestSSOOIDCRegistrationDiscoveryStoredResolutionAndSSRF(t *testing.T) {
	server := newSSOOIDCServer(t)
	pluginFactory := ssoplugin.NewFactory(ssoplugin.Options{
		OIDC:               ssoplugin.OIDCRuntimeOptions{HTTPClient: server.server.Client()},
		TrustEmailVerified: true,
	})
	pluginSchema, err := pluginFactory.Schema()
	if err != nil {
		t.Fatal(err)
	}
	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	schema, err = schema.Merge(pluginSchema)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := memory.New(memory.WithSchema(schema))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: oidcAuthBaseURL, Secret: "sso-registration-secret-at-least-32-bytes",
		Database: adapter, TrustedOrigins: []string{server.server.URL},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories:  []singleauth.PluginFactory{pluginFactory},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookies := make(map[string]string)
	signUp := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sign-up/email",
		[]byte(`{"name":"Owner","email":"owner@example.com","password":"password123"}`), cookies)
	if signUp.status != http.StatusOK {
		t.Fatalf("sign up status=%d body=%s", signUp.status, signUp.body)
	}
	registrationBody, _ := json.Marshal(map[string]any{
		"issuer": server.server.URL, "domain": "corp.example", "providerId": "stored-enterprise",
		"oidcConfig": map[string]any{
			"clientId": "enterprise-client", "clientSecret": "enterprise-secret",
			"mapping": map[string]any{"id": "sub", "email": "email", "name": "name"},
		},
	})
	registered := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sso/register", registrationBody, cookies)
	if registered.status != http.StatusOK {
		t.Fatalf("register status=%d body=%s", registered.status, registered.body)
	}
	var provider map[string]any
	if err := json.Unmarshal(registered.body, &provider); err != nil {
		t.Fatal(err)
	}
	config, _ := provider["oidcConfig"].(map[string]any)
	if provider["providerId"] != "stored-enterprise" || config["authorizationEndpoint"] != server.server.URL+"/authorize" ||
		config["tokenEndpoint"] != server.server.URL+"/token" || config["jwksEndpoint"] != server.server.URL+"/jwks" ||
		provider["redirectURI"] != oidcAuthBaseURL+"/api/auth/sso/callback/stored-enterprise" {
		t.Fatalf("registered provider=%#v", provider)
	}
	stored := oidcRecords(t, adapter, "ssoProvider")
	if len(stored) != 1 {
		t.Fatalf("stored providers=%#v", stored)
	}
	if _, ok := stored[0]["oidcConfig"].(string); !ok {
		t.Fatalf("stored oidc config must be encoded JSON text: %#v", stored[0]["oidcConfig"])
	}

	flowCookies := make(map[string]string)
	started := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"stored-enterprise","callbackURL":"/stored-done"}`), flowCookies)
	var startedBody map[string]any
	_ = json.Unmarshal(started.body, &startedBody)
	startedURL, _ := url.Parse(startedBody["url"].(string))
	callback := ssoOIDCExchange(t, auth, "net/http", http.MethodGet,
		"/sso/callback/stored-enterprise?code=stored&state="+url.QueryEscape(startedURL.Query().Get("state")), nil, flowCookies)
	if callback.header.Get("Location") != "/stored-done" {
		t.Fatalf("stored callback=%q body=%s", callback.header.Get("Location"), callback.body)
	}

	ssrfBody, _ := json.Marshal(map[string]any{
		"issuer": server.server.URL, "domain": "blocked.example", "providerId": "blocked-provider",
		"oidcConfig": map[string]any{
			"clientId": "blocked", "clientSecret": "blocked", "skipDiscovery": true,
			"authorizationEndpoint": server.server.URL + "/authorize",
			"tokenEndpoint":         "http://169.254.169.254/latest/meta-data/",
			"jwksEndpoint":          server.server.URL + "/jwks",
		},
	})
	blocked := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sso/register", ssrfBody, cookies)
	if blocked.status != http.StatusBadRequest || !strings.Contains(string(blocked.body), "discovery_private_host") {
		t.Fatalf("SSRF register status=%d body=%s", blocked.status, blocked.body)
	}
}

func TestSSOOIDCDNSRebindingAndDiscoveryRedirectGuards(t *testing.T) {
	server := newSSOOIDCServer(t)
	privateConfig := server.explicitConfig("enterprise")
	privateConfig.Issuer = "https://idp.public.example"
	privateConfig.AuthorizationEndpoint = "https://idp.public.example/authorize"
	privateConfig.TokenEndpoint = "https://idp.public.example/token"
	privateConfig.UserInfoEndpoint = "https://idp.public.example/userinfo"
	privateConfig.JWKSEndpoint = "https://idp.public.example/jwks"
	privateConfig.DiscoveryEndpoint = "https://idp.public.example/.well-known/openid-configuration"
	privateAuth, privateAdapter := newSSOOIDCAuth(t, server, privateConfig, func(_ *singleauth.Options, options *ssoplugin.Options) {
		options.OIDC.LookupIP = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
	})
	blocked := ssoOIDCExchange(t, privateAuth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"enterprise","callbackURL":"/done"}`), make(map[string]string))
	if blocked.status != http.StatusBadRequest || !strings.Contains(string(blocked.body), "discovery_private_host") ||
		len(oidcRecords(t, privateAdapter, "verification")) != 0 {
		t.Fatalf("DNS guard status=%d body=%s verifications=%#v", blocked.status, blocked.body, oidcRecords(t, privateAdapter, "verification"))
	}

	var redirectServer *httptest.Server
	redirectServer = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/.well-known/openid-configuration" {
			http.Redirect(writer, request, redirectServer.URL+"/private-document", http.StatusFound)
			return
		}
		writeOIDCJSON(t, writer, map[string]any{
			"issuer": redirectServer.URL, "authorization_endpoint": redirectServer.URL + "/authorize",
			"token_endpoint": redirectServer.URL + "/token", "jwks_uri": redirectServer.URL + "/jwks",
		})
	}))
	t.Cleanup(redirectServer.Close)
	pkce := true
	redirectConfig := ssoplugin.OIDCConfig{
		Issuer: redirectServer.URL, ClientID: "redirect-client", ClientSecret: "redirect-secret",
		DiscoveryEndpoint: redirectServer.URL + "/.well-known/openid-configuration", PKCE: &pkce,
	}
	redirectAuth, _ := newSSOOIDCAuth(t, server, redirectConfig, func(options *singleauth.Options, pluginOptions *ssoplugin.Options) {
		options.TrustedOrigins = append(options.TrustedOrigins, redirectServer.URL)
		pluginOptions.OIDC.HTTPClient = redirectServer.Client()
	})
	redirected := ssoOIDCExchange(t, redirectAuth, "net/http", http.MethodPost, "/sign-in/sso",
		[]byte(`{"providerId":"enterprise","callbackURL":"/done"}`), make(map[string]string))
	if redirected.status != http.StatusBadGateway || !strings.Contains(string(redirected.body), "discovery_unexpected_error") {
		t.Fatalf("redirect discovery status=%d body=%s", redirected.status, redirected.body)
	}
}

type ssoOIDCResponse struct {
	status int
	header http.Header
	body   []byte
}

func ssoOIDCExchange(
	t *testing.T,
	auth *singleauth.Auth,
	transport, method, target string,
	body []byte,
	cookies map[string]string,
) ssoOIDCResponse {
	t.Helper()
	fullTarget := oidcAuthBaseURL + "/api/auth" + target
	cookieHeader := serializeCookieValues(cookies)
	var result ssoOIDCResponse
	switch transport {
	case "net/http":
		request := httptest.NewRequest(method, fullTarget, bytes.NewReader(body))
		request.Header.Set("Origin", oidcAuthBaseURL)
		request.Header.Set("Content-Type", "application/json")
		if cookieHeader != "" {
			request.Header.Set("Cookie", cookieHeader)
		}
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		result = ssoOIDCResponse{status: recorder.Code, header: recorder.Header().Clone(), body: append([]byte(nil), recorder.Body.Bytes()...)}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.SetContentType("application/json")
		request.Header.Set("Origin", oidcAuthBaseURL)
		if cookieHeader != "" {
			request.Header.Set("Cookie", cookieHeader)
		}
		request.SetRequestURI(fullTarget)
		request.SetBody(body)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		header := make(http.Header)
		requestContext.Response.Header.VisitAll(func(key, value []byte) {
			header.Add(string(key), string(value))
		})
		result = ssoOIDCResponse{status: requestContext.Response.StatusCode(), header: header, body: append([]byte(nil), requestContext.Response.Body()...)}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(method, fullTarget, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", oidcAuthBaseURL)
		request.Header.Set("Content-Type", "application/json")
		if cookieHeader != "" {
			request.Header.Set("Cookie", cookieHeader)
		}
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		result = ssoOIDCResponse{status: response.StatusCode, header: response.Header.Clone(), body: encoded}
	default:
		t.Fatalf("unknown transport %q", transport)
	}
	applyOIDCSetCookies(cookies, result.header)
	return result
}

func applyOIDCSetCookies(jar map[string]string, header http.Header) {
	if jar == nil {
		return
	}
	response := &http.Response{Header: header}
	for _, cookie := range response.Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(jar, cookie.Name)
			continue
		}
		jar[cookie.Name] = cookie.Value
	}
}

func serializeCookieValues(values map[string]string) string {
	parts := make([]string, 0, len(values))
	for name, value := range values {
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; ")
}

func cloneCookieValues(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func oidcRecords(t *testing.T, adapter storage.Adapter, model string) []storage.Record {
	t.Helper()
	records, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: model})
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func cloneURLValues(input url.Values) url.Values {
	result := make(url.Values, len(input))
	for key, values := range input {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func cloneAnyRecord(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func writeOIDCJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode OIDC response: %v", err)
	}
}

func signSSOOIDCToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "sso-test-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func rsaSSOJWK(key *rsa.PublicKey) map[string]any {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]any{
		"kty": "RSA", "kid": "sso-test-key", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}
}
