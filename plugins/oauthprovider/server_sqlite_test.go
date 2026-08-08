package oauthprovider

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
)

func TestOAuthAuthorizationServerSQLiteLifecycleAndReplaySafety(t *testing.T) {
	h := newSQLiteServerIntegrationHarness(t)
	redirectURI := "http://127.0.0.1:4621/callback"
	client := h.createClient(map[string]any{
		"client_name": "sqlite client", "redirect_uris": []string{redirectURI},
		"scope":          "openid profile email offline_access read:data write:data",
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "client_secret_basic", "type": "web",
	})
	clientID := client["client_id"].(string)
	clientSecret := client["client_secret"].(string)
	verifier := strings.Repeat("s", 64)
	code := h.authorizeAndConsent(clientID, redirectURI, verifier)

	const codeRacers = 8
	start := make(chan struct{})
	results := make(chan singleauth.DirectCallResult, codeRacers)
	var wait sync.WaitGroup
	wait.Add(codeRacers)
	for range codeRacers {
		go func() {
			defer wait.Done()
			<-start
			result, _ := h.auth.API().Call(t.Context(), "oauth2Token", singleauth.DirectCallInput{
				Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
				Body: map[string]any{
					"grant_type": "authorization_code", "client_id": clientID, "client_secret": clientSecret,
					"code": code, "redirect_uri": redirectURI, "code_verifier": verifier,
				},
			})
			results <- result
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var tokens map[string]any
	successes := 0
	for result := range results {
		if result.Response.Status() == http.StatusOK {
			successes++
			tokens = result.Value.(map[string]any)
		}
	}
	if successes != 1 {
		t.Fatalf("SQLite successful authorization-code redemptions=%d want=1", successes)
	}
	accessToken := tokens["access_token"].(string)
	refreshToken := tokens["refresh_token"].(string)

	introspected, err := h.call("oauth2Introspect", http.MethodPost, contract.Headers{}, map[string]any{
		"client_id": clientID, "client_secret": clientSecret, "token": accessToken,
	}, nil)
	if err != nil || introspected.Value.(map[string]any)["active"] != true {
		t.Fatalf("SQLite introspection err=%v value=%#v", err, introspected.Value)
	}
	revoked, err := h.call("oauth2Revoke", http.MethodPost, contract.Headers{}, map[string]any{
		"client_id": clientID, "client_secret": clientSecret,
		"token": accessToken, "token_type_hint": "access_token",
	}, nil)
	if err != nil || revoked.Response.Status() != http.StatusOK {
		t.Fatalf("SQLite revoke status=%d err=%v body=%s", revoked.Response.Status(), err, revoked.Response.Body())
	}
	inactive, err := h.call("oauth2Introspect", http.MethodPost, contract.Headers{}, map[string]any{
		"client_id": clientID, "client_secret": clientSecret,
		"token": accessToken, "token_type_hint": "access_token",
	}, nil)
	if err != nil || inactive.Value.(map[string]any)["active"] != false {
		t.Fatalf("SQLite inactive introspection err=%v value=%#v", err, inactive.Value)
	}
	escalated, escalationErr := h.call("oauth2Token", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": "refresh_token", "client_id": clientID, "client_secret": clientSecret,
		"refresh_token": refreshToken, "scope": "openid email offline_access read:data write:data unknown",
	}, nil)
	if escalationErr == nil || escalated.Response.Status() != http.StatusBadRequest {
		t.Fatalf("SQLite scope escalation status=%d err=%v body=%s", escalated.Response.Status(), escalationErr, escalated.Response.Body())
	}

	const refreshRacers = 8
	refreshStart := make(chan struct{})
	refreshStatuses := make(chan int, refreshRacers)
	wait.Add(refreshRacers)
	for range refreshRacers {
		go func() {
			defer wait.Done()
			<-refreshStart
			result, _ := h.auth.API().Call(t.Context(), "oauth2Token", singleauth.DirectCallInput{
				Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
				Body: map[string]any{
					"grant_type": "refresh_token", "client_id": clientID, "client_secret": clientSecret,
					"refresh_token": refreshToken, "scope": "openid email read:data",
				},
			})
			refreshStatuses <- result.Response.Status()
		}()
	}
	close(refreshStart)
	wait.Wait()
	close(refreshStatuses)
	refreshSuccesses := 0
	for status := range refreshStatuses {
		if status == http.StatusOK {
			refreshSuccesses++
		}
	}
	if refreshSuccesses != 1 {
		t.Fatalf("SQLite successful refresh rotations=%d want=1", refreshSuccesses)
	}
}

func newSQLiteServerIntegrationHarness(t *testing.T) *serverIntegrationHarness {
	t.Helper()
	now := time.Date(2028, time.March, 4, 5, 6, 7, 0, time.UTC)
	dsn := fmt.Sprintf(
		"file:oauth_server_%d?mode=memory&cache=shared&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)",
		time.Now().UnixNano(),
	)
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(8)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close OAuth server SQLite database: %v", err)
		}
	})
	factory := NewFactory(Options{
		LoginPage: "/login", ConsentPage: "/consent", DisableJWTPlugin: true,
		AllowDynamicClientRegistration: true,
		Scopes:                         []string{"openid", "profile", "email", "offline_access", "read:data", "write:data"},
	})
	auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
		Clock: func() time.Time { return now },
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
				Verify: func(hash, value string) bool { return hash == "hashed:"+value },
			},
		},
		PluginFactories: []singleauth.PluginFactory{factory},
	}, database)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RunMigrationsContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	signedUp, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "OAuth SQLite User", Email: "oauth-sqlite@test.invalid", Password: "password123",
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
