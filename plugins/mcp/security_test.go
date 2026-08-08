package mcp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	securityClientID     = "pw9m-mcp-confidential-test-client"
	securityClientSecret = "pw9m-mcp-secret-only-the-client-knows"
	securityRefreshToken = "pw9m-mcp-test-refresh-token"
)

func securityHarness(t *testing.T, disabled bool, scopes string) (*harness, string) {
	t.Helper()
	harness := newHarness(t, nil)
	userID, _ := harness.signUp(t, 20)
	seedClient(t, harness, securityClientID, securityClientSecret, "web", disabled)
	seedToken(
		t, harness, userID, securityClientID, "stale-access-token", securityRefreshToken, scopes,
		harness.clock.Now().Add(-time.Minute), harness.clock.Now().Add(7*24*time.Hour),
	)
	return harness, userID
}

func TestRefreshTokenGrantClientAuthenticationSecurity(t *testing.T) {
	t.Run("missing confidential secret", func(t *testing.T) {
		harness, _ := securityHarness(t, false, "openid profile email offline_access")
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.Headers{}, map[string]any{
			"grant_type": "refresh_token", "refresh_token": securityRefreshToken,
			"client_id": securityClientID,
		}, nil)
		oauthErrorObject(t, result, err, http.StatusUnauthorized, "invalid_client")
	})
	t.Run("wrong confidential secret", func(t *testing.T) {
		harness, _ := securityHarness(t, false, "openid profile email offline_access")
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.Headers{}, map[string]any{
			"grant_type": "refresh_token", "refresh_token": securityRefreshToken,
			"client_id": securityClientID, "client_secret": "wrong-secret",
		}, nil)
		oauthErrorObject(t, result, err, http.StatusUnauthorized, "invalid_client")
	})
	t.Run("basic authentication", func(t *testing.T) {
		harness, _ := securityHarness(t, false, "openid profile email offline_access")
		basic := base64.StdEncoding.EncodeToString([]byte(securityClientID + ":" + securityClientSecret))
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.NewHeaders(
			contract.HeaderField{Name: "Authorization", Value: "Basic " + basic},
		), map[string]any{
			"grant_type": "refresh_token", "refresh_token": securityRefreshToken,
		}, nil)
		if err != nil {
			t.Fatalf("refresh: %v body=%s", err, result.Response.Body())
		}
		object := responseObject(t, result)
		if object["access_token"] == "" || object["refresh_token"] == "" || object["token_type"] != "bearer" {
			t.Fatalf("refresh=%#v", object)
		}
	})
	t.Run("basic and matching body id", func(t *testing.T) {
		harness, _ := securityHarness(t, false, "openid profile email offline_access")
		basic := base64.StdEncoding.EncodeToString([]byte(securityClientID + ":" + securityClientSecret))
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.NewHeaders(
			contract.HeaderField{Name: "Authorization", Value: "Basic " + basic},
		), map[string]any{
			"grant_type": "refresh_token", "refresh_token": securityRefreshToken,
			"client_id": securityClientID,
		}, nil)
		if err != nil || responseObject(t, result)["access_token"] == "" {
			t.Fatalf("refresh result=%s err=%v", result.Response.Body(), err)
		}
	})
	t.Run("basic and mismatching body id", func(t *testing.T) {
		harness, _ := securityHarness(t, false, "openid profile email offline_access")
		basic := base64.StdEncoding.EncodeToString([]byte(securityClientID + ":" + securityClientSecret))
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.NewHeaders(
			contract.HeaderField{Name: "Authorization", Value: "Basic " + basic},
		), map[string]any{
			"grant_type": "refresh_token", "refresh_token": securityRefreshToken,
			"client_id": "different-client-id",
		}, nil)
		oauthErrorObject(t, result, err, http.StatusUnauthorized, "invalid_client")
	})
	t.Run("disabled confidential client", func(t *testing.T) {
		harness, _ := securityHarness(t, true, "openid profile email offline_access")
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.Headers{}, map[string]any{
			"grant_type": "refresh_token", "refresh_token": securityRefreshToken,
			"client_id": securityClientID, "client_secret": securityClientSecret,
		}, nil)
		oauthErrorObject(t, result, err, http.StatusUnauthorized, "invalid_client")
	})
	t.Run("missing offline access", func(t *testing.T) {
		harness, _ := securityHarness(t, false, "openid profile email")
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.Headers{}, map[string]any{
			"grant_type": "refresh_token", "refresh_token": securityRefreshToken,
			"client_id": securityClientID, "client_secret": securityClientSecret,
		}, nil)
		oauthErrorObject(t, result, err, http.StatusUnauthorized, "invalid_grant")
	})
	t.Run("invalid refresh token", func(t *testing.T) {
		harness, _ := securityHarness(t, false, "openid profile email offline_access")
		result, err := harness.call(t, "mcpOAuthToken", http.MethodPost, contract.Headers{}, map[string]any{
			"grant_type": "refresh_token", "refresh_token": "invalid-refresh-token",
			"client_id": securityClientID, "client_secret": securityClientSecret,
		}, nil)
		object := oauthErrorObject(t, result, err, http.StatusUnauthorized, "invalid_grant")
		if object["error_description"] != "invalid refresh token" {
			t.Fatalf("error=%#v", object)
		}
	})
}

func TestSessionFreshnessAndWithMCPAuth(t *testing.T) {
	harness := newHarness(t, nil)
	userID, _ := harness.signUp(t, 30)
	seedClient(t, harness, "freshness-test-client", "freshness-secret", "web", false)
	seedToken(
		t, harness, userID, "freshness-test-client", "expired-access-token", "expired-refresh",
		"openid profile email offline_access", harness.clock.Now().Add(-time.Minute), harness.clock.Now().Add(time.Hour),
	)
	seedToken(
		t, harness, userID, "freshness-test-client", "live-access-token", "live-refresh",
		"openid profile email offline_access", harness.clock.Now().Add(time.Hour), harness.clock.Now().Add(24*time.Hour),
	)

	expired, err := harness.call(t, "getMcpSession", http.MethodGet, contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer expired-access-token"},
	), nil, nil)
	if err != nil || expired.Value != nil {
		t.Fatalf("expired=%#v err=%v", expired.Value, err)
	}
	live, err := harness.call(t, "getMcpSession", http.MethodGet, contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer live-access-token"},
	), nil, nil)
	if err != nil || responseObject(t, live)["userId"] != userID {
		t.Fatalf("live=%#v err=%v", live.Value, err)
	}

	var called atomic.Bool
	protected := WithMCPAuth(harness.auth, func(writer http.ResponseWriter, _ *http.Request, token AccessToken) {
		called.Store(true)
		if token.UserID != userID {
			t.Errorf("token=%#v", token)
		}
		writer.WriteHeader(http.StatusOK)
	})
	expiredRequest := httptest.NewRequest(http.MethodPost, "http://localhost:3000/mcp", nil)
	expiredRequest.Header.Set("Authorization", "Bearer expired-access-token")
	expiredRecorder := httptest.NewRecorder()
	protected.ServeHTTP(expiredRecorder, expiredRequest)
	if expiredRecorder.Code != http.StatusUnauthorized || called.Load() {
		t.Fatalf("expired status=%d called=%v", expiredRecorder.Code, called.Load())
	}
	wantChallenge := `Bearer resource_metadata="http://localhost:3000/api/auth/.well-known/oauth-protected-resource"`
	if expiredRecorder.Header().Get("WWW-Authenticate") != wantChallenge ||
		expiredRecorder.Header().Get("Access-Control-Expose-Headers") != "WWW-Authenticate" {
		t.Fatalf("headers=%#v", expiredRecorder.Header())
	}
	liveRequest := httptest.NewRequest(http.MethodPost, "http://localhost:3000/mcp", nil)
	liveRequest.Header.Set("Authorization", "Bearer live-access-token")
	liveRecorder := httptest.NewRecorder()
	protected.ServeHTTP(liveRecorder, liveRequest)
	if liveRecorder.Code != http.StatusOK || !called.Load() {
		t.Fatalf("live status=%d called=%v", liveRecorder.Code, called.Load())
	}
}

func TestAuthorizationCodeIsAtomicallySingleUse(t *testing.T) {
	harness := newHarness(t, func(options *Options) {
		options.OIDCConfig.RequirePKCE = false
	})
	userID, _ := harness.signUp(t, 40)
	seedClient(t, harness, "race-client", "race-secret", "web", false)
	seedCode(t, harness, "race-authorization-code", codeVerificationValue{
		ClientID: "race-client", RedirectURI: "http://localhost/callback",
		Scope: []string{"openid", "offline_access"}, UserID: userID,
	})

	start := make(chan struct{})
	type outcome struct {
		resultStatus int
		err          error
		body         map[string]any
	}
	outcomes := make(chan outcome, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := harness.auth.API().Call(t.Context(), "mcpOAuthToken", singleauth.DirectCallInput{
				Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
				Body: map[string]any{
					"grant_type": "authorization_code", "client_id": "race-client",
					"client_secret": "race-secret", "code": "race-authorization-code",
					"redirect_uri": "http://localhost/callback",
				},
			})
			object, _ := result.Value.(map[string]any)
			outcomes <- outcome{resultStatus: result.Response.Status(), err: err, body: object}
		}()
	}
	close(start)
	wait.Wait()
	close(outcomes)
	successes, failures := 0, 0
	for result := range outcomes {
		if result.err == nil && result.resultStatus == http.StatusOK && result.body["access_token"] != nil {
			successes++
			continue
		}
		if result.err != nil && result.resultStatus == http.StatusUnauthorized && result.body["error"] == "invalid_grant" {
			failures++
			continue
		}
		t.Fatalf("unexpected result=%#v", result)
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes=%d failures=%d", successes, failures)
	}
	rows, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "clientId", Value: "race-client"}},
	})
	if err != nil || len(rows) != 1 {
		t.Fatalf("tokens=%#v err=%v", rows, err)
	}
}
