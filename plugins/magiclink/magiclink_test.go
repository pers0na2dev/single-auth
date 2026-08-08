package magiclink

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDescriptorAndSendMagicLinkFrozenOracle(t *testing.T) {
	harness := newMagicLinkHarness(t, nil)
	descriptor := harness.descriptor
	if descriptor.ID != "magic-link" || descriptor.Version != Version || len(descriptor.Endpoints) != 2 || len(descriptor.RateLimit) != 1 {
		t.Fatalf("descriptor: id=%q version=%q endpoints=%d rate=%d", descriptor.ID, descriptor.Version, len(descriptor.Endpoints), len(descriptor.RateLimit))
	}
	rule := descriptor.RateLimit[0]
	if rule.Rule.Window != 60 || rule.Rule.Max != 5 || !rule.Match("/sign-in/magic-link/child") || !rule.Match("/magic-link/verify-extra") || rule.Match("/magic-link") {
		t.Fatalf("rate rule mismatch: %#v", rule.Rule)
	}

	response, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{
		"email":              "user@example.com",
		"name":               "Alice <Admin>",
		"callbackURL":        "/dashboard",
		"newUserCallbackURL": "/welcome",
		"errorCallbackURL":   "/error",
		"metadata":           map[string]any{"inviteId": "123"},
	})
	if err != nil || response.Status() != contract.StatusOK || responseObject(t, response)["status"] != true {
		t.Fatalf("send: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	message := harness.latestMessage(t)
	wantURL := "http://localhost:3000/api/auth/magic-link/verify?token=" + message.Token + "&callbackURL=%2Fdashboard&newUserCallbackURL=%2Fwelcome&errorCallbackURL=%2Ferror"
	if message.URL != wantURL || message.Email != "user@example.com" || message.Metadata["inviteId"] != "123" {
		t.Fatalf("message mismatch:\nwant %s\n got %#v", wantURL, message)
	}
	record, findErr := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: message.Token}},
	})
	if findErr != nil || record == nil {
		t.Fatalf("verification row: %v %v", record, findErr)
	}
	if record["value"] != `{"email":"user@example.com","name":"Alice <Admin>"}` {
		t.Fatalf("frozen JSON value: %q", record["value"])
	}
	expiresAt, _ := recordTime(record, "expiresAt")
	if !expiresAt.Equal(harness.clock.Now().Add(5 * time.Minute)) {
		t.Fatalf("expiry: %s", expiresAt)
	}
}

func TestVerifyReturnsSessionAndRejectsReplayAndExpiry(t *testing.T) {
	harness := newMagicLinkHarness(t, nil)
	harness.seedUser(t, "existing-user", "existing@example.com", "Existing", true)
	_, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{"email": "existing@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token := harness.latestMessage(t).Token
	response, err := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
	if err != nil || response.Status() != contract.StatusOK {
		t.Fatalf("verify: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	payload := responseObject(t, response)
	if payload["token"] != "session-token-1" || payload["user"] == nil || payload["session"] == nil || len(response.Headers().Values("Set-Cookie")) != 1 {
		t.Fatalf("session response: %#v headers=%#v", payload, response.Headers().Fields())
	}
	replay, replayErr := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
	if replayErr != nil || replay.Status() != contract.StatusFound || location(replay) != "http://localhost:3000/?error=INVALID_TOKEN" {
		t.Fatalf("replay: status=%d err=%v location=%q", replay.Status(), replayErr, location(replay))
	}

	_, err = harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{"email": "existing@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	expiredToken := harness.latestMessage(t).Token
	harness.clock.Advance(5*time.Minute + time.Nanosecond)
	expired, expiredErr := harness.call(t, "GET", "/magic-link/verify", url.Values{
		"token": {expiredToken}, "callbackURL": {"/callback"},
	}, emptyHeaders(), nil)
	if expiredErr != nil || expired.Status() != contract.StatusFound || location(expired) != "http://localhost:3000/callback?error=INVALID_TOKEN" {
		t.Fatalf("expired: status=%d err=%v location=%q", expired.Status(), expiredErr, location(expired))
	}
}

func TestSignupRedirectsAndDisableSignupRemainsEnumerationSafe(t *testing.T) {
	harness := newMagicLinkHarness(t, nil)
	_, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{
		"email": "NEW@EXAMPLE.COM", "name": "New User", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome",
	})
	if err != nil {
		t.Fatal(err)
	}
	message := harness.latestMessage(t)
	response, err := harness.call(t, "GET", "/magic-link/verify", url.Values{
		"token": {message.Token}, "callbackURL": {"/dashboard"}, "newUserCallbackURL": {"/welcome"},
	}, emptyHeaders(), nil)
	if err != nil || response.Status() != contract.StatusFound || location(response) != "http://localhost:3000/welcome" {
		t.Fatalf("new user redirect: status=%d err=%v location=%q", response.Status(), err, location(response))
	}
	created, _ := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "new@example.com"}},
	})
	verified, _ := recordBool(created, "emailVerified")
	if created == nil || created["name"] != "New User" || !verified {
		t.Fatalf("created user: %#v", created)
	}

	disabled := newMagicLinkHarness(t, func(options *Options, _ *magicLinkHarness) { options.DisableSignUp = true })
	response, err = disabled.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{
		"email": "missing@example.com", "errorCallbackURL": "/error?from=link",
	})
	if err != nil || response.Status() != contract.StatusOK || disabled.messageCount() != 1 {
		t.Fatalf("enumeration-safe send: status=%d err=%v sends=%d", response.Status(), err, disabled.messageCount())
	}
	disabledToken := disabled.latestMessage(t).Token
	rejected, rejectedErr := disabled.call(t, "GET", "/magic-link/verify", url.Values{
		"token": {disabledToken}, "errorCallbackURL": {"/error?from=link"},
	}, emptyHeaders(), nil)
	if rejectedErr != nil || rejected.Status() != contract.StatusFound {
		t.Fatalf("disabled signup: status=%d err=%v", rejected.Status(), rejectedErr)
	}
	rejectedURL, parseErr := url.Parse(location(rejected))
	if parseErr != nil || rejectedURL.Query().Get("from") != "link" || rejectedURL.Query().Get("error") != "new_user_signup_disabled" {
		t.Fatalf("disabled redirect: %q", location(rejected))
	}
	replay, _ := disabled.call(t, "GET", "/magic-link/verify", url.Values{"token": {disabledToken}}, emptyHeaders(), nil)
	if !strings.Contains(location(replay), "error=INVALID_TOKEN") {
		t.Fatalf("disabled branch did not burn token: %q", location(replay))
	}
}

func TestUnverifiedUserLosesUnprovenCredentialsAndSessions(t *testing.T) {
	harness := newMagicLinkHarness(t, nil)
	harness.seedUser(t, "unverified-user", "unverified@example.com", "User", false)
	_, err := harness.adapter.Create(context.Background(), storage.CreateParams{
		Model: "account", Data: storage.Record{
			"userId": "unverified-user", "providerId": "credential", "accountId": "unverified-user", "password": "unproven",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.adapter.Create(context.Background(), storage.CreateParams{
		Model: "session", Data: storage.Record{
			"userId": "unverified-user", "token": "old-session", "expiresAt": harness.clock.Now().Add(time.Hour),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{"email": "unverified@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token := harness.latestMessage(t).Token
	response, err := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
	if err != nil || response.Status() != contract.StatusOK {
		t.Fatalf("verify unverified user: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	responseUser, _ := responseObject(t, response)["user"].(map[string]any)
	if responseUser["emailVerified"] != true {
		t.Fatalf("verified response user = %#v", responseUser)
	}
	user, _ := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "unverified-user"}},
	})
	verified, _ := recordBool(user, "emailVerified")
	credential, _ := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: "unverified-user"}},
	})
	sessions, _ := harness.adapter.Count(context.Background(), storage.CountParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: "unverified-user"}},
	})
	if !verified || credential != nil || sessions != 1 {
		t.Fatalf("adoption state: verified=%v credential=%v sessions=%d", verified, credential, sessions)
	}
}

func TestTokenStorageModesAndHashOracle(t *testing.T) {
	const hashVector = "xGlf7c5SjYo0ExV5OqJWrF4pywn5Ls3Rzg0VjRgkom4"
	if got := defaultTokenHash("custom_token"); got != hashVector {
		t.Fatalf("SHA-256 base64url oracle: want %q got %q", hashVector, got)
	}
	for _, test := range []struct {
		name      string
		configure func(*Options, *magicLinkHarness)
		stored    func(string) string
	}{
		{name: "hashed", configure: func(options *Options, _ *magicLinkHarness) { options.Storage.Mode = StoreHashed }, stored: defaultTokenHash},
		{name: "custom", configure: func(options *Options, _ *magicLinkHarness) {
			options.Storage.CustomHash = func(_ context.Context, token string) (string, error) { return token + "hashed", nil }
		}, stored: func(token string) string { return token + "hashed" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newMagicLinkHarness(t, test.configure)
			harness.seedUser(t, "store-user", "store@example.com", "Store", true)
			_, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{"email": "store@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			token := harness.latestMessage(t).Token
			record, findErr := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
				Model: "verification", Where: []storage.Where{{Field: "identifier", Value: test.stored(token)}},
			})
			if findErr != nil || record == nil {
				t.Fatalf("stored identifier: row=%v err=%v", record, findErr)
			}
			response, verifyErr := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
			if verifyErr != nil || response.Status() != contract.StatusOK {
				t.Fatalf("verify stored token: status=%d err=%v body=%s", response.Status(), verifyErr, response.Body())
			}
		})
	}
}

func TestMagicLinkSingleUseUnderConcurrentVerification(t *testing.T) {
	harness := newMagicLinkHarness(t, nil)
	harness.seedUser(t, "race-user", "race@example.com", "Race", true)
	_, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{"email": "race@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token := harness.latestMessage(t).Token
	start := make(chan struct{})
	type result struct {
		response contract.Response
		err      error
	}
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response, callErr := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
			results <- result{response: response, err: callErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, redirects := 0, 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent verify returned error: %v", result.err)
		}
		switch result.response.Status() {
		case contract.StatusOK:
			successes++
		case contract.StatusFound:
			redirects++
			if !strings.Contains(location(result.response), "INVALID_TOKEN") {
				t.Fatalf("racing redirect: %q", location(result.response))
			}
		}
	}
	if successes != 1 || redirects != 1 || harness.issued.Load() != 1 {
		t.Fatalf("single use: successes=%d redirects=%d sessions=%d", successes, redirects, harness.issued.Load())
	}
}

func TestDeprecatedAllowedAttemptsNeverAllowsReplay(t *testing.T) {
	for _, attempts := range []*float64{nil, Float64(3), Float64(math.Inf(1))} {
		name := "default"
		if attempts != nil {
			name = fmt.Sprintf("configured-%v", *attempts)
		}
		t.Run(name, func(t *testing.T) {
			harness := newMagicLinkHarness(t, func(options *Options, _ *magicLinkHarness) {
				options.AllowedAttempts = attempts
			})
			harness.seedUser(t, "attempt-user", "attempt@example.com", "Attempt", true)
			if _, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{
				"email": "attempt@example.com",
			}); err != nil {
				t.Fatal(err)
			}
			token := harness.latestMessage(t).Token
			first, err := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
			if err != nil || first.Status() != contract.StatusOK || responseObject(t, first)["token"] == nil {
				t.Fatalf("first verify status=%d err=%v body=%s", first.Status(), err, first.Body())
			}
			second, err := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
			if err != nil || second.Status() != contract.StatusFound || !strings.Contains(location(second), "error=INVALID_TOKEN") {
				t.Fatalf("replay status=%d err=%v location=%q", second.Status(), err, location(second))
			}
		})
	}
}

func TestLatestOfSeveralMagicLinksVerifies(t *testing.T) {
	harness := newMagicLinkHarness(t, nil)
	harness.seedUser(t, "latest-user", "latest@example.com", "Latest", true)
	for range 3 {
		if _, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{
			"email": "latest@example.com",
		}); err != nil {
			t.Fatal(err)
		}
	}
	last := harness.latestMessage(t)
	response, err := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {last.Token}}, emptyHeaders(), nil)
	if err != nil || response.Status() != contract.StatusOK || responseObject(t, response)["token"] == nil {
		t.Fatalf("latest verify status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
}

func TestCustomGenerateTokenIsUsedVerbatim(t *testing.T) {
	var calls atomic.Int64
	harness := newMagicLinkHarness(t, func(options *Options, _ *magicLinkHarness) {
		options.GenerateToken = func(context.Context, string) (string, error) {
			calls.Add(1)
			return "custom_token", nil
		}
	})
	if _, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{
		"email": "custom-token@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	message := harness.latestMessage(t)
	if calls.Load() != 1 || message.Token != "custom_token" || !strings.Contains(message.URL, "token=custom_token") {
		t.Fatalf("generator calls=%d message=%#v", calls.Load(), message)
	}
}

func TestFailedSessionAndDeprecatedAttemptsStillBurnToken(t *testing.T) {
	var warnings atomic.Int64
	harness := newMagicLinkHarness(t, func(options *Options, _ *magicLinkHarness) {
		options.AllowedAttempts = Float64(math.Inf(1))
		options.Runtime.Warn = func(message string) {
			if message == warningAttempts {
				warnings.Add(1)
			}
		}
		options.Runtime.IssueSession = func(*engine.Context, storage.Record) (*SessionState, error) { return nil, nil }
	})
	harness.seedUser(t, "failure-user", "failure@example.com", "Failure", true)
	_, err := harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{"email": "failure@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token := harness.latestMessage(t).Token
	failed, failedErr := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
	if failedErr != nil || !strings.Contains(location(failed), "failed_to_create_session") || warnings.Load() != 1 {
		t.Fatalf("failed session: err=%v location=%q warnings=%d", failedErr, location(failed), warnings.Load())
	}
	replay, _ := harness.call(t, "GET", "/magic-link/verify", url.Values{"token": {token}}, emptyHeaders(), nil)
	if !strings.Contains(location(replay), "INVALID_TOKEN") {
		t.Fatalf("failed session did not burn token: %q", location(replay))
	}
}

func TestMagicLinkOriginAndFormCSRFProtection(t *testing.T) {
	harness := newMagicLinkHarness(t, nil)
	body := map[string]any{"email": "csrf@example.com"}
	crossSite := contract.NewHeaders(
		contract.HeaderField{Name: "Sec-Fetch-Site", Value: "cross-site"},
		contract.HeaderField{Name: "Sec-Fetch-Mode", Value: "navigate"},
	)
	response, err := harness.call(t, "POST", "/sign-in/magic-link", nil, crossSite, body)
	if err == nil || responseCode(t, response) != "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED" || harness.messageCount() != 0 {
		t.Fatalf("cross-site form: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	evil := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "https://evil.example"})
	response, err = harness.call(t, "POST", "/sign-in/magic-link", nil, evil, body)
	if err == nil || responseCode(t, response) != "INVALID_ORIGIN" {
		t.Fatalf("evil origin: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	response, err = harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), map[string]any{
		"email": "csrf@example.com", "callbackURL": "https://evil.example/steal",
	})
	if err == nil || responseCode(t, response) != "INVALID_CALLBACK_URL" {
		t.Fatalf("evil send callback: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	response, err = harness.call(t, "GET", "/magic-link/verify", url.Values{
		"token": {"invalid"}, "callbackURL": {"http://malicious.com"},
	}, emptyHeaders(), nil)
	if err == nil || response.Status() != contract.StatusForbidden || responseCode(t, response) != "INVALID_CALLBACK_URL" {
		t.Fatalf("evil verify callback: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	response, err = harness.call(t, "POST", "/sign-in/magic-link", nil, emptyHeaders(), body)
	if err != nil || response.Status() != contract.StatusOK || harness.messageCount() != 1 {
		t.Fatalf("server-to-server send: status=%d err=%v sends=%d", response.Status(), err, harness.messageCount())
	}
}
