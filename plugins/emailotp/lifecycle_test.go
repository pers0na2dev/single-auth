package emailotp

import (
	"context"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestSendVerificationOTPMatchesNormalizationAndEnumerationBehavior(t *testing.T) {
	harness := newEmailOTPHarness(t, nil)
	harness.seedUser(t, "known-user", "known@example.com", false)

	response, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "KNOWN@EXAMPLE.COM", "type": "email-verification",
	})
	if err != nil || response.Status() != contract.StatusOK {
		t.Fatalf("send known: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	message := harness.latestMessage(t)
	if message.Email != "known@example.com" || message.Type != TypeEmailVerification || len(message.OTP) != 6 {
		t.Fatalf("unexpected normalized message: %#v", message)
	}

	response, err = harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "missing@example.com", "type": "email-verification",
	})
	if err != nil || response.Status() != contract.StatusOK || harness.messageCount() != 1 {
		t.Fatalf("missing-user response must not reveal existence: status=%d err=%v sends=%d", response.Status(), err, harness.messageCount())
	}
	missing, findErr := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: Identifier(TypeEmailVerification, "missing@example.com")}},
	})
	if findErr != nil || missing != nil {
		t.Fatalf("missing-user OTP must be removed: row=%v err=%v", missing, findErr)
	}

	response, err = harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "new@example.com", "type": "sign-in",
	})
	if err != nil || response.Status() != contract.StatusOK || harness.messageCount() != 2 {
		t.Fatalf("sign-up-enabled sign-in OTP: status=%d err=%v sends=%d", response.Status(), err, harness.messageCount())
	}

	invalid, invalidErr := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "not-an-email", "type": "sign-in",
	})
	if invalidErr == nil || invalid.Status() != contract.StatusBadRequest || responseCode(t, invalid) != "INVALID_EMAIL" {
		t.Fatalf("invalid email: status=%d err=%v body=%s", invalid.Status(), invalidErr, invalid.Body())
	}
	change, changeErr := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "known@example.com", "type": "change-email",
	})
	if changeErr == nil || change.Status() != contract.StatusBadRequest || responseObject(t, change)["message"] != "Invalid OTP type" {
		t.Fatalf("change-email must use dedicated endpoint: status=%d err=%v body=%s", change.Status(), changeErr, change.Body())
	}

	disabled := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) { options.DisableSignUp = true })
	response, err = disabled.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "missing@example.com", "type": "sign-in",
	})
	if err != nil || response.Status() != contract.StatusOK || disabled.messageCount() != 0 {
		t.Fatalf("disabled signup must retain enumeration resistance: status=%d err=%v sends=%d", response.Status(), err, disabled.messageCount())
	}
}

func TestSendVerificationOTPCSRFMatchesFormMiddleware(t *testing.T) {
	harness := newEmailOTPHarness(t, nil)
	harness.seedUser(t, "csrf-user", "csrf@example.com", true)
	body := map[string]any{"email": "csrf@example.com", "type": "sign-in"}

	cookieOnly := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: "session=value"})
	response, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, cookieOnly, body)
	if err == nil || response.Status() != contract.StatusForbidden || responseCode(t, response) != "MISSING_OR_NULL_ORIGIN" {
		t.Fatalf("cookie request without origin: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	crossSite := contract.NewHeaders(
		contract.HeaderField{Name: "Sec-Fetch-Site", Value: "cross-site"},
		contract.HeaderField{Name: "Sec-Fetch-Mode", Value: "navigate"},
	)
	response, err = harness.call(t, "POST", "/email-otp/send-verification-otp", nil, crossSite, body)
	if err == nil || responseCode(t, response) != "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED" {
		t.Fatalf("cross-site navigation: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	evil := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "https://evil.example"})
	response, err = harness.call(t, "POST", "/email-otp/send-verification-otp", nil, evil, body)
	if err == nil || responseCode(t, response) != "INVALID_ORIGIN" {
		t.Fatalf("invalid origin: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	sameOrigin := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
	response, err = harness.call(t, "POST", "/email-otp/send-verification-otp", nil, sameOrigin, body)
	if err != nil || response.Status() != contract.StatusOK {
		t.Fatalf("same origin: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
}

func TestCheckVerificationOTPAttemptsAndNonConsumingSuccess(t *testing.T) {
	harness := newEmailOTPHarness(t, nil)
	harness.seedUser(t, "attempt-user", "attempt@example.com", false)
	_, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "attempt@example.com", "type": "email-verification",
	})
	if err != nil {
		t.Fatal(err)
	}
	validOTP := harness.latestMessage(t).OTP
	wrongOTP := "000000"
	if wrongOTP == validOTP {
		wrongOTP = "999999"
	}
	for attempt := 1; attempt <= 3; attempt++ {
		response, callErr := harness.call(t, "POST", "/email-otp/check-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "attempt@example.com", "type": "email-verification", "otp": wrongOTP,
		})
		if callErr == nil || responseCode(t, response) != ErrorInvalidOTP {
			t.Fatalf("wrong attempt %d: status=%d err=%v body=%s", attempt, response.Status(), callErr, response.Body())
		}
	}
	locked, callErr := harness.call(t, "POST", "/email-otp/check-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "attempt@example.com", "type": "email-verification", "otp": wrongOTP,
	})
	if callErr == nil || locked.Status() != contract.StatusForbidden || responseCode(t, locked) != ErrorTooManyAttempts {
		t.Fatalf("lockout: status=%d err=%v body=%s", locked.Status(), callErr, locked.Body())
	}

	harness.seedUser(t, "check-user", "check@example.com", false)
	_, err = harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "check@example.com", "type": "email-verification",
	})
	if err != nil {
		t.Fatal(err)
	}
	validOTP = harness.latestMessage(t).OTP
	checked, checkErr := harness.call(t, "POST", "/email-otp/check-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "check@example.com", "type": "email-verification", "otp": validOTP,
	})
	if checkErr != nil || responseObject(t, checked)["success"] != true {
		t.Fatalf("valid check: status=%d err=%v body=%s", checked.Status(), checkErr, checked.Body())
	}
	verified, verifyErr := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
		"email": "check@example.com", "otp": validOTP,
	})
	if verifyErr != nil || responseObject(t, verified)["status"] != true {
		t.Fatalf("check must not consume: status=%d err=%v body=%s", verified.Status(), verifyErr, verified.Body())
	}
}

func TestOTPExpiryAndSingleUseUnderConcurrency(t *testing.T) {
	harness := newEmailOTPHarness(t, nil)
	harness.seedUser(t, "expired-user", "expired@example.com", false)
	_, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "expired@example.com", "type": "email-verification",
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredOTP := harness.latestMessage(t).OTP
	harness.clock.Advance(6 * time.Minute)
	expired, expiredErr := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
		"email": "expired@example.com", "otp": expiredOTP,
	})
	if expiredErr == nil || responseCode(t, expired) != ErrorOTPExpired {
		t.Fatalf("expired OTP: status=%d err=%v body=%s", expired.Status(), expiredErr, expired.Body())
	}

	_, err = harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "race@example.com", "type": "sign-in",
	})
	if err != nil {
		t.Fatal(err)
	}
	raceOTP := harness.latestMessage(t).OTP
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
			response, callErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
				"email": "race@example.com", "otp": raceOTP,
			})
			results <- result{response: response, err: callErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	failures := 0
	for result := range results {
		if result.err == nil {
			successes++
			if responseObject(t, result.response)["token"] == "" {
				t.Fatal("successful sign in has no token")
			}
		} else {
			failures++
			if responseCode(t, result.response) != ErrorInvalidOTP {
				t.Fatalf("racing failure code: %s", result.response.Body())
			}
		}
	}
	if successes != 1 || failures != 1 || harness.issuedSessions.Load() != 1 {
		t.Fatalf("single-use gate: successes=%d failures=%d sessions=%d", successes, failures, harness.issuedSessions.Load())
	}
}

func TestAtomicVerificationPreservesWrongAttemptsThenLocksPermanently(t *testing.T) {
	harness := newEmailOTPHarness(t, nil)
	_, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "wrong-attempts@example.com", "type": "sign-in",
	})
	if err != nil {
		t.Fatal(err)
	}
	validOTP := harness.latestMessage(t).OTP
	wrongOTP := "999999"
	if wrongOTP == validOTP {
		wrongOTP = "000000"
	}
	for attempt := 1; attempt <= 3; attempt++ {
		response, callErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
			"email": "wrong-attempts@example.com", "otp": wrongOTP,
		})
		if callErr == nil || responseCode(t, response) != ErrorInvalidOTP {
			t.Fatalf("wrong atomic attempt %d: err=%v body=%s", attempt, callErr, response.Body())
		}
		record, findErr := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: Identifier(TypeSignIn, "wrong-attempts@example.com")}},
		})
		if findErr != nil || record == nil {
			t.Fatalf("attempt %d burned OTP: row=%v err=%v", attempt, record, findErr)
		}
		_, attempts := SplitStoredValue(record["value"].(string))
		if attempts != strconv.Itoa(attempt) {
			t.Fatalf("attempt suffix %d: %q", attempt, attempts)
		}
	}
	locked, lockedErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
		"email": "wrong-attempts@example.com", "otp": validOTP,
	})
	if lockedErr == nil || responseCode(t, locked) != ErrorTooManyAttempts {
		t.Fatalf("attempt budget: err=%v body=%s", lockedErr, locked.Body())
	}
	replay, replayErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
		"email": "wrong-attempts@example.com", "otp": validOTP,
	})
	if replayErr == nil || responseCode(t, replay) != ErrorInvalidOTP {
		t.Fatalf("lockout replay: err=%v body=%s", replayErr, replay.Body())
	}
}

func TestPasswordResetCreatesCredentialVerifiesUserAndRevokesSessions(t *testing.T) {
	var resets atomic.Int64
	harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
		options.Password.Hash = func(value string) (string, error) { return "hashed:" + value, nil }
		options.Password.RevokeSessions = true
		options.Password.OnReset = func(context.Context, *engine.Context, storage.Record) error {
			resets.Add(1)
			return nil
		}
	})
	user := harness.seedUser(t, "reset-user", "reset@example.com", false)
	_, err := harness.adapter.Create(context.Background(), storage.CreateParams{
		Model: "session", Data: storage.Record{
			"userId": user["id"], "token": "old-token", "expiresAt": harness.clock.Now().Add(time.Hour),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.call(t, "POST", "/email-otp/request-password-reset", nil, emptyHeaders(), map[string]any{"email": "RESET@EXAMPLE.COM"})
	if err != nil {
		t.Fatal(err)
	}
	otp := harness.latestMessage(t).OTP
	response, err := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
		"email": "reset@example.com", "otp": otp, "password": "changed-password",
	})
	if err != nil || responseObject(t, response)["success"] != true {
		t.Fatalf("reset: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	account, err := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: "reset-user"}},
	})
	if err != nil || account == nil || account["password"] != "hashed:changed-password" {
		t.Fatalf("credential account: row=%v err=%v", account, err)
	}
	updated, _ := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "reset-user"}},
	})
	verified, _ := recordBool(updated, "emailVerified")
	sessions, _ := harness.adapter.Count(context.Background(), storage.CountParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: "reset-user"}},
	})
	if !verified || sessions != 0 || resets.Load() != 1 {
		t.Fatalf("reset side effects: verified=%v sessions=%d callbacks=%d", verified, sessions, resets.Load())
	}
}

func TestChangeEmailWithCurrentVerificationAndSessionRefresh(t *testing.T) {
	harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
		options.ChangeEmail = ChangeEmailOptions{Enabled: true, VerifyCurrentEmail: true}
	})
	harness.seedUser(t, "change-user", "old@example.com", true)
	headers := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "change-user"})
	_, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "old@example.com", "type": "email-verification",
	})
	if err != nil {
		t.Fatal(err)
	}
	currentOTP := harness.latestMessage(t).OTP
	response, err := harness.call(t, "POST", "/email-otp/request-email-change", nil, headers, map[string]any{
		"newEmail": "NEW@EXAMPLE.COM", "otp": currentOTP,
	})
	if err != nil || responseObject(t, response)["success"] != true {
		t.Fatalf("request change: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	changeMessage := harness.latestMessage(t)
	if changeMessage.Email != "new@example.com" || changeMessage.Type != TypeChangeEmail {
		t.Fatalf("change message: %#v", changeMessage)
	}
	response, err = harness.call(t, "POST", "/email-otp/change-email", nil, headers, map[string]any{
		"newEmail": "new@example.com", "otp": changeMessage.OTP,
	})
	if err != nil || responseObject(t, response)["success"] != true {
		t.Fatalf("change email: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	updated, _ := harness.adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "change-user"}},
	})
	if updated["email"] != "new@example.com" {
		t.Fatalf("email not updated: %#v", updated)
	}
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if len(harness.refreshed) != 1 || harness.refreshed[0].User["email"] != "new@example.com" {
		t.Fatalf("session refresh mismatch: %#v", harness.refreshed)
	}
}

func TestResendReuseAndServerOnlyGet(t *testing.T) {
	harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
		options.ResendStrategy = ResendReuse
	})
	harness.seedUser(t, "reuse-user", "reuse@example.com", true)
	for range 2 {
		_, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "reuse@example.com", "type": "email-verification",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	harness.mu.Lock()
	first, second := harness.messages[0], harness.messages[1]
	harness.mu.Unlock()
	if first.OTP != second.OTP || harness.generated.Load() != 1 {
		t.Fatalf("reused OTP mismatch: first=%q second=%q generated=%d", first.OTP, second.OTP, harness.generated.Load())
	}
	request := contract.NewRequest("GET", "/", contract.RequestOptions{
		Context: context.Background(), RawQuery: url.Values{
			"email": {"REUSE@EXAMPLE.COM"}, "type": {"email-verification"},
		}.Encode(),
	})
	response, err := harness.dispatcher.Invoke("getVerificationOTP", engine.DirectInput{Request: request})
	if err != nil || responseObject(t, response)["otp"] != first.OTP {
		t.Fatalf("server-only get: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}

	hashed := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
		options.Storage.Mode = StoreHashed
	})
	hashed.seedUser(t, "hashed-user", "hashed@example.com", true)
	_, err = hashed.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": "hashed@example.com", "type": "email-verification",
	})
	if err != nil {
		t.Fatal(err)
	}
	hashedRequest := contract.NewRequest("GET", "/", contract.RequestOptions{RawQuery: url.Values{
		"email": {"hashed@example.com"}, "type": {"email-verification"},
	}.Encode()})
	response, err = hashed.dispatcher.Invoke("getVerificationOTP", engine.DirectInput{Request: hashedRequest})
	if err == nil || response.Status() != contract.StatusBadRequest || responseObject(t, response)["message"] != "OTP is hashed, cannot return the plain text OTP" {
		t.Fatalf("hashed get: status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
}
