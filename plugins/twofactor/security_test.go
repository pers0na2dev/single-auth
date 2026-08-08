package twofactor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/magiclink"
	"github.com/pers0na2dev/single-auth/plugins/phonenumber"
	"github.com/pers0na2dev/single-auth/plugins/username"
	"github.com/pers0na2dev/single-auth/storage"
)

func wrongTOTP(correct string) string {
	if correct == "000000" {
		return "111111"
	}
	return "000000"
}

func TestAccountLockoutAcrossChallengesAndFactors(t *testing.T) {
	t.Run("across challenges", func(t *testing.T) {
		h := setupEnrolled(t, Options{AccountLockout: AccountLockoutOptions{MaxFailedAttempts: 3}}, nil)
		wrong := wrongTOTP(h.currentTOTP(t))
		for index := 0; index < 3; index++ {
			failed := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": wrong})
			if failed.status != http.StatusUnauthorized || errorCode(failed) != CodeInvalidCode {
				t.Fatalf("failure %d=%d %#v", index, failed.status, failed.body)
			}
		}
		locked := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": h.currentTOTP(t)})
		if locked.status != http.StatusTooManyRequests || errorCode(locked) != CodeAccountTemporarilyLocked {
			t.Fatalf("locked=%d %#v", locked.status, locked.body)
		}
	})

	t.Run("across TOTP backup and OTP", func(t *testing.T) {
		capture := &otpCapture{}
		h := setupEnrolled(t, Options{
			OTP:            OTPOptions{SendOTP: capture.send},
			AccountLockout: AccountLockoutOptions{MaxFailedAttempts: 3},
		}, nil)
		wrong := wrongTOTP(h.currentTOTP(t))
		totp := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": wrong})
		if totp.status != http.StatusUnauthorized {
			t.Fatalf("TOTP=%d %#v", totp.status, totp.body)
		}
		backup := invoke(t, h.auth, "verifyBackupCode", http.MethodPost, "/two-factor/verify-backup-code", h.challenge(t).cookie, map[string]any{"code": "wrong-backup"})
		if backup.status != http.StatusUnauthorized {
			t.Fatalf("backup=%d %#v", backup.status, backup.body)
		}
		challenge := h.challenge(t)
		_ = invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
		otp := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": "wrong"})
		if otp.status != http.StatusUnauthorized {
			t.Fatalf("OTP=%d %#v", otp.status, otp.body)
		}
		locked := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": h.currentTOTP(t)})
		if locked.status != http.StatusTooManyRequests {
			t.Fatalf("cross-factor lock=%d %#v", locked.status, locked.body)
		}
	})

	t.Run("success resets counter", func(t *testing.T) {
		h := setupEnrolled(t, Options{AccountLockout: AccountLockoutOptions{MaxFailedAttempts: 3}}, nil)
		wrong := wrongTOTP(h.currentTOTP(t))
		for range 2 {
			_ = invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": wrong})
		}
		ok := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": h.currentTOTP(t)})
		if ok.status != http.StatusOK {
			t.Fatalf("reset success=%d %#v", ok.status, ok.body)
		}
		for range 2 {
			_ = invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": wrong})
		}
		stillOpen := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": h.currentTOTP(t)})
		if stillOpen.status != http.StatusOK {
			t.Fatalf("counter did not reset=%d %#v", stillOpen.status, stillOpen.body)
		}
	})

	t.Run("expired lock is released", func(t *testing.T) {
		h := setupEnrolled(t, Options{AccountLockout: AccountLockoutOptions{MaxFailedAttempts: 1}}, nil)
		_ = invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": wrongTOTP(h.currentTOTP(t))})
		updateTwoFactor(t, h.auth, storage.Record{"lockedUntil": h.clock.Now().Add(-time.Second)})
		ok := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": h.currentTOTP(t)})
		if ok.status != http.StatusOK {
			t.Fatalf("released=%d %#v", ok.status, ok.body)
		}
	})

	t.Run("disabled lockout", func(t *testing.T) {
		disabled := false
		h := setupEnrolled(t, Options{AccountLockout: AccountLockoutOptions{Enabled: &disabled, MaxFailedAttempts: 1}}, nil)
		for range 5 {
			_ = invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": wrongTOTP(h.currentTOTP(t))})
		}
		ok := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": h.currentTOTP(t)})
		if ok.status != http.StatusOK {
			t.Fatalf("disabled lockout=%d %#v", ok.status, ok.body)
		}
	})

	t.Run("null legacy counter starts at one", func(t *testing.T) {
		h := setupEnrolled(t, Options{AccountLockout: AccountLockoutOptions{MaxFailedAttempts: 3}}, nil)
		updateTwoFactor(t, h.auth, storage.Record{"failedVerificationCount": nil})
		failed := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": wrongTOTP(h.currentTOTP(t))})
		if failed.status != http.StatusUnauthorized {
			t.Fatalf("legacy first failure=%d %#v", failed.status, failed.body)
		}
		row := twoFactorRow(t, h.auth)
		if recordInt(row, "failedVerificationCount") != 1 {
			t.Fatalf("legacy count=%#v", row["failedVerificationCount"])
		}
		ok := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.challenge(t).cookie, map[string]any{"code": h.currentTOTP(t)})
		if ok.status != http.StatusOK {
			t.Fatalf("legacy open=%d %#v", ok.status, ok.body)
		}
	})
}

func TestPerChallengeAttemptCapsAndServerErrorRestore(t *testing.T) {
	t.Run("TOTP sequential cap cancels challenge", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		challenge := h.challenge(t)
		wrong := wrongTOTP(h.currentTOTP(t))
		for index := 0; index < DefaultAllowedAttempts; index++ {
			failed := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": wrong})
			if failed.status != http.StatusUnauthorized || errorCode(failed) != CodeInvalidCode {
				t.Fatalf("failure %d=%d %#v", index, failed.status, failed.body)
			}
		}
		locked := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": h.currentTOTP(t)})
		if locked.status != http.StatusBadRequest || errorCode(locked) != CodeTooManyAttempts {
			t.Fatalf("locked=%d %#v", locked.status, locked.body)
		}
		after := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": wrong})
		if after.status != http.StatusUnauthorized || errorCode(after) != CodeInvalidTwoFactorCookie {
			t.Fatalf("after cancel=%d %#v", after.status, after.body)
		}
	})

	t.Run("backup sequential cap", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		challenge := h.challenge(t)
		for index := 0; index < DefaultAllowedAttempts; index++ {
			failed := invoke(t, h.auth, "verifyBackupCode", http.MethodPost, "/two-factor/verify-backup-code", challenge.cookie, map[string]any{"code": "wrong"})
			if failed.status != http.StatusUnauthorized || errorCode(failed) != CodeInvalidBackupCode {
				t.Fatalf("failure %d=%d %#v", index, failed.status, failed.body)
			}
		}
		locked := invoke(t, h.auth, "verifyBackupCode", http.MethodPost, "/two-factor/verify-backup-code", challenge.cookie, map[string]any{"code": h.backupCodes[0]})
		if locked.status != http.StatusBadRequest || errorCode(locked) != CodeTooManyAttempts {
			t.Fatalf("backup locked=%d %#v", locked.status, locked.body)
		}
	})

	t.Run("concurrent TOTP burst bounded", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		challenge := h.challenge(t)
		statuses, codes := concurrentCalls(h.auth, 20, "verifyTOTP", "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": wrongTOTP(h.currentTOTP(t))})
		processed := 0
		for index := range statuses {
			if statuses[index] == http.StatusOK {
				t.Fatal("wrong concurrent TOTP minted a session")
			}
			if codes[index] == CodeInvalidCode {
				processed++
			}
		}
		if processed > DefaultAllowedAttempts {
			t.Fatalf("processed=%d statuses=%#v codes=%#v", processed, statuses, codes)
		}
	})

	t.Run("decrypt failure restores slot", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		challenge := h.challenge(t)
		row := twoFactorRow(t, h.auth)
		original, _ := recordString(row, "secret")
		updateTwoFactor(t, h.auth, storage.Record{"secret": "not-encrypted"})
		failed := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": "000000"})
		if failed.status != http.StatusInternalServerError {
			t.Fatalf("decrypt failure=%d %#v err=%v", failed.status, failed.body, failed.err)
		}
		updateTwoFactor(t, h.auth, storage.Record{"secret": original})
		ok := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": h.currentTOTP(t)})
		if ok.status != http.StatusOK {
			t.Fatalf("restored slot=%d %#v", ok.status, ok.body)
		}
	})
}

func TestChallengeAndOTPConcurrencySecurity(t *testing.T) {
	t.Run("expired challenge", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		challenge := h.challenge(t)
		h.clock.Advance(DefaultTwoFactorCookieMaxAge + time.Second)
		result := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": h.currentTOTP(t)})
		if result.status != http.StatusUnauthorized || errorCode(result) != CodeInvalidTwoFactorCookie {
			t.Fatalf("expired=%d %#v", result.status, result.body)
		}
	})

	t.Run("single-use challenge", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		challenge := h.challenge(t)
		statuses, _ := concurrentCalls(h.auth, 2, "verifyTOTP", "/two-factor/verify-totp", challenge.cookie, map[string]any{"code": h.currentTOTP(t)})
		success := 0
		for _, status := range statuses {
			if status == http.StatusOK {
				success++
			}
		}
		if success != 1 {
			t.Fatalf("single-use successes=%d statuses=%#v", success, statuses)
		}
	})

	t.Run("OTP wrong burst bounded", func(t *testing.T) {
		capture := &otpCapture{}
		h := setupEnrolled(t, Options{OTP: OTPOptions{SendOTP: capture.send}}, nil)
		challenge := h.challenge(t)
		_ = invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
		statuses, codes := concurrentCalls(h.auth, 20, "verifyTwoFactorOTP", "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": "wrong"})
		processed := 0
		for index, status := range statuses {
			if status == http.StatusOK {
				t.Fatal("wrong OTP minted a session")
			}
			if codes[index] == CodeInvalidCode {
				processed++
			}
		}
		if processed > DefaultAllowedAttempts {
			t.Fatalf("processed=%d statuses=%#v codes=%#v", processed, statuses, codes)
		}
	})

	t.Run("concurrent correct OTP mints one session", func(t *testing.T) {
		capture := &otpCapture{}
		h := setupEnrolled(t, Options{OTP: OTPOptions{SendOTP: capture.send}}, nil)
		challenge := h.challenge(t)
		_ = invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
		statuses, _ := concurrentCalls(h.auth, 12, "verifyTwoFactorOTP", "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": capture.get()})
		success := 0
		for _, status := range statuses {
			if status == http.StatusOK {
				success++
			}
		}
		if success != 1 {
			t.Fatalf("OTP successes=%d statuses=%#v", success, statuses)
		}
	})
}

func TestConcurrentBackupCodeIsSingleUse(t *testing.T) {
	h := setupEnrolled(t, Options{}, nil)
	statuses, _ := concurrentCalls(
		h.auth,
		12,
		"verifyBackupCode",
		"/two-factor/verify-backup-code",
		h.activeCookie,
		map[string]any{"code": h.backupCodes[0], "disableSession": true},
	)
	success := 0
	for _, status := range statuses {
		if status == http.StatusOK {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("backup successes=%d statuses=%#v", success, statuses)
	}
	viewed := invoke(t, h.auth, "viewBackupCodes", http.MethodPost, "/two-factor/view-backup-codes", "", map[string]any{"userId": h.userID})
	if viewed.status != http.StatusOK || len(viewed.body["backupCodes"].([]any)) != 9 {
		t.Fatalf("backup view=%d %#v", viewed.status, viewed.body)
	}
}

func concurrentCalls(
	auth *singleauth.Auth,
	count int,
	name, path, cookie string,
	body map[string]any,
) ([]int, []string) {
	statuses := make([]int, count)
	codes := make([]string, count)
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(count)
	for index := 0; index < count; index++ {
		go func(index int) {
			defer wait.Done()
			<-start
			response, _ := invokeRaw(auth, name, http.MethodPost, path, cookie, body)
			statuses[index] = response.Status()
			var value map[string]any
			_ = json.Unmarshal(response.Body(), &value)
			codes[index], _ = value["code"].(string)
		}(index)
	}
	close(start)
	wait.Wait()
	return statuses, codes
}

func TestCredentialSignInScrubsSessionCookiesAndReplay(t *testing.T) {
	for _, cacheEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "cache disabled", true: "cache enabled"}[cacheEnabled], func(t *testing.T) {
			h := setupEnrolled(t, Options{}, func(options *singleauth.Options) {
				options.Session.CookieCache.Enabled = cacheEnabled
			})
			challenge := h.challenge(t)
			assertOnlyExpiredSessionCookies(t, challenge.headers.Values("Set-Cookie"))
			if responseCookie(challenge.headers.Values("Set-Cookie"), "two_factor") == nil {
				t.Fatalf("two-factor cookie missing: %#v", challenge.headers.Values("Set-Cookie"))
			}
			replay := capturedSessionCookieHeader(challenge.headers.Values("Set-Cookie"))
			session := invoke(t, h.auth, "getSession", http.MethodGet, "/get-session", replay, nil)
			if session.status != http.StatusOK || string(session.raw) != "null" {
				t.Fatalf("replay session=%d %s", session.status, session.raw)
			}
			disable := invoke(t, h.auth, "disableTwoFactor", http.MethodPost, "/two-factor/disable", replay, map[string]any{"password": testPass})
			if disable.status != http.StatusUnauthorized {
				t.Fatalf("replay disable=%d %#v", disable.status, disable.body)
			}
		})
	}

	t.Run("chunked session cache", func(t *testing.T) {
		filler := strings.Repeat("x", 2200)
		h := setupEnrolled(t, Options{}, func(options *singleauth.Options) {
			options.Session.CookieCache.Enabled = true
			options.Schema = storage.Schema{Models: map[string]storage.ModelSchema{
				"user": {ModelName: "user", Fields: map[string]storage.FieldAttribute{
					"blob1": {Type: storage.FieldString, Required: storage.Bool(false), DefaultValue: storage.StaticValue(filler)},
					"blob2": {Type: storage.FieldString, Required: storage.Bool(false), DefaultValue: storage.StaticValue(filler)},
				}},
			}}
		})
		probeChunks := 0
		for _, line := range h.signedUp.headers.Values("Set-Cookie") {
			for _, parsed := range cookies.ParseSetCookieHeader(line) {
				if strings.Contains(parsed.Name, "session_data.") {
					probeChunks++
				}
			}
		}
		if probeChunks == 0 {
			t.Fatal("fixture did not produce chunked session_data")
		}
		challenge := h.challenge(t)
		assertOnlyExpiredSessionCookies(t, challenge.headers.Values("Set-Cookie"))
		if replay := capturedSessionCookieHeader(challenge.headers.Values("Set-Cookie")); replay != "" {
			session := invoke(t, h.auth, "getSession", http.MethodGet, "/get-session", replay, nil)
			if string(session.raw) != "null" {
				t.Fatalf("chunk replay authenticated: %s", session.raw)
			}
		}
	})
}

func TestEmailUsernameAndPhoneSignInCookieScrubbing(t *testing.T) {
	h := setupEnrolled(t, Options{}, func(options *singleauth.Options) {
		options.Session.CookieCache.Enabled = true
		options.PluginFactories = append(options.PluginFactories,
			username.NewFactory(username.Options{}),
			phonenumber.NewFactory(phonenumber.Options{SendOTP: func(context.Context, phonenumber.OTPMessage, *engine.Context) error { return nil }}),
		)
	})
	user, err := h.auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: h.userID}},
		Update: storage.Record{
			"username": "security_user", "displayUsername": "security_user",
			"phoneNumber": "+15551230000", "phoneNumberVerified": true,
		},
	})
	if err != nil || user == nil {
		t.Fatalf("update credential aliases=%#v err=%v", user, err)
	}
	tests := []struct {
		name, endpoint, path string
		body                 map[string]any
	}{
		{"email", "signInEmail", "/sign-in/email", map[string]any{"email": testEmail, "password": testPass}},
		{"username", "signInUsername", "/sign-in/username", map[string]any{"username": "security_user", "password": testPass}},
		{"phone", "signInPhoneNumber", "/sign-in/phone-number", map[string]any{"phoneNumber": "+15551230000", "password": testPass}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := invoke(t, h.auth, test.endpoint, http.MethodPost, test.path, "", test.body)
			if result.status != http.StatusOK || result.body["twoFactorRedirect"] != true {
				t.Fatalf("result=%d %#v", result.status, result.body)
			}
			assertOnlyExpiredSessionCookies(t, result.headers.Values("Set-Cookie"))
			replay := capturedSessionCookieHeader(result.headers.Values("Set-Cookie"))
			session := invoke(t, h.auth, "getSession", http.MethodGet, "/get-session", replay, nil)
			if string(session.raw) != "null" {
				t.Fatalf("replay authenticated: %s", session.raw)
			}
		})
	}
}

func capturedSessionCookieHeader(lines []string) string {
	parsed := cookies.Parse("")
	for _, line := range lines {
		for _, cookie := range cookies.ParseSetCookieHeader(line) {
			if !strings.Contains(cookie.Name, "session_token") && !strings.Contains(cookie.Name, "session_data") {
				continue
			}
			if cookie.Attributes.Value != "" {
				parsed.Set(cookie.Name, cookie.Attributes.Value)
			}
		}
	}
	return parsed.Header()
}

func TestTwoFactorEnforcementScope(t *testing.T) {
	var message magiclink.MagicLinkMessage
	h := setupEnrolled(t, Options{}, func(options *singleauth.Options) {
		options.PluginFactories = append(options.PluginFactories, magiclink.NewFactory(magiclink.Options{
			SendMagicLink: func(_ context.Context, value magiclink.MagicLinkMessage, _ *engine.Context) error {
				message = value
				return nil
			},
		}))
	})

	getSession := invoke(t, h.auth, "getSession", http.MethodGet, "/get-session", h.activeCookie, nil)
	if getSession.status != http.StatusOK || getSession.body["twoFactorRedirect"] != nil {
		t.Fatalf("authenticated endpoint challenged=%d %#v", getSession.status, getSession.body)
	}
	sent := invoke(t, h.auth, "signInMagicLink", http.MethodPost, "/sign-in/magic-link", "", map[string]any{"email": testEmail})
	if sent.status != http.StatusOK || message.Token == "" {
		t.Fatalf("magic send=%d %#v message=%#v", sent.status, sent.body, message)
	}
	verified := exchangeHTTP(t, h.auth, http.MethodGet, "/magic-link/verify?token="+message.Token, "", nil)
	if verified.status != http.StatusOK || verified.body["twoFactorRedirect"] != nil ||
		responseCookie(verified.headers.Values("Set-Cookie"), "session_token") == nil {
		t.Fatalf("magic verify=%d %#v cookies=%#v", verified.status, verified.body, verified.headers.Values("Set-Cookie"))
	}
}

func TestResponseHeaderScrubPrimitive(t *testing.T) {
	endpoint := engine.Endpoint{Name: "cookie-source", Path: "/cookie-source", Methods: []string{http.MethodPost}, Handler: func(ctx *engine.Context) (contract.Response, error) {
		ctx.AddSetCookie("session=live")
		return contract.JSONResponse(http.StatusOK, map[string]any{"source": true})
	}}
	plugin := engine.Plugin{ID: "scrubber", Hooks: engine.Hooks{After: []engine.AfterHook{{
		Matcher: func(*engine.Context) (bool, error) { return true, nil },
		Handler: func(ctx *engine.Context, response contract.Response) (*contract.Response, error) {
			ctx.RemoveResponseHeaderValues("set-cookie", "session=live")
			ctx.AddSetCookie("session=; Max-Age=0")
			replacement, _ := contract.JSONResponse(http.StatusOK, map[string]any{"scrubbed": true})
			return &replacement, nil
		},
	}}}}
	registry, err := engine.NewRegistry([]engine.Endpoint{endpoint}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := dispatcher.Invoke("cookie-source", engine.DirectInput{Request: contract.NewRequest(http.MethodPost, "/cookie-source", contract.RequestOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Headers().Values("Set-Cookie"); len(got) != 1 || got[0] != "session=; Max-Age=0" {
		t.Fatalf("Set-Cookie=%#v", got)
	}
}
