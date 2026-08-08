package emailotp

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func wrongCompatibilityOTP(valid string) string {
	if valid == "000000" {
		return "999999"
	}
	return "000000"
}

func assertCompatibilityOTPError(t *testing.T, response contract.Response, err error, status int, code string) {
	t.Helper()
	if err == nil || response.Status() != status || responseCode(t, response) != code {
		t.Fatalf("OTP error status=%d err=%v body=%s, want status=%d code=%s", response.Status(), err, response.Body(), status, code)
	}
}

func TestUpstreamEmailOTPVerifyRuntime(t *testing.T) {
	t.Run("should prevent user enumeration when disableSignUp is enabled", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) { options.DisableSignUp = true })
		harness.seedUser(t, "enumeration-user", "enumeration@example.com", false)
		missing, missingErr := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "missing@example.com", "type": "email-verification",
		})
		if missingErr != nil || responseObject(t, missing)["success"] != true || harness.messageCount() != 0 {
			t.Fatalf("missing response err=%v body=%s sends=%d", missingErr, missing.Body(), harness.messageCount())
		}
		known, knownErr := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "enumeration@example.com", "type": "email-verification",
		})
		if knownErr != nil || responseObject(t, known)["success"] != true || harness.messageCount() != 1 {
			t.Fatalf("known response err=%v body=%s sends=%d", knownErr, known.Body(), harness.messageCount())
		}
	})

	t.Run("should return INVALID_OTP regardless of email registration", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) { options.DisableSignUp = true })
		harness.seedUser(t, "registered-user", "registered@example.com", false)
		for _, email := range []string{"registered@example.com", "unregistered@example.com"} {
			response, err := harness.call(t, "POST", "/email-otp/check-verification-otp", nil, emptyHeaders(), map[string]any{
				"email": email, "type": "email-verification", "otp": "000000",
			})
			assertCompatibilityOTPError(t, response, err, contract.StatusBadRequest, ErrorInvalidOTP)
			body := responseObject(t, response)
			if body["message"] != "Invalid OTP" {
				t.Fatalf("enumeration error body=%#v", body)
			}
		}
	})

	t.Run("should not send OTP email for non-existent users when disableSignUp is enabled", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) { options.DisableSignUp = true })
		harness.seedUser(t, "existing-user", "existing@example.com", true)
		missing, missingErr := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "missing@example.com", "type": "sign-in",
		})
		if missingErr != nil || responseObject(t, missing)["success"] != true || harness.messageCount() != 0 {
			t.Fatalf("missing sign-in OTP err=%v body=%s sends=%d", missingErr, missing.Body(), harness.messageCount())
		}
		existing, existingErr := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "existing@example.com", "type": "sign-in",
		})
		message := harness.latestMessage(t)
		if existingErr != nil || responseObject(t, existing)["success"] != true || harness.messageCount() != 1 || message.Email != "existing@example.com" || message.Type != TypeSignIn {
			t.Fatalf("existing sign-in OTP err=%v body=%s sends=%d message=%#v", existingErr, existing.Body(), harness.messageCount(), message)
		}
	})

	t.Run("should verify email with last otp", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "last-user", "last@example.com", false)
		messages := make([]OTPMessage, 0, 3)
		for range 3 {
			messages = append(messages, sendCompatibilityOTP(t, harness, "last@example.com", TypeEmailVerification))
			harness.clock.Advance(time.Nanosecond)
		}
		if messages[0].OTP == messages[2].OTP {
			t.Fatalf("rotate strategy reused OTPs=%#v", messages)
		}
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
			"email": "last@example.com", "otp": messages[2].OTP,
		})
		if err != nil || responseObject(t, response)["status"] != true {
			t.Fatalf("last OTP verify err=%v body=%s", err, response.Body())
		}
	})

	t.Run("should block after exceeding allowed attempts", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "attempt-verify", "attempt-verify@example.com", false)
		valid := sendCompatibilityOTP(t, harness, "attempt-verify@example.com", TypeEmailVerification).OTP
		wrong := wrongCompatibilityOTP(valid)
		for attempt := 0; attempt < 3; attempt++ {
			response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
				"email": "attempt-verify@example.com", "otp": wrong,
			})
			assertCompatibilityOTPError(t, response, err, contract.StatusBadRequest, ErrorInvalidOTP)
		}
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
			"email": "attempt-verify@example.com", "otp": valid,
		})
		assertCompatibilityOTPError(t, response, err, contract.StatusForbidden, ErrorTooManyAttempts)
	})

	t.Run("should block reset password after exceeding allowed attempts", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "attempt-reset", "attempt-reset@example.com", true)
		valid := sendCompatibilityOTP(t, harness, "attempt-reset@example.com", TypeForgetPassword).OTP
		wrong := wrongCompatibilityOTP(valid)
		for attempt := 0; attempt < 3; attempt++ {
			response, err := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
				"email": "attempt-reset@example.com", "otp": wrong, "password": "new-password",
			})
			assertCompatibilityOTPError(t, response, err, contract.StatusBadRequest, ErrorInvalidOTP)
		}
		response, err := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
			"email": "attempt-reset@example.com", "otp": valid, "password": "new-password",
		})
		assertCompatibilityOTPError(t, response, err, contract.StatusForbidden, ErrorTooManyAttempts)
	})
}

func TestUpstreamEmailOTPCustomGenerateRuntime(t *testing.T) {
	newCustom := func(t *testing.T) *emailOTPHarness {
		t.Helper()
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.GenerateOTP = func(data OTPData, _ *engine.Context) (string, error) {
				if data.Email != "generated@example.com" || data.Type != TypeEmailVerification {
					t.Fatalf("generate data=%#v", data)
				}
				return "123456", nil
			}
		})
		harness.seedUser(t, "generated-user", "generated@example.com", false)
		return harness
	}
	t.Run("should generate otp", func(t *testing.T) {
		harness := newCustom(t)
		message := sendCompatibilityOTP(t, harness, "generated@example.com", TypeEmailVerification)
		if message.OTP != "123456" {
			t.Fatalf("generated OTP=%q", message.OTP)
		}
	})
	t.Run("should verify email with otp", func(t *testing.T) {
		harness := newCustom(t)
		sendCompatibilityOTP(t, harness, "generated@example.com", TypeEmailVerification)
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
			"email": "generated@example.com", "otp": "123456",
		})
		if err != nil || responseObject(t, response)["status"] != true {
			t.Fatalf("custom generate verify err=%v body=%s", err, response.Body())
		}
	})
}

type compatibilityStorageMode struct {
	suite        string
	createTitle  string
	getTitle     string
	signInTitle  string
	configure    func(*Options)
	recoverable  bool
	storedSuffix string
}

func TestUpstreamEmailOTPCustomStorageRuntime(t *testing.T) {
	modes := []compatibilityStorageMode{
		{
			suite: "hashed", createTitle: "should create a hashed otp",
			getTitle: "should not be allowed to get otp if storeOTP is hashed", signInTitle: "should be able to sign in with normal otp",
			configure: func(options *Options) { options.Storage.Mode = StoreHashed },
		},
		{
			suite: "encrypted", createTitle: "should create an encrypted otp",
			getTitle: "should be allowed to get otp if storeOTP is encrypted", signInTitle: "should be able to sign in with encrypted otp",
			configure: func(options *Options) { options.Storage.Mode = StoreEncrypted }, recoverable: true,
		},
		{
			suite: "custom encryptor", createTitle: "should create a custom encryptor otp",
			getTitle: "should be allowed to get otp if storeOTP is custom encryptor", signInTitle: "should be able to sign in with custom encryptor otp",
			configure: func(options *Options) {
				options.Storage.CustomEncrypt = func(_ context.Context, otp string) (string, error) { return otp + "encrypted", nil }
				options.Storage.CustomDecrypt = func(_ context.Context, stored string) (string, error) {
					return strings.TrimSuffix(stored, "encrypted"), nil
				}
			}, recoverable: true, storedSuffix: "encrypted",
		},
		{
			suite: "custom hasher", createTitle: "should create a custom hasher otp",
			getTitle: "should be allowed to get otp if storeOTP is custom hasher", signInTitle: "should be able to sign in with custom hasher otp",
			configure: func(options *Options) {
				options.Storage.CustomHash = func(_ context.Context, otp string) (string, error) { return otp + "hashed", nil }
			}, storedSuffix: "hashed",
		},
	}
	newStorageHarness := func(t *testing.T, mode compatibilityStorageMode, email string) *emailOTPHarness {
		t.Helper()
		return newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) { mode.configure(options) })
	}
	for _, mode := range modes {
		mode := mode
		t.Run(mode.suite+"/"+mode.createTitle, func(t *testing.T) {
			email := strings.ReplaceAll(mode.suite, " ", "-") + "-create@example.com"
			harness := newStorageHarness(t, mode, email)
			message := sendCompatibilityOTP(t, harness, email, TypeSignIn)
			record := findCompatibilityVerification(t, harness, Identifier(TypeSignIn, email))
			value, _ := recordString(record, "value")
			stored, attempts := SplitStoredValue(value)
			if stored == "" || stored == message.OTP || attempts != "0" {
				t.Fatalf("stored=%q attempts=%q raw=%q", stored, attempts, message.OTP)
			}
			if mode.storedSuffix != "" && !strings.HasSuffix(stored, mode.storedSuffix) {
				t.Fatalf("stored=%q missing suffix=%q", stored, mode.storedSuffix)
			}
		})

		t.Run(mode.suite+"/"+mode.getTitle, func(t *testing.T) {
			email := strings.ReplaceAll(mode.suite, " ", "-") + "-get@example.com"
			harness := newStorageHarness(t, mode, email)
			message := sendCompatibilityOTP(t, harness, email, TypeSignIn)
			response, err := invokeGetCompatibilityOTP(t, harness, email, TypeSignIn)
			if mode.recoverable {
				if err != nil || responseObject(t, response)["otp"] != message.OTP {
					t.Fatalf("recoverable get err=%v body=%s raw=%q", err, response.Body(), message.OTP)
				}
				return
			}
			if err == nil || response.Status() != contract.StatusBadRequest || responseObject(t, response)["message"] != "OTP is hashed, cannot return the plain text OTP" {
				t.Fatalf("hashed get status=%d err=%v body=%s", response.Status(), err, response.Body())
			}
		})

		t.Run(mode.suite+"/"+mode.signInTitle, func(t *testing.T) {
			email := strings.ReplaceAll(mode.suite, " ", "-") + "-signin@example.com"
			harness := newStorageHarness(t, mode, email)
			message := sendCompatibilityOTP(t, harness, email, TypeSignIn)
			response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
				"email": email, "otp": message.OTP,
			})
			body := responseObject(t, response)
			if err != nil || body["token"] == "" || body["user"].(map[string]any)["email"] != email {
				t.Fatalf("storage sign-in err=%v body=%s", err, response.Body())
			}
		})
	}
}

func TestUpstreamEmailOTPRaceProtectionRuntime(t *testing.T) {
	t.Run("should delete OTP after successful sign-in", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "delete-signin@example.com", TypeSignIn)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "delete-signin@example.com", "otp": message.OTP})
		if err != nil || responseObject(t, response)["token"] == "" || findCompatibilityVerification(t, harness, Identifier(TypeSignIn, "delete-signin@example.com")) != nil {
			t.Fatalf("first sign-in err=%v body=%s", err, response.Body())
		}
		replay, replayErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "delete-signin@example.com", "otp": message.OTP})
		assertCompatibilityOTPError(t, replay, replayErr, contract.StatusBadRequest, ErrorInvalidOTP)
	})

	t.Run("should delete OTP after successful email verification", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "delete-verify", "delete-verify@example.com", false)
		message := sendCompatibilityOTP(t, harness, "delete-verify@example.com", TypeEmailVerification)
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{"email": "delete-verify@example.com", "otp": message.OTP})
		if err != nil || responseObject(t, response)["status"] != true || findCompatibilityVerification(t, harness, Identifier(TypeEmailVerification, "delete-verify@example.com")) != nil {
			t.Fatalf("first verify err=%v body=%s", err, response.Body())
		}
		replay, replayErr := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{"email": "delete-verify@example.com", "otp": message.OTP})
		assertCompatibilityOTPError(t, replay, replayErr, contract.StatusBadRequest, ErrorInvalidOTP)
	})

	t.Run("should delete OTP after successful password reset", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "delete-reset", "delete-reset@example.com", true)
		message := sendCompatibilityOTP(t, harness, "delete-reset@example.com", TypeForgetPassword)
		response, err := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{"email": "delete-reset@example.com", "otp": message.OTP, "password": "newpass1"})
		if err != nil || responseObject(t, response)["success"] != true || findCompatibilityVerification(t, harness, Identifier(TypeForgetPassword, "delete-reset@example.com")) != nil {
			t.Fatalf("first reset err=%v body=%s", err, response.Body())
		}
		replay, replayErr := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{"email": "delete-reset@example.com", "otp": message.OTP, "password": "newpass2"})
		assertCompatibilityOTPError(t, replay, replayErr, contract.StatusBadRequest, ErrorInvalidOTP)
	})

	t.Run("should allow exactly one success when the same OTP is verified concurrently", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "concurrent-signin@example.com", TypeSignIn)
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
				response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "concurrent-signin@example.com", "otp": message.OTP})
				results <- result{response: response, err: err}
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		successes, failures := 0, 0
		for result := range results {
			if result.err == nil && responseObject(t, result.response)["token"] != "" {
				successes++
			} else if result.err != nil && responseCode(t, result.response) == ErrorInvalidOTP {
				failures++
			}
		}
		if successes != 1 || failures != 1 || findCompatibilityVerification(t, harness, Identifier(TypeSignIn, "concurrent-signin@example.com")) != nil {
			t.Fatalf("concurrent sign-in successes=%d failures=%d", successes, failures)
		}
	})

	t.Run("should allow exactly one success when the same email-verification OTP is verified concurrently", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "concurrent-verify", "concurrent-verify@example.com", false)
		message := sendCompatibilityOTP(t, harness, "concurrent-verify@example.com", TypeEmailVerification)
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
				response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{"email": "concurrent-verify@example.com", "otp": message.OTP})
				results <- result{response: response, err: err}
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		successes, failures := 0, 0
		for result := range results {
			if result.err == nil && responseObject(t, result.response)["status"] == true {
				successes++
			} else if result.err != nil && responseCode(t, result.response) == ErrorInvalidOTP {
				failures++
			}
		}
		if successes != 1 || failures != 1 {
			t.Fatalf("concurrent verify successes=%d failures=%d", successes, failures)
		}
	})

	t.Run("should increment attempts on a wrong code without burning a valid OTP, and reject replay of a consumed code", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "wrong-code@example.com", TypeSignIn)
		wrong := wrongCompatibilityOTP(message.OTP)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "wrong-code@example.com", "otp": wrong})
		assertCompatibilityOTPError(t, response, err, contract.StatusBadRequest, ErrorInvalidOTP)
		record := findCompatibilityVerification(t, harness, Identifier(TypeSignIn, "wrong-code@example.com"))
		value, _ := recordString(record, "value")
		_, attempts := SplitStoredValue(value)
		if attempts != "1" {
			t.Fatalf("attempt suffix=%q record=%#v", attempts, record)
		}
		success, successErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "wrong-code@example.com", "otp": message.OTP})
		if successErr != nil || responseObject(t, success)["token"] == "" {
			t.Fatalf("valid after wrong err=%v body=%s", successErr, success.Body())
		}
		replay, replayErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "wrong-code@example.com", "otp": message.OTP})
		assertCompatibilityOTPError(t, replay, replayErr, contract.StatusBadRequest, ErrorInvalidOTP)
	})

	t.Run("should lock out after the attempt budget is exhausted and not recreate the OTP", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "lockout@example.com", TypeSignIn)
		wrong := wrongCompatibilityOTP(message.OTP)
		for attempt := 0; attempt < 3; attempt++ {
			response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "lockout@example.com", "otp": wrong})
			assertCompatibilityOTPError(t, response, err, contract.StatusBadRequest, ErrorInvalidOTP)
		}
		locked, lockedErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "lockout@example.com", "otp": wrong})
		assertCompatibilityOTPError(t, locked, lockedErr, contract.StatusForbidden, ErrorTooManyAttempts)
		if record := findCompatibilityVerification(t, harness, Identifier(TypeSignIn, "lockout@example.com")); record != nil {
			t.Fatalf("lockout recreated record=%#v", record)
		}
		replay, replayErr := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "lockout@example.com", "otp": message.OTP})
		assertCompatibilityOTPError(t, replay, replayErr, contract.StatusBadRequest, ErrorInvalidOTP)
	})
}

func TestUpstreamEmailOTPResendStrategyRuntime(t *testing.T) {
	t.Run("should reuse existing OTP when resendStrategy is reuse", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) { options.ResendStrategy = ResendReuse })
		harness.seedUser(t, "reuse-user", "reuse@example.com", true)
		first := sendCompatibilityOTP(t, harness, "reuse@example.com", TypeEmailVerification)
		second := sendCompatibilityOTP(t, harness, "reuse@example.com", TypeEmailVerification)
		if first.OTP != second.OTP || harness.generated.Load() != 1 {
			t.Fatalf("reuse first=%q second=%q generated=%d", first.OTP, second.OTP, harness.generated.Load())
		}
	})

	t.Run("should generate new OTP after previous one expires", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) { options.ResendStrategy = ResendReuse })
		harness.seedUser(t, "reuse-expired", "reuse-expired@example.com", true)
		first := sendCompatibilityOTP(t, harness, "reuse-expired@example.com", TypeSignIn)
		harness.clock.Advance(6 * time.Minute)
		second := sendCompatibilityOTP(t, harness, "reuse-expired@example.com", TypeSignIn)
		if first.OTP == second.OTP || harness.generated.Load() != 2 {
			t.Fatalf("expired reuse first=%q second=%q generated=%d", first.OTP, second.OTP, harness.generated.Load())
		}
	})

	t.Run("should generate new OTP when resendStrategy is reuse but storeOTP is hashed", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.ResendStrategy = ResendReuse
			options.Storage.Mode = StoreHashed
		})
		harness.seedUser(t, "reuse-hashed", "reuse-hashed@example.com", true)
		first := sendCompatibilityOTP(t, harness, "reuse-hashed@example.com", TypeEmailVerification)
		second := sendCompatibilityOTP(t, harness, "reuse-hashed@example.com", TypeEmailVerification)
		if first.OTP == second.OTP || harness.generated.Load() != 2 {
			t.Fatalf("hashed reuse first=%q second=%q generated=%d", first.OTP, second.OTP, harness.generated.Load())
		}
	})

	t.Run("should generate new OTP when resendStrategy is reuse but storeOTP is custom hash", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.ResendStrategy = ResendReuse
			options.Storage.CustomHash = func(_ context.Context, otp string) (string, error) { return "hashed-" + otp, nil }
		})
		harness.seedUser(t, "reuse-custom-hash", "reuse-custom-hash@example.com", true)
		first := sendCompatibilityOTP(t, harness, "reuse-custom-hash@example.com", TypeEmailVerification)
		second := sendCompatibilityOTP(t, harness, "reuse-custom-hash@example.com", TypeEmailVerification)
		if first.OTP == second.OTP || harness.generated.Load() != 2 {
			t.Fatalf("custom hash reuse first=%q second=%q generated=%d", first.OTP, second.OTP, harness.generated.Load())
		}
	})

	t.Run("should not send OTP for non-existent user on email-verification type", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.ResendStrategy = ResendReuse
			options.DisableSignUp = true
		})
		response, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "nonexistent@example.com", "type": "email-verification",
		})
		if err != nil || responseObject(t, response)["success"] != true || harness.messageCount() != 0 || findCompatibilityVerification(t, harness, Identifier(TypeEmailVerification, "nonexistent@example.com")) != nil {
			t.Fatalf("missing reuse err=%v body=%s sends=%d", err, response.Body(), harness.messageCount())
		}
	})

	t.Run("should generate fresh OTP when attempts are exhausted", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.ResendStrategy = ResendReuse
			options.AllowedAttempts = 2
		})
		harness.seedUser(t, "reuse-attempts", "reuse-attempts@example.com", false)
		first := sendCompatibilityOTP(t, harness, "reuse-attempts@example.com", TypeEmailVerification)
		wrong := wrongCompatibilityOTP(first.OTP)
		for attempt := 0; attempt < 2; attempt++ {
			response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{"email": "reuse-attempts@example.com", "otp": wrong})
			assertCompatibilityOTPError(t, response, err, contract.StatusBadRequest, ErrorInvalidOTP)
		}
		second := sendCompatibilityOTP(t, harness, "reuse-attempts@example.com", TypeEmailVerification)
		if first.OTP == second.OTP || harness.generated.Load() != 2 {
			t.Fatalf("attempt reuse first=%q second=%q generated=%d", first.OTP, second.OTP, harness.generated.Load())
		}
	})
}
