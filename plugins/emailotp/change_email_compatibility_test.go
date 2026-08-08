package emailotp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func compatibilityUserHeaders(userID string) contract.Headers {
	return contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: userID})
}

func newChangeEmailCompatibilityHarness(t *testing.T, verifyCurrent bool, configure func(*Options, *emailOTPHarness)) *emailOTPHarness {
	t.Helper()
	return newEmailOTPHarness(t, func(options *Options, harness *emailOTPHarness) {
		options.ChangeEmail = ChangeEmailOptions{Enabled: true, VerifyCurrentEmail: verifyCurrent}
		if configure != nil {
			configure(options, harness)
		}
	})
}

func requestCompatibilityEmailChange(t *testing.T, harness *emailOTPHarness, headers contract.Headers, newEmail string, currentOTP *string) (contract.Response, error) {
	t.Helper()
	body := map[string]any{"newEmail": newEmail}
	if currentOTP != nil {
		body["otp"] = *currentOTP
	}
	return harness.call(t, "POST", "/email-otp/request-email-change", nil, headers, body)
}

func changeCompatibilityEmail(t *testing.T, harness *emailOTPHarness, headers contract.Headers, newEmail, otp string) (contract.Response, error) {
	t.Helper()
	return harness.call(t, "POST", "/email-otp/change-email", nil, headers, map[string]any{"newEmail": newEmail, "otp": otp})
}

func TestUpstreamEmailOTPChangeEmailRuntime(t *testing.T) {
	t.Run("request/should send otp for change email request", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		harness.seedUser(t, "request-user", "request@example.com", true)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("request-user"), "NEW@EXAMPLE.COM", nil)
		message := harness.latestMessage(t)
		if err != nil || responseObject(t, response)["success"] != true || message.Email != "new@example.com" || message.Type != TypeChangeEmail || message.OTP == "" {
			t.Fatalf("request response=%s err=%v message=%#v", response.Body(), err, message)
		}
	})

	t.Run("request/should not send otp for change email request if session does not exist", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		response, err := requestCompatibilityEmailChange(t, harness, emptyHeaders(), "new@example.com", nil)
		if err == nil || response.Status() != contract.StatusUnauthorized || responseCode(t, response) != "UNAUTHORIZED" || harness.messageCount() != 0 {
			t.Fatalf("missing session status=%d err=%v body=%s sends=%d", response.Status(), err, response.Body(), harness.messageCount())
		}
	})

	t.Run("request/should not send otp for change email request if session is invalid", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("missing-user"), "new@example.com", nil)
		if err == nil || response.Status() != contract.StatusUnauthorized || responseCode(t, response) != "UNAUTHORIZED" || harness.messageCount() != 0 {
			t.Fatalf("invalid session status=%d err=%v body=%s sends=%d", response.Status(), err, response.Body(), harness.messageCount())
		}
	})

	t.Run("request/should not send otp for change email request when change email with OTP is disabled", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "disabled-user", "disabled@example.com", true)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("disabled-user"), "new@example.com", nil)
		if err == nil || response.Status() != contract.StatusBadRequest || responseObject(t, response)["message"] != "Change email with OTP is disabled" || harness.messageCount() != 0 {
			t.Fatalf("disabled status=%d err=%v body=%s sends=%d", response.Status(), err, response.Body(), harness.messageCount())
		}
	})

	t.Run("request/should not send otp for change email request if email is same as old email", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		harness.seedUser(t, "same-user", "same@example.com", true)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("same-user"), "SAME@EXAMPLE.COM", nil)
		if err == nil || response.Status() != contract.StatusBadRequest || responseObject(t, response)["message"] != "Email is the same" || harness.messageCount() != 0 {
			t.Fatalf("same email status=%d err=%v body=%s sends=%d", response.Status(), err, response.Body(), harness.messageCount())
		}
	})

	t.Run("request/should not send otp for change email request if email is already used by another account", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		harness.seedUser(t, "current-user", "current@example.com", true)
		harness.seedUser(t, "other-user", "other@example.com", true)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("current-user"), "OTHER@EXAMPLE.COM", nil)
		if err != nil || responseObject(t, response)["success"] != true || harness.messageCount() != 0 {
			t.Fatalf("existing new email err=%v body=%s sends=%d", err, response.Body(), harness.messageCount())
		}
		if record := findCompatibilityVerification(t, harness, Identifier(TypeChangeEmail, "current@example.com-other@example.com")); record != nil {
			t.Fatalf("enumeration-safe request retained verification=%#v", record)
		}
	})

	t.Run("request/when verifyCurrentEmail is enabled/should require otp when requesting email change", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, true, nil)
		harness.seedUser(t, "required-user", "required@example.com", true)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("required-user"), "new@example.com", nil)
		if err == nil || response.Status() != contract.StatusBadRequest || responseObject(t, response)["message"] != "OTP is required to verify current email" {
			t.Fatalf("required OTP status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("request/when verifyCurrentEmail is enabled/should reject invalid current email otp when requesting email change", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, true, nil)
		harness.seedUser(t, "invalid-current", "invalid-current@example.com", true)
		message := sendCompatibilityOTP(t, harness, "invalid-current@example.com", TypeEmailVerification)
		wrong := "000000"
		if wrong == message.OTP {
			wrong = "999999"
		}
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("invalid-current"), "new@example.com", &wrong)
		if err == nil || response.Status() != contract.StatusBadRequest || responseCode(t, response) != ErrorInvalidOTP {
			t.Fatalf("invalid current OTP status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("request/when verifyCurrentEmail is enabled/should reject when no email-verification OTP was requested for current email", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, true, nil)
		harness.seedUser(t, "missing-current", "missing-current@example.com", true)
		provided := "123456"
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("missing-current"), "new@example.com", &provided)
		if err == nil || response.Status() != contract.StatusBadRequest || responseCode(t, response) != ErrorInvalidOTP {
			t.Fatalf("missing current OTP status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("request/when verifyCurrentEmail is enabled/should reject expired current email OTP when requesting email change", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, true, func(options *Options, _ *emailOTPHarness) {
			options.ExpiresIn = time.Minute
		})
		harness.seedUser(t, "expired-current", "expired-current@example.com", true)
		message := sendCompatibilityOTP(t, harness, "expired-current@example.com", TypeEmailVerification)
		harness.clock.Advance(61 * time.Second)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("expired-current"), "new@example.com", &message.OTP)
		if err == nil || response.Status() != contract.StatusBadRequest || responseCode(t, response) != ErrorOTPExpired {
			t.Fatalf("expired current OTP status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("request/when verifyCurrentEmail is enabled/should send change-email OTP when valid current email OTP is provided", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, true, nil)
		harness.seedUser(t, "valid-current", "valid-current@example.com", true)
		current := sendCompatibilityOTP(t, harness, "valid-current@example.com", TypeEmailVerification)
		response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("valid-current"), "verified-change@example.com", &current.OTP)
		message := harness.latestMessage(t)
		if err != nil || responseObject(t, response)["success"] != true || message.Email != "verified-change@example.com" || message.Type != TypeChangeEmail {
			t.Fatalf("verified current request err=%v body=%s message=%#v", err, response.Body(), message)
		}
		if record := findCompatibilityVerification(t, harness, Identifier(TypeEmailVerification, "valid-current@example.com")); record != nil {
			t.Fatalf("current-email OTP was not consumed: %#v", record)
		}
	})

	t.Run("change/should change email with otp", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		harness.seedUser(t, "change-success", "change-success@example.com", true)
		headers := compatibilityUserHeaders("change-success")
		if response, err := requestCompatibilityEmailChange(t, harness, headers, "changed@example.com", nil); err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("request err=%v body=%s", err, response.Body())
		}
		message := harness.latestMessage(t)
		response, err := changeCompatibilityEmail(t, harness, headers, "changed@example.com", message.OTP)
		if err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("change err=%v body=%s", err, response.Body())
		}
		user, _ := harness.adapter.FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: "change-success"}}})
		harness.mu.Lock()
		refreshed := append([]SessionState(nil), harness.refreshed...)
		harness.mu.Unlock()
		if user["email"] != "changed@example.com" || len(refreshed) != 1 || refreshed[0].User["email"] != "changed@example.com" {
			t.Fatalf("changed user=%#v refreshed=%#v", user, refreshed)
		}
	})

	t.Run("change/should not change email if session does not exist", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		response, err := changeCompatibilityEmail(t, harness, emptyHeaders(), "other@example.com", "123456")
		if err == nil || response.Status() != contract.StatusUnauthorized || responseCode(t, response) != "UNAUTHORIZED" {
			t.Fatalf("missing session status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("change/should not change email if session is invalid", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		response, err := changeCompatibilityEmail(t, harness, compatibilityUserHeaders("invalid-session"), "other@example.com", "123456")
		if err == nil || response.Status() != contract.StatusUnauthorized || responseCode(t, response) != "UNAUTHORIZED" {
			t.Fatalf("invalid session status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("change/should not change email if session contains different email from otp request email", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		harness.seedUser(t, "request-owner", "request-owner@example.com", true)
		harness.seedUser(t, "other-owner", "other-owner@example.com", true)
		if response, err := requestCompatibilityEmailChange(t, harness, compatibilityUserHeaders("request-owner"), "target@example.com", nil); err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("request err=%v body=%s", err, response.Body())
		}
		message := harness.latestMessage(t)
		response, err := changeCompatibilityEmail(t, harness, compatibilityUserHeaders("other-owner"), "target@example.com", message.OTP)
		if err == nil || responseCode(t, response) != ErrorInvalidOTP {
			t.Fatalf("different session err=%v body=%s", err, response.Body())
		}
	})

	t.Run("change/should not change email if new email is different from otp request email", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		harness.seedUser(t, "wrong-target", "wrong-target@example.com", true)
		headers := compatibilityUserHeaders("wrong-target")
		if response, err := requestCompatibilityEmailChange(t, harness, headers, "requested@example.com", nil); err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("request err=%v body=%s", err, response.Body())
		}
		message := harness.latestMessage(t)
		response, err := changeCompatibilityEmail(t, harness, headers, "wrong@example.com", message.OTP)
		if err == nil || responseCode(t, response) != ErrorInvalidOTP {
			t.Fatalf("wrong new email err=%v body=%s", err, response.Body())
		}
	})

	t.Run("change/should not change email if otp is invalid", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, nil)
		harness.seedUser(t, "invalid-change", "invalid-change@example.com", true)
		headers := compatibilityUserHeaders("invalid-change")
		if response, err := requestCompatibilityEmailChange(t, harness, headers, "new@example.com", nil); err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("request err=%v body=%s", err, response.Body())
		}
		message := harness.latestMessage(t)
		wrong := "000000"
		if wrong == message.OTP {
			wrong = "999999"
		}
		response, err := changeCompatibilityEmail(t, harness, headers, "new@example.com", wrong)
		if err == nil || responseCode(t, response) != ErrorInvalidOTP {
			t.Fatalf("invalid change OTP err=%v body=%s", err, response.Body())
		}
	})

	t.Run("change/should not change email if otp is expired", func(t *testing.T) {
		harness := newChangeEmailCompatibilityHarness(t, false, func(options *Options, _ *emailOTPHarness) {
			options.ExpiresIn = time.Minute
		})
		harness.seedUser(t, "expired-change", "expired-change@example.com", true)
		headers := compatibilityUserHeaders("expired-change")
		if response, err := requestCompatibilityEmailChange(t, harness, headers, "new@example.com", nil); err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("request err=%v body=%s", err, response.Body())
		}
		message := harness.latestMessage(t)
		harness.clock.Advance(61 * time.Second)
		response, err := changeCompatibilityEmail(t, harness, headers, "new@example.com", message.OTP)
		if err == nil || responseCode(t, response) != ErrorOTPExpired {
			t.Fatalf("expired change OTP err=%v body=%s", err, response.Body())
		}
	})

	t.Run("change/should call beforeEmailVerification callback when email is updated", func(t *testing.T) {
		var calls atomic.Int64
		harness := newChangeEmailCompatibilityHarness(t, false, func(options *Options, _ *emailOTPHarness) {
			options.Runtime.BeforeEmailVerification = func(_ context.Context, _ *engine.Context, user storage.Record) error {
				if user["email"] != "before@example.com" {
					t.Fatalf("before user=%#v", user)
				}
				calls.Add(1)
				return nil
			}
		})
		harness.seedUser(t, "before-user", "before@example.com", true)
		headers := compatibilityUserHeaders("before-user")
		_, _ = requestCompatibilityEmailChange(t, harness, headers, "before-new@example.com", nil)
		message := harness.latestMessage(t)
		response, err := changeCompatibilityEmail(t, harness, headers, "before-new@example.com", message.OTP)
		if err != nil || responseObject(t, response)["success"] != true || calls.Load() != 1 {
			t.Fatalf("before hook err=%v calls=%d body=%s", err, calls.Load(), response.Body())
		}
	})

	t.Run("change/should call afterEmailVerification callback when email is updated", func(t *testing.T) {
		var calls atomic.Int64
		harness := newChangeEmailCompatibilityHarness(t, false, func(options *Options, _ *emailOTPHarness) {
			options.Runtime.AfterEmailVerification = func(_ context.Context, _ *engine.Context, user storage.Record) error {
				verified, _ := recordBool(user, "emailVerified")
				if user["email"] != "after-new@example.com" || !verified {
					t.Fatalf("after user=%#v", user)
				}
				calls.Add(1)
				return nil
			}
		})
		harness.seedUser(t, "after-user", "after@example.com", true)
		headers := compatibilityUserHeaders("after-user")
		_, _ = requestCompatibilityEmailChange(t, harness, headers, "after-new@example.com", nil)
		message := harness.latestMessage(t)
		response, err := changeCompatibilityEmail(t, harness, headers, "after-new@example.com", message.OTP)
		if err != nil || responseObject(t, response)["success"] != true || calls.Load() != 1 {
			t.Fatalf("after hook err=%v calls=%d body=%s", err, calls.Load(), response.Body())
		}
	})
}
