package emailotp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func sendCompatibilityOTP(t *testing.T, harness *emailOTPHarness, email string, otpType OTPType) OTPMessage {
	t.Helper()
	response, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
		"email": email, "type": string(otpType),
	})
	if err != nil || response.Status() != contract.StatusOK || responseObject(t, response)["success"] != true {
		t.Fatalf("send OTP status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	return harness.latestMessage(t)
}

func invokeCreateCompatibilityOTP(t *testing.T, harness *emailOTPHarness, email string, otpType OTPType) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"email": email, "type": string(otpType)})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.NewRequest("POST", "/", contract.RequestOptions{
		Context: context.Background(), Body: body,
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
	})
	response, err := harness.dispatcher.Invoke("createVerificationOTP", engine.DirectInput{Request: request})
	if err != nil || response.Status() != contract.StatusOK {
		t.Fatalf("create OTP status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	var otp string
	if err := json.Unmarshal(response.Body(), &otp); err != nil || otp == "" {
		t.Fatalf("create OTP body=%s decoded=%q err=%v", response.Body(), otp, err)
	}
	return otp
}

func invokeGetCompatibilityOTP(t *testing.T, harness *emailOTPHarness, email string, otpType OTPType) (contract.Response, error) {
	t.Helper()
	request := contract.NewRequest("GET", "/", contract.RequestOptions{RawQuery: url.Values{
		"email": {email}, "type": {string(otpType)},
	}.Encode()})
	return harness.dispatcher.Invoke("getVerificationOTP", engine.DirectInput{Request: request})
}

func findCompatibilityVerification(t *testing.T, harness *emailOTPHarness, identifier string) storage.Record {
	t.Helper()
	record, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestUpstreamEmailOTPCoreRuntime(t *testing.T) {
	t.Run("should verify email with otp", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.AutoSignInAfterVerification = true
		})
		harness.seedUser(t, "verify-user", "verify@example.com", false)
		message := sendCompatibilityOTP(t, harness, "verify@example.com", TypeEmailVerification)
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
			"email": "verify@example.com", "otp": message.OTP,
		})
		body := responseObject(t, response)
		if err != nil || body["status"] != true || body["token"] == nil || harness.issuedSessions.Load() != 1 {
			t.Fatalf("verify response=%#v err=%v sessions=%d", body, err, harness.issuedSessions.Load())
		}
		user := body["user"].(map[string]any)
		if user["emailVerified"] != true || len(message.OTP) != defaultOTPLength {
			t.Fatalf("verified user=%#v OTP=%q", user, message.OTP)
		}
	})

	t.Run("should sign-in with otp", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "signin-user", "signin@example.com", true)
		message := sendCompatibilityOTP(t, harness, "signin@example.com", TypeSignIn)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
			"email": "signin@example.com", "otp": message.OTP,
		})
		body := responseObject(t, response)
		cookies := strings.Join(response.Headers().Values("Set-Cookie"), ";")
		if err != nil || body["token"] == "" || !strings.Contains(cookies, "single-auth.session_token=") {
			t.Fatalf("sign-in response=%#v cookies=%q err=%v", body, cookies, err)
		}
	})

	t.Run("should clear an unverified account's password when sign-in adopts it", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "adopt-user", "adopt@example.com", false)
		if _, err := harness.adapter.Create(t.Context(), storage.CreateParams{Model: "account", Data: storage.Record{
			"userId": "adopt-user", "providerId": "credential", "accountId": "adopt-user", "password": "existing-hash",
		}}); err != nil {
			t.Fatal(err)
		}
		if _, err := harness.adapter.Create(t.Context(), storage.CreateParams{Model: "session", Data: storage.Record{
			"userId": "adopt-user", "token": "unproven-session", "expiresAt": harness.clock.Now().Add(time.Hour),
		}}); err != nil {
			t.Fatal(err)
		}
		message := sendCompatibilityOTP(t, harness, "adopt@example.com", TypeSignIn)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
			"email": "adopt@example.com", "otp": message.OTP,
		})
		if err != nil || responseObject(t, response)["token"] == "" {
			t.Fatalf("adopt sign-in err=%v body=%s", err, response.Body())
		}
		account, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "account", Where: []storage.Where{{Field: "userId", Value: "adopt-user"}, {Field: "providerId", Value: "credential"}},
		})
		if err != nil || account != nil {
			t.Fatalf("credential account=%#v err=%v", account, err)
		}
		user, _ := harness.adapter.FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: "adopt-user"}}})
		verified, _ := recordBool(user, "emailVerified")
		if !verified {
			t.Fatalf("adopted user=%#v", user)
		}
	})

	t.Run("should sign-up with otp", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "signup@example.com", TypeSignIn)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
			"email": "signup@example.com", "otp": message.OTP,
		})
		body := responseObject(t, response)
		if err != nil || body["token"] == "" || body["user"].(map[string]any)["email"] != "signup@example.com" {
			t.Fatalf("sign-up response=%#v err=%v", body, err)
		}
	})

	t.Run("should sign-up with otp and set name and image", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "profile@example.com", TypeSignIn)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
			"email": "profile@example.com", "otp": message.OTP, "name": "Test User", "image": "https://example.com/avatar.png",
		})
		user := responseObject(t, response)["user"].(map[string]any)
		if err != nil || user["name"] != "Test User" || user["image"] != "https://example.com/avatar.png" {
			t.Fatalf("profile user=%#v err=%v", user, err)
		}
	})

	t.Run("should sign-up with uppercase email", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "UPPER@EXAMPLE.COM", TypeSignIn)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
			"email": "UPPER@EXAMPLE.COM", "otp": message.OTP,
		})
		user := responseObject(t, response)["user"].(map[string]any)
		if err != nil || user["email"] != "upper@example.com" {
			t.Fatalf("uppercase user=%#v err=%v", user, err)
		}
	})

	t.Run("should sign-up with varying case email", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		message := sendCompatibilityOTP(t, harness, "mixed@example.com", TypeSignIn)
		response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{
			"email": "MIXED@EXAMPLE.COM", "otp": message.OTP,
		})
		if err != nil || responseObject(t, response)["token"] == "" {
			t.Fatalf("varying-case err=%v body=%s", err, response.Body())
		}
	})

	t.Run("should send verification otp on sign-up", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.SendVerificationOnSignUp = true
		})
		base := engine.Endpoint{
			Name: "signUpEmail", Path: "/sign-up/email", Methods: []string{"POST"},
			Handler: func(*engine.Context) (contract.Response, error) {
				return contract.JSONResponse(contract.StatusOK, map[string]any{"user": map[string]any{"email": "hook@example.com"}})
			},
		}
		registry, err := engine.NewRegistry([]engine.Endpoint{base}, harness.descriptor)
		if err != nil {
			t.Fatal(err)
		}
		dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
		if err != nil {
			t.Fatal(err)
		}
		response, err := dispatcher.Dispatch(contract.NewRequest("POST", "/api/auth/sign-up/email", contract.RequestOptions{}))
		if err != nil || response.Status() != contract.StatusOK {
			t.Fatalf("sign-up hook status=%d err=%v", response.Status(), err)
		}
		message := harness.latestMessage(t)
		if message.Email != "hook@example.com" || message.Type != TypeEmailVerification || message.OTP == "" {
			t.Fatalf("sign-up hook message=%#v", message)
		}
	})

	t.Run("should reset password using new emailOtp.requestPasswordReset endpoint", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.Password.Hash = func(password string) (string, error) { return "new:" + password, nil }
		})
		harness.seedUser(t, "reset-new", "reset-new@example.com", true)
		response, err := harness.call(t, "POST", "/email-otp/request-password-reset", nil, emptyHeaders(), map[string]any{"email": "reset-new@example.com"})
		if err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("request reset err=%v body=%s", err, response.Body())
		}
		otp := harness.latestMessage(t).OTP
		response, err = harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
			"email": "reset-new@example.com", "otp": otp, "password": "changed-password",
		})
		if err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("reset err=%v body=%s", err, response.Body())
		}
		account, _ := harness.adapter.FindOne(t.Context(), storage.FindOneParams{Model: "account", Where: []storage.Where{{Field: "userId", Value: "reset-new"}}})
		if account == nil || account["password"] != "new:changed-password" {
			t.Fatalf("password account=%#v", account)
		}
	})

	for _, test := range []struct {
		title    string
		password string
		code     string
	}{
		{title: "should preserve OTP after 'PASSWORD_TOO_SHORT'", password: "short", code: "PASSWORD_TOO_SHORT"},
		{title: "should preserve OTP after 'PASSWORD_TOO_LONG'", password: strings.Repeat("a", 129), code: "PASSWORD_TOO_LONG"},
	} {
		t.Run(test.title, func(t *testing.T) {
			harness := newEmailOTPHarness(t, nil)
			harness.seedUser(t, "preserve-user", "preserve@example.com", true)
			message := sendCompatibilityOTP(t, harness, "preserve@example.com", TypeForgetPassword)
			invalid, invalidErr := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
				"email": "preserve@example.com", "otp": message.OTP, "password": test.password,
			})
			if invalidErr == nil || responseCode(t, invalid) != test.code {
				t.Fatalf("invalid password err=%v body=%s", invalidErr, invalid.Body())
			}
			valid, validErr := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
				"email": "preserve@example.com", "otp": message.OTP, "password": "valid-password",
			})
			if validErr != nil || responseObject(t, valid)["success"] != true {
				t.Fatalf("preserved OTP err=%v body=%s", validErr, valid.Body())
			}
		})
	}

	t.Run("should reset password using deprecated forgetPassword endpoint (backward compatibility)", func(t *testing.T) {
		var warnings atomic.Int64
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.Runtime.Warn = func(string) { warnings.Add(1) }
			options.Password.Hash = func(password string) (string, error) { return "deprecated:" + password, nil }
		})
		harness.seedUser(t, "deprecated-user", "deprecated@example.com", true)
		response, err := harness.call(t, "POST", "/forget-password/email-otp", nil, emptyHeaders(), map[string]any{"email": "deprecated@example.com"})
		if err != nil || responseObject(t, response)["success"] != true {
			t.Fatalf("deprecated request err=%v body=%s", err, response.Body())
		}
		message := harness.latestMessage(t)
		response, err = harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
			"email": "deprecated@example.com", "otp": message.OTP, "password": "changed-password-2",
		})
		if err != nil || warnings.Load() != 1 || responseObject(t, response)["success"] != true {
			t.Fatalf("deprecated reset err=%v warnings=%d body=%s", err, warnings.Load(), response.Body())
		}
	})

	t.Run("should call onPasswordReset callback when resetting password", func(t *testing.T) {
		var callback atomic.Int64
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.Password.OnReset = func(_ context.Context, _ *engine.Context, user storage.Record) error {
				if user["email"] != "callback@example.com" {
					t.Fatalf("callback user=%#v", user)
				}
				callback.Add(1)
				return nil
			}
		})
		harness.seedUser(t, "callback-user", "callback@example.com", true)
		message := sendCompatibilityOTP(t, harness, "callback@example.com", TypeForgetPassword)
		response, err := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
			"email": "callback@example.com", "otp": message.OTP, "password": "new-password",
		})
		if err != nil || callback.Load() != 1 || responseObject(t, response)["success"] != true {
			t.Fatalf("callback reset err=%v calls=%d body=%s", err, callback.Load(), response.Body())
		}
	})

	t.Run("should reset password and create credential account", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		signIn := sendCompatibilityOTP(t, harness, "credential@example.com", TypeSignIn)
		if response, err := harness.call(t, "POST", "/sign-in/email-otp", nil, emptyHeaders(), map[string]any{"email": "credential@example.com", "otp": signIn.OTP}); err != nil || responseObject(t, response)["token"] == "" {
			t.Fatalf("initial OTP sign-up err=%v body=%s", err, response.Body())
		}
		reset := sendCompatibilityOTP(t, harness, "credential@example.com", TypeForgetPassword)
		response, err := harness.call(t, "POST", "/email-otp/reset-password", nil, emptyHeaders(), map[string]any{
			"email": "credential@example.com", "otp": reset.OTP, "password": "password",
		})
		user, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "email", Value: "credential@example.com"}},
		})
		userID, _ := recordString(user, "id")
		account, accountErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{Model: "account", Where: []storage.Where{
			{Field: "providerId", Value: "credential"}, {Field: "accountId", Value: userID},
		}})
		if err != nil || findErr != nil || accountErr != nil || responseObject(t, response)["success"] != true || account == nil || account["password"] == "" {
			t.Fatalf("credential reset err=%v findErr=%v accountErr=%v body=%s account=%#v", err, findErr, accountErr, response.Body(), account)
		}
	})

	t.Run("should fail on invalid email", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		response, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "invalid-email", "type": "email-verification",
		})
		if err == nil || response.Status() != contract.StatusBadRequest || responseCode(t, response) != "INVALID_EMAIL" {
			t.Fatalf("invalid email status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("should reject change-email type", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		response, err := harness.call(t, "POST", "/email-otp/send-verification-otp", nil, emptyHeaders(), map[string]any{
			"email": "change@example.com", "type": "change-email",
		})
		if err == nil || response.Status() != contract.StatusBadRequest || responseObject(t, response)["message"] != "Invalid OTP type" {
			t.Fatalf("change type status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("should fail on expired otp", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "expired-core", "expired-core@example.com", false)
		message := sendCompatibilityOTP(t, harness, "expired-core@example.com", TypeEmailVerification)
		harness.clock.Advance(6 * time.Minute)
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
			"email": "expired-core@example.com", "otp": message.OTP,
		})
		if err == nil || responseCode(t, response) != ErrorOTPExpired {
			t.Fatalf("expired status=%d err=%v body=%s", response.Status(), err, response.Body())
		}
	})

	t.Run("should not fail on time elapsed", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		harness.seedUser(t, "elapsed-user", "elapsed@example.com", false)
		message := sendCompatibilityOTP(t, harness, "elapsed@example.com", TypeEmailVerification)
		harness.clock.Advance(4 * time.Minute)
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
			"email": "elapsed@example.com", "otp": message.OTP,
		})
		user := responseObject(t, response)["user"].(map[string]any)
		if err != nil || user["emailVerified"] != true {
			t.Fatalf("elapsed verify user=%#v err=%v", user, err)
		}
	})

	t.Run("should create verification otp on server", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		first := invokeCreateCompatibilityOTP(t, harness, "create@example.com", TypeSignIn)
		second := invokeCreateCompatibilityOTP(t, harness, "create@example.com", TypeSignIn)
		if len(first) != defaultOTPLength || len(second) != defaultOTPLength || first == second {
			t.Fatalf("created OTPs first=%q second=%q", first, second)
		}
	})

	t.Run("should get verification otp on server", func(t *testing.T) {
		harness := newEmailOTPHarness(t, nil)
		otp := invokeCreateCompatibilityOTP(t, harness, "get@example.com", TypeSignIn)
		response, err := invokeGetCompatibilityOTP(t, harness, "GET@EXAMPLE.COM", TypeSignIn)
		if err != nil || responseObject(t, response)["otp"] != otp {
			t.Fatalf("get OTP err=%v body=%s want=%q", err, response.Body(), otp)
		}
	})

	t.Run("should work with custom options", func(t *testing.T) {
		harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
			options.OTPLength = 8
			options.ExpiresIn = 10 * time.Second
			options.GenerateOTP = nil
			options.Runtime.Random = bytes.NewReader(bytes.Repeat([]byte{7}, 64))
		})
		harness.seedUser(t, "custom-user", "custom@example.com", false)
		message := sendCompatibilityOTP(t, harness, "custom@example.com", TypeEmailVerification)
		if len(message.OTP) != 8 {
			t.Fatalf("custom OTP=%q", message.OTP)
		}
		harness.clock.Advance(11 * time.Second)
		response, err := harness.call(t, "POST", "/email-otp/verify-email", nil, emptyHeaders(), map[string]any{
			"email": "custom@example.com", "otp": message.OTP,
		})
		if err == nil || responseCode(t, response) != ErrorOTPExpired {
			t.Fatalf("custom expiry err=%v body=%s", err, response.Body())
		}
	})
}
