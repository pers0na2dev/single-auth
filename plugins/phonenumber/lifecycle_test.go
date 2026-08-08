package phonenumber

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestSendOTPErrorAndBackgroundTaskSemantics(t *testing.T) {
	providerError := errors.New("SMS provider error")
	t.Run("without background tasks provider failure is returned", func(t *testing.T) {
		var calls atomic.Int64
		auth, _ := newRootHarness(t, Options{SendOTP: func(context.Context, OTPMessage, *engine.Context) error {
			calls.Add(1)
			return providerError
		}}, nil)
		result := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{
			"phoneNumber": "+251922334455",
		})
		if calls.Load() != 1 || result.status != http.StatusInternalServerError || result.body != nil && result.body["code"] != "INTERNAL_SERVER_ERROR" {
			t.Fatalf("calls=%d status=%d body=%#v", calls.Load(), result.status, result.body)
		}
	})

	t.Run("provider failure in configured background task is swallowed", func(t *testing.T) {
		var sends atomic.Int64
		var scheduled atomic.Int64
		auth, _ := newRootHarness(t, Options{SendOTP: func(context.Context, OTPMessage, *engine.Context) error {
			sends.Add(1)
			return providerError
		}}, func(options *singleauth.Options) {
			options.RunBackground = func(ctx context.Context, work func(context.Context) error) error {
				scheduled.Add(1)
				return work(ctx)
			}
		})
		result := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{
			"phoneNumber": "+251955667788",
		})
		if sends.Load() != 1 || scheduled.Load() != 1 || result.status != http.StatusOK || result.body["message"] != "code sent" {
			t.Fatalf("sends=%d scheduled=%d status=%d body=%#v", sends.Load(), scheduled.Load(), result.status, result.body)
		}
	})

	t.Run("background handler failure is swallowed", func(t *testing.T) {
		var sends atomic.Int64
		var scheduled atomic.Int64
		auth, _ := newRootHarness(t, Options{SendOTP: func(context.Context, OTPMessage, *engine.Context) error {
			sends.Add(1)
			return nil
		}}, func(options *singleauth.Options) {
			options.RunBackground = func(context.Context, func(context.Context) error) error {
				scheduled.Add(1)
				return errors.New("Background task handler error")
			}
		})
		result := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{
			"phoneNumber": "+251988776655",
		})
		if sends.Load() != 1 || scheduled.Load() != 1 || result.status != http.StatusOK || result.body["message"] != "code sent" {
			t.Fatalf("sends=%d scheduled=%d status=%d body=%#v", sends.Load(), scheduled.Load(), result.status, result.body)
		}
	})
}

func TestPhoneNumberValidatorAndMissingSender(t *testing.T) {
	t.Run("sendOTP missing", func(t *testing.T) {
		auth, _ := newRootHarness(t, Options{}, nil)
		result := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{
			"phoneNumber": "+15551234567",
		})
		if result.status != http.StatusNotImplemented || errorCode(result) != CodeSendOTPNotImplemented {
			t.Fatalf("status=%d body=%#v", result.status, result.body)
		}
	})

	t.Run("custom validator", func(t *testing.T) {
		store := newCaptureStore()
		options := standardOptions(store)
		options.PhoneNumberValidator = func(phone string) (bool, error) {
			return strings.HasPrefix(phone, "+251"), nil
		}
		auth, _ := newRootHarness(t, options, nil)
		invalid := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{
			"phoneNumber": "+15551234567",
		})
		if invalid.status != http.StatusBadRequest || errorCode(invalid) != CodeInvalidPhoneNumber {
			t.Fatalf("invalid status=%d body=%#v", invalid.status, invalid.body)
		}
		valid := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{
			"phoneNumber": "+251911000000",
		})
		if valid.status != http.StatusOK {
			t.Fatalf("valid status=%d body=%#v", valid.status, valid.body)
		}
	})
}

func TestPasswordResetAttemptsSuccessCredentialCreationReplayCallbacksAndRevocation(t *testing.T) {
	store := newCaptureStore()
	var resetCallbacks atomic.Int64
	options := standardOptions(store)
	auth, _ := newRootHarness(t, options, func(root *singleauth.Options) {
		root.EmailAndPassword.RevokeSessionsOnReset = true
		root.EmailAndPassword.OnPasswordReset = func(_ context.Context, user model.User) error {
			if _, exists := user.AdditionalFields["phoneNumber"]; !exists {
				return errors.New("phone missing from callback user")
			}
			resetCallbacks.Add(1)
			return nil
		}
	})
	phone := "+251911000000"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	if verified.status != http.StatusOK {
		t.Fatalf("verify status=%d body=%#v", verified.status, verified.body)
	}
	exchange(t, auth, http.MethodPost, "/phone-number/request-password-reset", "", map[string]any{"phoneNumber": phone})
	resetOTP := store.resetCode(phone)
	wrong := "000000"
	if wrong == resetOTP {
		wrong = "999999"
	}
	for attempt := 0; attempt < 3; attempt++ {
		result := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
			"phoneNumber": phone, "otp": wrong, "newPassword": "password",
		})
		if result.status != http.StatusBadRequest || errorCode(result) != CodeInvalidOTP {
			t.Fatalf("wrong attempt %d status=%d body=%#v", attempt, result.status, result.body)
		}
	}
	blocked := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
		"phoneNumber": phone, "otp": wrong, "newPassword": "password",
	})
	if blocked.status != http.StatusForbidden || errorCode(blocked) != CodeTooManyAttempts {
		t.Fatalf("blocked status=%d body=%#v", blocked.status, blocked.body)
	}

	exchange(t, auth, http.MethodPost, "/phone-number/request-password-reset", "", map[string]any{"phoneNumber": phone})
	resetOTP = store.resetCode(phone)
	reset := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
		"phoneNumber": phone, "otp": resetOTP, "newPassword": "new-secure-password",
	})
	if reset.status != http.StatusOK || reset.body["status"] != true || resetCallbacks.Load() != 1 {
		t.Fatalf("reset status=%d body=%#v callbacks=%d", reset.status, reset.body, resetCallbacks.Load())
	}
	replay := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
		"phoneNumber": phone, "otp": resetOTP, "newPassword": "another-password",
	})
	if replay.status != http.StatusBadRequest || errorCode(replay) != CodeOTPNotFound {
		t.Fatalf("replay status=%d body=%#v", replay.status, replay.body)
	}
	signIn := exchange(t, auth, http.MethodPost, "/sign-in/phone-number", "", map[string]any{
		"phoneNumber": phone, "password": "new-secure-password",
	})
	if signIn.status != http.StatusOK || bodyString(t, signIn.body, "token") == "" {
		t.Fatalf("sign-in status=%d body=%#v", signIn.status, signIn.body)
	}
	oldSession := exchange(t, auth, http.MethodGet, "/get-session", verified.cookie, nil)
	if oldSession.body != nil {
		t.Fatalf("old session survived reset: %#v", oldSession.body)
	}

	secondPhone := "+2519111213142"
	_, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "user", ForceAllowID: true,
		Data: storage.Record{
			"id": "user-without-credential", "name": "Test User", "email": "test-user2@email.com",
			"emailVerified": true, "phoneNumber": secondPhone, "phoneNumberVerified": false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, auth, http.MethodPost, "/phone-number/request-password-reset", "", map[string]any{"phoneNumber": secondPhone})
	created := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
		"phoneNumber": secondPhone, "otp": store.resetCode(secondPhone), "newPassword": "password123",
	})
	if created.status != http.StatusOK {
		t.Fatalf("credential create status=%d body=%#v", created.status, created.body)
	}
	emailSignIn := exchange(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": "test-user2@email.com", "password": "password123",
	})
	if emailSignIn.status != http.StatusOK {
		t.Fatalf("created credential sign-in status=%d body=%#v", emailSignIn.status, emailSignIn.body)
	}
}

func TestPasswordResetLengthValidationOccursAfterSingleUseOTPConsumption(t *testing.T) {
	store := newCaptureStore()
	auth, _ := newRootHarness(t, standardOptions(store), nil)
	phone := "+15550000001"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone), "disableSession": true,
	})
	exchange(t, auth, http.MethodPost, "/phone-number/request-password-reset", "", map[string]any{"phoneNumber": phone})
	code := store.resetCode(phone)
	tooShort := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
		"phoneNumber": phone, "otp": code, "newPassword": "short",
	})
	if tooShort.status != http.StatusBadRequest || errorCode(tooShort) != string(singleauth.ErrorPasswordTooShort) {
		t.Fatalf("short status=%d body=%#v", tooShort.status, tooShort.body)
	}
	replay := exchange(t, auth, http.MethodPost, "/phone-number/reset-password", "", map[string]any{
		"phoneNumber": phone, "otp": code, "newPassword": "long-enough-password",
	})
	if replay.status != http.StatusBadRequest || errorCode(replay) != CodeOTPNotFound {
		t.Fatalf("consumed replay status=%d body=%#v", replay.status, replay.body)
	}
}
