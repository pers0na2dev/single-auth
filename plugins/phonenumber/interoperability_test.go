package phonenumber

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
)

func TestSignInErrorsPasswordAndPhoneUniqueness(t *testing.T) {
	store := newCaptureStore()
	auth, _ := newRootHarness(t, standardOptions(store), nil)
	missing := exchange(t, auth, http.MethodPost, "/sign-in/phone-number", "", map[string]any{
		"phoneNumber": "+15550000000", "password": "password123",
	})
	if missing.status != http.StatusUnauthorized || errorCode(missing) != CodeInvalidPhoneOrPassword {
		t.Fatalf("missing status=%d body=%#v", missing.status, missing.body)
	}

	phone := "+15550000001"
	signedUp := exchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"email": "password-phone@example.com", "name": "Password Phone", "password": "password123",
		"phoneNumber": phone,
	})
	if signedUp.status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%#v", signedUp.status, signedUp.body)
	}
	wrong := exchange(t, auth, http.MethodPost, "/sign-in/phone-number", "", map[string]any{
		"phoneNumber": phone, "password": "wrong-password",
	})
	if wrong.status != http.StatusUnauthorized || errorCode(wrong) != CodeInvalidPhoneOrPassword {
		t.Fatalf("wrong status=%d body=%#v", wrong.status, wrong.body)
	}
	valid := exchange(t, auth, http.MethodPost, "/sign-in/phone-number", "", map[string]any{
		"phoneNumber": phone, "password": "password123", "rememberMe": false,
	})
	if valid.status != http.StatusOK || bodyString(t, valid.body, "token") == "" {
		t.Fatalf("valid status=%d body=%#v", valid.status, valid.body)
	}

	// A second authenticated user cannot claim a number already owned by the
	// credential user, even with a valid freshly-issued OTP.
	second := exchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"email": "second-phone@example.com", "name": "Second", "password": "password123",
	})
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", second.cookie, map[string]any{"phoneNumber": phone})
	duplicate := exchange(t, auth, http.MethodPost, "/phone-number/verify", second.cookie, map[string]any{
		"phoneNumber": phone, "code": store.code(phone), "updatePhoneNumber": true,
	})
	if duplicate.status != http.StatusBadRequest || errorCode(duplicate) != CodePhoneNumberExists {
		t.Fatalf("duplicate status=%d body=%#v", duplicate.status, duplicate.body)
	}
}

func TestUnknownResetDoesNotSendAndUnknownVerificationNeedsSignUpOption(t *testing.T) {
	var resetSends atomic.Int64
	options := Options{
		SendOTP: func(context.Context, OTPMessage, *engine.Context) error { return nil },
		SendPasswordResetOTP: func(context.Context, OTPMessage, *engine.Context) error {
			resetSends.Add(1)
			return nil
		},
	}
	auth, _ := newRootHarness(t, options, nil)
	unknown := "+15558880000"
	reset := exchange(t, auth, http.MethodPost, "/phone-number/request-password-reset", "", map[string]any{
		"phoneNumber": unknown,
	})
	if reset.status != http.StatusOK || reset.body["status"] != true || resetSends.Load() != 0 {
		t.Fatalf("unknown reset status=%d body=%#v sends=%d", reset.status, reset.body, resetSends.Load())
	}

	var code string
	options.SendOTP = func(_ context.Context, message OTPMessage, _ *engine.Context) error {
		code = message.Code
		return nil
	}
	auth, _ = newRootHarness(t, options, nil)
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": unknown})
	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": unknown, "code": code,
	})
	if verified.status != http.StatusInternalServerError || errorCode(verified) != string(singleauth.ErrorFailedToUpdateUser) {
		t.Fatalf("verify status=%d body=%#v", verified.status, verified.body)
	}
}

func TestPhoneNumberAndEmailOTPFactoriesCoexist(t *testing.T) {
	store := newCaptureStore()
	phoneOptions := standardOptions(store)
	var emailMessage emailotp.OTPMessage
	auth, _ := newRootHarness(t, phoneOptions, func(root *singleauth.Options) {
		root.PluginFactories = []singleauth.PluginFactory{
			NewFactory(phoneOptions),
			emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
					emailMessage = message
					return nil
				},
			}),
		}
	})
	phone := "+15557770000"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	phoneVerified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone), "disableSession": true,
	})
	if phoneVerified.status != http.StatusOK {
		t.Fatalf("phone verify status=%d body=%#v", phoneVerified.status, phoneVerified.body)
	}

	email := "otp-coexist@example.com"
	emailSent := exchange(t, auth, http.MethodPost, "/email-otp/send-verification-otp", "", map[string]any{
		"email": email, "type": "sign-in",
	})
	if emailSent.status != http.StatusOK || emailMessage.Email != email || emailMessage.OTP == "" {
		t.Fatalf("email send status=%d body=%#v message=%#v", emailSent.status, emailSent.body, emailMessage)
	}
	emailVerified := exchange(t, auth, http.MethodPost, "/sign-in/email-otp", "", map[string]any{
		"email": email, "otp": emailMessage.OTP, "name": "Email OTP",
	})
	if emailVerified.status != http.StatusOK || bodyString(t, emailVerified.body, "token") == "" {
		t.Fatalf("email verify status=%d body=%#v", emailVerified.status, emailVerified.body)
	}
}

func TestRunInBackgroundOrAwaitSwallowsDeliveryFailures(t *testing.T) {
	providerError := context.Canceled
	options := Options{
		SendOTP:              func(context.Context, OTPMessage, *engine.Context) error { return providerError },
		SendPasswordResetOTP: func(context.Context, OTPMessage, *engine.Context) error { return providerError },
		RequireVerification:  true,
	}
	auth, _ := newRootHarness(t, options, nil)
	phone := "+15556660000"
	signUp := exchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"email": "background-await@example.com", "name": "Background", "password": "password123",
		"phoneNumber": phone,
	})
	if signUp.status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%#v", signUp.status, signUp.body)
	}
	signIn := exchange(t, auth, http.MethodPost, "/sign-in/phone-number", "", map[string]any{
		"phoneNumber": phone, "password": "password123",
	})
	if signIn.status != http.StatusUnauthorized || errorCode(signIn) != CodePhoneNumberNotVerified {
		t.Fatalf("sign-in status=%d body=%#v", signIn.status, signIn.body)
	}
	requested := exchange(t, auth, http.MethodPost, "/phone-number/request-password-reset", "", map[string]any{
		"phoneNumber": phone,
	})
	if requested.status != http.StatusOK || requested.body["status"] != true {
		t.Fatalf("request status=%d body=%#v", requested.status, requested.body)
	}
}
