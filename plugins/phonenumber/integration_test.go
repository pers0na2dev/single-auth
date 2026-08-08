package phonenumber

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/additionalfields"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
	"github.com/pers0na2dev/single-auth/storage"
)

func standardOptions(store *captureStore) Options {
	return Options{
		SendOTP: store.sendOTP,
		SendPasswordResetOTP: func(_ context.Context, message OTPMessage, _ *engine.Context) error {
			store.mu.Lock()
			store.resetOTP[message.PhoneNumber] = message.Code
			store.mu.Unlock()
			return nil
		},
		SignUpOnVerification: &SignUpOnVerificationOptions{
			GetTempEmail: func(phone string) string { return "temp-" + phone + "@example.com" },
		},
	}
}

func TestPhoneNumberSendVerifyReplayUpdateAndExpiry(t *testing.T) {
	store := newCaptureStore()
	var callbacks atomic.Int64
	options := standardOptions(store)
	options.CallbackOnVerification = func(_ context.Context, event VerificationEvent, _ *engine.Context) error {
		if event.PhoneNumber == "" || event.User["phoneNumberVerified"] != true {
			return errors.New("invalid callback event")
		}
		callbacks.Add(1)
		return nil
	}
	auth, clock := newRootHarness(t, options, nil)
	phone := "+251911121314"

	sent := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{
		"phoneNumber": phone,
	})
	if sent.status != http.StatusOK || sent.body["message"] != "code sent" || len(store.code(phone)) != 6 {
		t.Fatalf("send status=%d body=%#v code=%q", sent.status, sent.body, store.code(phone))
	}

	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	if verified.status != http.StatusOK || verified.body["status"] != true {
		t.Fatalf("verify status=%d body=%#v", verified.status, verified.body)
	}
	if bodyString(t, verified.body, "token") == "" || !strings.Contains(verified.cookie, "session_token=") {
		t.Fatalf("verify token/cookie missing: body=%#v cookie=%q", verified.body, verified.cookie)
	}
	user := bodyObject(t, verified.body, "user")
	if user["phoneNumber"] != phone || user["phoneNumberVerified"] != true || user["email"] != "temp-"+phone+"@example.com" {
		t.Fatalf("verified user = %#v", user)
	}
	if callbacks.Load() != 1 {
		t.Fatalf("callback count = %d", callbacks.Load())
	}

	replay := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	if replay.status != http.StatusBadRequest || errorCode(replay) != CodeOTPNotFound {
		t.Fatalf("replay status=%d body=%#v", replay.status, replay.body)
	}

	newPhone := "+0123456789"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", verified.cookie, map[string]any{"phoneNumber": newPhone})
	updated := exchange(t, auth, http.MethodPost, "/phone-number/verify", verified.cookie, map[string]any{
		"phoneNumber": newPhone, "code": store.code(newPhone), "updatePhoneNumber": true,
	})
	if updated.status != http.StatusOK || bodyObject(t, updated.body, "user")["phoneNumber"] != newPhone {
		t.Fatalf("update status=%d body=%#v", updated.status, updated.body)
	}
	if callbacks.Load() != 2 {
		t.Fatalf("callback count after update = %d", callbacks.Load())
	}

	expiredPhone := "+25120201212"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": expiredPhone})
	clock.Advance(5*time.Minute + time.Nanosecond)
	expired := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": expiredPhone, "code": store.code(expiredPhone),
	})
	if expired.status != http.StatusBadRequest || errorCode(expired) != CodeOTPExpired {
		t.Fatalf("expired status=%d body=%#v", expired.status, expired.body)
	}
}

func TestPhoneAuthFlowPasswordAndEmailRemainInteroperable(t *testing.T) {
	store := newCaptureStore()
	auth, _ := newRootHarness(t, standardOptions(store), func(options *singleauth.Options) {
		options.User.ChangeEmail.Enabled = true
		options.User.ChangeEmail.UpdateEmailWithoutVerification = true
		options.PluginFactories = append(options.PluginFactories, bearer.NewFactory(bearer.Options{}))
	})
	phone := "+251911121314"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	if verified.status != http.StatusOK {
		t.Fatalf("verify status=%d body=%#v", verified.status, verified.body)
	}
	token := bodyString(t, verified.body, "token")
	bearerRequest := httptest.NewRequest(http.MethodGet, testBaseURL+"/api/auth/get-session", nil)
	bearerRequest.Header.Set("Authorization", "Bearer "+token)
	bearerRecorder := httptest.NewRecorder()
	auth.ServeHTTP(bearerRecorder, bearerRequest)
	if bearerRecorder.Code != http.StatusOK || !strings.Contains(bearerRecorder.Body.String(), `"phoneNumberVerified":true`) {
		t.Fatalf("bearer session status=%d body=%s", bearerRecorder.Code, bearerRecorder.Body.String())
	}

	// Re-running send/verify for the existing user signs that same identity in
	// again and issues a fresh session.
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	existingSignIn := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	if existingSignIn.status != http.StatusOK || bodyString(t, existingSignIn.body, "token") == "" {
		t.Fatalf("existing verify status=%d body=%#v", existingSignIn.status, existingSignIn.body)
	}

	setBody, _ := json.Marshal(map[string]any{"newPassword": "password"})
	directHeaders := contract.NewHeaders(
		contract.HeaderField{Name: "Content-Type", Value: "application/json"},
		contract.HeaderField{Name: "Cookie", Value: existingSignIn.cookie},
	)
	setPassword, err := auth.Invoke("setPassword", engine.DirectInput{Request: contract.NewRequest(
		http.MethodPost, "/api/auth/:virtual", contract.RequestOptions{Headers: directHeaders, Body: setBody},
	)})
	if err != nil || setPassword.Status() != http.StatusOK {
		t.Fatalf("set password status=%d body=%s err=%v", setPassword.Status(), setPassword.Body(), err)
	}
	newEmail := "new-email@email.com"
	changed := exchange(t, auth, http.MethodPost, "/change-email", existingSignIn.cookie, map[string]any{
		"newEmail": newEmail,
	})
	if changed.status != http.StatusOK || changed.body["status"] != true {
		t.Fatalf("change email status=%d body=%#v", changed.status, changed.body)
	}

	phoneSignIn := exchange(t, auth, http.MethodPost, "/sign-in/phone-number", "", map[string]any{
		"phoneNumber": phone, "password": "password",
	})
	if phoneSignIn.status != http.StatusOK || bodyString(t, phoneSignIn.body, "token") == "" {
		t.Fatalf("phone sign-in status=%d body=%#v", phoneSignIn.status, phoneSignIn.body)
	}
	emailSignIn := exchange(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": newEmail, "password": "password",
	})
	if emailSignIn.status != http.StatusOK || bodyString(t, emailSignIn.body, "token") == "" {
		t.Fatalf("email sign-in status=%d body=%#v", emailSignIn.status, emailSignIn.body)
	}
}

func TestVerificationAttemptsLatestCodeAndAtomicRace(t *testing.T) {
	store := newCaptureStore()
	auth, clock := newRootHarness(t, standardOptions(store), nil)
	phone := "+251900000001"
	var first, second string
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	first = store.code(phone)
	clock.Advance(time.Second)
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	second = store.code(phone)
	if first == second {
		// A random collision is valid but makes the last-code assertion useless.
		t.Skip("random OTP collision")
	}
	old := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": first,
	})
	if old.status != http.StatusBadRequest || errorCode(old) != CodeInvalidOTP {
		t.Fatalf("old code status=%d body=%#v", old.status, old.body)
	}
	latest := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": second,
	})
	if latest.status != http.StatusOK {
		t.Fatalf("latest code status=%d body=%#v", latest.status, latest.body)
	}

	attemptPhone := "+251900000002"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": attemptPhone})
	correct := store.code(attemptPhone)
	wrong := "000000"
	if wrong == correct {
		wrong = "999999"
	}
	for attempt := 0; attempt < 3; attempt++ {
		result := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
			"phoneNumber": attemptPhone, "code": wrong,
		})
		if result.status != http.StatusBadRequest || errorCode(result) != CodeInvalidOTP {
			t.Fatalf("attempt %d status=%d body=%#v", attempt, result.status, result.body)
		}
		row, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: attemptPhone}},
		})
		if err != nil || row == nil || row["value"] != correct+":"+string(rune('1'+attempt)) {
			t.Fatalf("attempt %d row=%#v err=%v", attempt, row, err)
		}
	}
	blocked := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": attemptPhone, "code": wrong,
	})
	if blocked.status != http.StatusForbidden || errorCode(blocked) != CodeTooManyAttempts {
		t.Fatalf("blocked status=%d body=%#v", blocked.status, blocked.body)
	}

	racePhone := "+251900000003"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": racePhone})
	code := store.code(racePhone)
	results := make(chan httpResult, 2)
	for range 2 {
		go func() {
			results <- exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
				"phoneNumber": racePhone, "code": code,
			})
		}()
	}
	successes, failures := 0, 0
	for range 2 {
		result := <-results
		if result.status == http.StatusOK {
			successes++
		} else if result.status == http.StatusBadRequest &&
			(errorCode(result) == CodeOTPNotFound || errorCode(result) == CodeInvalidOTP) {
			failures++
		} else {
			t.Fatalf("race status=%d body=%#v", result.status, result.body)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("race successes=%d failures=%d", successes, failures)
	}
}

func TestRequireVerificationSendsOTPAndBlocksSignIn(t *testing.T) {
	store := newCaptureStore()
	options := standardOptions(store)
	options.RequireVerification = true
	auth, _ := newRootHarness(t, options, nil)
	phone := "+251911000111"
	signUp := exchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"email": "unverified-phone@example.com", "name": "Test", "password": "password123",
		"phoneNumber": phone,
	})
	if signUp.status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%#v", signUp.status, signUp.body)
	}
	signIn := exchange(t, auth, http.MethodPost, "/sign-in/phone-number", "", map[string]any{
		"phoneNumber": phone, "password": "password123",
	})
	if signIn.status != http.StatusUnauthorized || errorCode(signIn) != CodePhoneNumberNotVerified || len(store.code(phone)) != 6 {
		t.Fatalf("sign-in status=%d body=%#v otp=%q", signIn.status, signIn.body, store.code(phone))
	}
}

func TestUpdateUserPreventionDisassociationAndReclaim(t *testing.T) {
	store := newCaptureStore()
	auth, _ := newRootHarness(t, standardOptions(store), nil)
	phone := "+251911121314"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	original := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	forbidden := exchange(t, auth, http.MethodPost, "/update-user", original.cookie, map[string]any{
		"phoneNumber": "+9876543210",
	})
	if forbidden.status != http.StatusBadRequest || errorCode(forbidden) != CodePhoneNumberCannotBeUpdated {
		t.Fatalf("forbidden status=%d body=%#v", forbidden.status, forbidden.body)
	}
	disassociated := exchange(t, auth, http.MethodPost, "/update-user", original.cookie, map[string]any{
		"phoneNumber": nil,
	})
	if disassociated.status != http.StatusOK {
		t.Fatalf("disassociate status=%d body=%#v", disassociated.status, disassociated.body)
	}
	session := exchange(t, auth, http.MethodGet, "/get-session", disassociated.cookie, nil)
	user := bodyObject(t, session.body, "user")
	if user["phoneNumber"] != nil || user["phoneNumberVerified"] != false {
		t.Fatalf("disassociated user = %#v", user)
	}

	reclaimer := exchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"email": "reclaimer@example.com", "name": "Reclaimer", "password": "password123",
	})
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", reclaimer.cookie, map[string]any{"phoneNumber": phone})
	claimed := exchange(t, auth, http.MethodPost, "/phone-number/verify", reclaimer.cookie, map[string]any{
		"phoneNumber": phone, "code": store.code(phone), "updatePhoneNumber": true,
	})
	if claimed.status != http.StatusOK || bodyObject(t, claimed.body, "user")["phoneNumber"] != phone {
		t.Fatalf("claim status=%d body=%#v", claimed.status, claimed.body)
	}
	originalSession := exchange(t, auth, http.MethodGet, "/get-session", disassociated.cookie, nil)
	if bodyObject(t, originalSession.body, "user")["phoneNumber"] != nil {
		t.Fatalf("original user reclaimed number: %#v", originalSession.body)
	}
}

func TestSignUpOnVerificationPreservesAdditionalFieldsAndDisableSession(t *testing.T) {
	store := newCaptureStore()
	options := standardOptions(store)
	auth, _ := newRootHarness(t, options, func(root *singleauth.Options) {
		root.PluginFactories = []singleauth.PluginFactory{
			NewFactory(options),
			additionalfields.NewFactory(additionalfields.Options{User: additionalfields.Fields{
				{Name: "lastName", Attribute: storage.FieldAttribute{Type: storage.FieldString}},
				{Name: "dateOfBirth", Attribute: storage.FieldAttribute{Type: storage.FieldDate, Required: storage.Bool(false)}},
			}}),
		}
	})
	phone := "+1234567890"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone), "lastName": "Doe", "disableSession": true,
	})
	if verified.status != http.StatusOK || verified.body["token"] != nil {
		t.Fatalf("verify status=%d body=%#v", verified.status, verified.body)
	}
	user := bodyObject(t, verified.body, "user")
	if user["lastName"] != "Doe" || user["dateOfBirth"] != nil {
		t.Fatalf("additional user = %#v", user)
	}
}

func TestCustomVerifyOTPBypassesInternalStoreAndUpdatesPhone(t *testing.T) {
	store := newCaptureStore()
	var calls atomic.Int64
	options := standardOptions(store)
	options.VerifyOTP = func(_ context.Context, message OTPMessage, _ *engine.Context) (bool, error) {
		calls.Add(1)
		return message.Code != "wrong-code", nil
	}
	auth, _ := newRootHarness(t, options, nil)
	phone := "+1234567890"
	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": "external-code",
	})
	if verified.status != http.StatusOK {
		t.Fatalf("external verify status=%d body=%#v", verified.status, verified.body)
	}
	invalid := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": "+9876543210", "code": "wrong-code",
	})
	if invalid.status != http.StatusBadRequest || errorCode(invalid) != CodeInvalidOTP {
		t.Fatalf("invalid status=%d body=%#v", invalid.status, invalid.body)
	}
	updated := exchange(t, auth, http.MethodPost, "/phone-number/verify", verified.cookie, map[string]any{
		"phoneNumber": "+1111111111", "code": "external-code", "updatePhoneNumber": true,
	})
	if updated.status != http.StatusOK || bodyObject(t, updated.body, "user")["phoneNumber"] != "+1111111111" {
		t.Fatalf("updated status=%d body=%#v", updated.status, updated.body)
	}
	if calls.Load() != 3 {
		t.Fatalf("verify callback calls = %d", calls.Load())
	}
}
