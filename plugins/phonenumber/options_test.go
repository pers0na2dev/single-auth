package phonenumber

import (
	"net/http"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
)

func TestSchemaAliasesAndDescriptorRateLimit(t *testing.T) {
	schema, err := Schema(Options{Schema: SchemaOptions{User: UserSchemaOptions{
		ModelName: "members", PhoneNumber: "mobile", PhoneNumberVerified: "mobile_verified",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	user := schema.Models["user"]
	phone := user.Fields["phoneNumber"]
	verified := user.Fields["phoneNumberVerified"]
	if user.ModelName != "members" || phone.FieldName != "mobile" || verified.FieldName != "mobile_verified" ||
		!phone.Unique || !phone.Sortable || verified.IsInput() {
		t.Fatalf("schema user=%#v phone=%#v verified=%#v", user, phone, verified)
	}

	store := newCaptureStore()
	auth, _ := newRootHarness(t, standardOptions(store), nil)
	descriptor := auth.Options().Plugins[0]
	rule := descriptor.RateLimit[0]
	for _, path := range []string{
		"/phone-number/send-otp", "/phone-number/verify",
		"/phone-number/request-password-reset", "/phone-number/reset-password",
	} {
		if !rule.Match(path) {
			t.Fatalf("rate rule does not match %q", path)
		}
	}
	if rule.Match("/sign-in/phone-number") || rule.Rule.Window != 60 || rule.Rule.Max != 10 {
		t.Fatalf("rate rule = %#v", rule)
	}
}

func TestCustomOTPLengthExpiryAttemptsAndTemporaryName(t *testing.T) {
	store := newCaptureStore()
	options := standardOptions(store)
	options.OTPLength = 8
	options.ExpiresIn = 30 * time.Second
	options.AllowedAttempts = 1
	options.SignUpOnVerification.GetTempName = func(phone string) string { return "phone-user:" + phone }
	auth, clock := newRootHarness(t, options, nil)
	phone := "+15551110000"
	sent := exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	if sent.status != http.StatusOK || len(store.code(phone)) != 8 {
		t.Fatalf("send status=%d code=%q", sent.status, store.code(phone))
	}
	wrong := "00000000"
	if wrong == store.code(phone) {
		wrong = "99999999"
	}
	first := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": wrong,
	})
	if first.status != http.StatusBadRequest || errorCode(first) != CodeInvalidOTP {
		t.Fatalf("first status=%d body=%#v", first.status, first.body)
	}
	blocked := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	if blocked.status != http.StatusForbidden || errorCode(blocked) != CodeTooManyAttempts {
		t.Fatalf("blocked status=%d body=%#v", blocked.status, blocked.body)
	}

	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": phone})
	clock.Advance(30*time.Second + time.Nanosecond)
	expired := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": phone, "code": store.code(phone),
	})
	if expired.status != http.StatusBadRequest || errorCode(expired) != CodeOTPExpired {
		t.Fatalf("expired status=%d body=%#v", expired.status, expired.body)
	}

	newPhone := "+15551110001"
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", "", map[string]any{"phoneNumber": newPhone})
	verified := exchange(t, auth, http.MethodPost, "/phone-number/verify", "", map[string]any{
		"phoneNumber": newPhone, "code": store.code(newPhone), "disableSession": true,
	})
	if verified.status != http.StatusOK || bodyObject(t, verified.body, "user")["name"] != "phone-user:"+newPhone {
		t.Fatalf("verify status=%d body=%#v", verified.status, verified.body)
	}
}

func TestFactoryRejectsIncompleteSignUpConfiguration(t *testing.T) {
	options := Options{SignUpOnVerification: &SignUpOnVerificationOptions{}}
	if _, err := singleauth.New(singleauth.Options{
		BaseURL: testBaseURL, Secret: testSecret,
		PluginFactories: []singleauth.PluginFactory{NewFactory(options)},
	}); err == nil {
		t.Fatal("incomplete SignUpOnVerification unexpectedly initialized")
	}
}

func TestSchemaRejectsCollidingPhysicalFields(t *testing.T) {
	_, err := Schema(Options{Schema: SchemaOptions{User: UserSchemaOptions{
		PhoneNumber: "mobile", PhoneNumberVerified: "mobile",
	}}})
	if err == nil {
		t.Fatal("colliding physical field aliases unexpectedly accepted")
	}
}
