package emailotp_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
)

func TestRootFactorySignInCreatesUserSessionAndCookies(t *testing.T) {
	var sent emailotp.OTPMessage
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  "0123456789abcdef0123456789abcdef",
		PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
			SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
				sent = message
				return nil
			},
		})},
	})
	if err != nil {
		t.Fatal(err)
	}

	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "http://auth.example.test/api/auth"+path, bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		return recorder
	}
	if response := post("/email-otp/send-verification-otp", `{"email":"factory-otp@example.com","type":"sign-in"}`); response.Code != http.StatusOK {
		t.Fatalf("send status=%d body=%s", response.Code, response.Body.String())
	}
	if sent.Email != "factory-otp@example.com" || sent.OTP == "" || sent.Type != emailotp.TypeSignIn {
		t.Fatalf("sent message = %#v", sent)
	}

	response := post("/sign-in/email-otp", `{"email":"factory-otp@example.com","otp":"`+sent.OTP+`","name":"Factory OTP"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("sign in status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"user"`) || !strings.Contains(response.Header().Get("Set-Cookie"), "single-auth.session_token=") {
		t.Fatalf("sign in body=%s cookies=%q", response.Body.String(), response.Header().Values("Set-Cookie"))
	}
}
