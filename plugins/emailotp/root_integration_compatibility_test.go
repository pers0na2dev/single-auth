package emailotp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/plugins/additionalfields"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
	"github.com/pers0na2dev/single-auth/storage"
)

func rootBool(value bool) *bool { return &value }

func rootPostJSON(
	t *testing.T,
	auth *singleauth.Auth,
	path string,
	body map[string]any,
	cookieHeader string,
	origin *string,
	extra map[string]string,
) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://localhost:3000/api/auth"+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if cookieHeader != "" {
		request.Header.Set("Cookie", cookieHeader)
	}
	if origin != nil {
		request.Header.Set("Origin", *origin)
	}
	for name, value := range extra {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	result := map[string]any{}
	if len(recorder.Body.Bytes()) > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode response status=%d body=%s: %v", recorder.Code, recorder.Body.String(), err)
		}
	}
	return recorder, result
}

func seedRootOTPUser(t *testing.T, auth *singleauth.Auth, email string, verified bool) storage.Record {
	t.Helper()
	user, err := auth.Adapter().Create(t.Context(), storage.CreateParams{Model: "user", Data: storage.Record{
		"name": email, "email": email, "emailVerified": verified,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestRootFactoryInheritsAutoSignInAndPreservesExpiredError(t *testing.T) {
	t.Run("inherits root autoSignInAfterVerification", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
			EmailVerification: singleauth.EmailVerificationOptions{AutoSignInAfterVerification: true},
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
		seedRootOTPUser(t, auth, "auto-verify@example.com", false)
		response, body := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
			"email": "auto-verify@example.com", "type": "email-verification",
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["success"] != true || sent.OTP == "" {
			t.Fatalf("send status=%d body=%#v sent=%#v", response.Code, body, sent)
		}
		response, body = rootPostJSON(t, auth, "/email-otp/verify-email", map[string]any{
			"email": "auto-verify@example.com", "otp": sent.OTP,
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["status"] != true || body["token"] == nil ||
			!strings.Contains(strings.Join(response.Header().Values("Set-Cookie"), ";"), "single-auth.session_token=") {
			t.Fatalf("verify status=%d body=%#v cookies=%q", response.Code, body, response.Header().Values("Set-Cookie"))
		}
	})

	t.Run("returns OTP_EXPIRED through PluginHost PeekVerification", func(t *testing.T) {
		now := time.Date(2026, time.August, 9, 13, 0, 0, 0, time.UTC)
		var sent emailotp.OTPMessage
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef", Clock: func() time.Time { return now },
			PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
					sent = message
					return nil
				},
				ExpiresIn: time.Minute,
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		seedRootOTPUser(t, auth, "expired-factory@example.com", false)
		response, _ := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
			"email": "expired-factory@example.com", "type": "email-verification",
		}, "", nil, nil)
		if response.Code != http.StatusOK || sent.OTP == "" {
			t.Fatalf("send status=%d body=%s", response.Code, response.Body.String())
		}
		now = now.Add(61 * time.Second)
		response, body := rootPostJSON(t, auth, "/email-otp/verify-email", map[string]any{
			"email": "expired-factory@example.com", "otp": sent.OTP,
		}, "", nil, nil)
		if response.Code != http.StatusBadRequest || body["code"] != emailotp.ErrorOTPExpired {
			t.Fatalf("expired factory status=%d body=%#v", response.Code, body)
		}
	})
}

func TestUpstreamEmailOTPOverrideDefaultVerificationRuntime(t *testing.T) {
	newOverrideAuth := func(t *testing.T, pluginSend func(emailotp.OTPMessage), after func(context.Context, model.User) error, sendPluginHook bool) *singleauth.Auth {
		t.Helper()
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
			EmailVerification: singleauth.EmailVerificationOptions{
				SendOnSignUp: rootBool(true), AfterEmailVerification: after,
			},
			PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
					pluginSend(message)
					return nil
				},
				OverrideDefaultEmailVerification: true,
				SendVerificationOnSignUp:         sendPluginHook,
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}

	t.Run("should send verification email on sign up", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newOverrideAuth(t, func(message emailotp.OTPMessage) { sent = message }, nil, false)
		origin := "http://localhost:3000"
		response, body := rootPostJSON(t, auth, "/sign-up/email", map[string]any{
			"email": "override-signup@example.com", "password": "password", "name": "Test User",
		}, "", &origin, nil)
		if response.Code != http.StatusOK || body["user"] == nil || sent.Email != "override-signup@example.com" || sent.Type != emailotp.TypeEmailVerification || len(sent.OTP) != 6 {
			t.Fatalf("sign-up status=%d body=%#v sent=%#v", response.Code, body, sent)
		}
	})

	t.Run("should verify email with otp", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newOverrideAuth(t, func(message emailotp.OTPMessage) { sent = message }, nil, false)
		origin := "http://localhost:3000"
		response, _ := rootPostJSON(t, auth, "/sign-up/email", map[string]any{
			"email": "override-verify@example.com", "password": "password", "name": "Test User",
		}, "", &origin, nil)
		if response.Code != http.StatusOK || sent.OTP == "" {
			t.Fatalf("sign-up status=%d body=%s sent=%#v", response.Code, response.Body.String(), sent)
		}
		response, body := rootPostJSON(t, auth, "/email-otp/verify-email", map[string]any{
			"email": "override-verify@example.com", "otp": sent.OTP,
		}, "", nil, nil)
		user := body["user"].(map[string]any)
		if response.Code != http.StatusOK || body["status"] != true || user["emailVerified"] != true {
			t.Fatalf("verify status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("should by default not override default email verification", func(t *testing.T) {
		var defaultCalls atomic.Int64
		var pluginCalls atomic.Int64
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
			EmailVerification: singleauth.EmailVerificationOptions{
				SendOnSignUp: rootBool(true),
				SendVerificationEmail: func(context.Context, singleauth.EmailVerificationMessage) error {
					defaultCalls.Add(1)
					return nil
				},
			},
			PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(context.Context, emailotp.OTPMessage, *engine.Context) error {
					pluginCalls.Add(1)
					return nil
				},
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		origin := "http://localhost:3000"
		response, _ := rootPostJSON(t, auth, "/sign-up/email", map[string]any{
			"email": "default-sender@example.com", "password": "password", "name": "Test User",
		}, "", &origin, nil)
		if response.Code != http.StatusOK || defaultCalls.Load() != 1 || pluginCalls.Load() != 0 {
			t.Fatalf("status=%d defaultCalls=%d pluginCalls=%d body=%s", response.Code, defaultCalls.Load(), pluginCalls.Load(), response.Body.String())
		}
	})

	t.Run("should send email only once when override is enabled", func(t *testing.T) {
		var calls atomic.Int64
		auth := newOverrideAuth(t, func(message emailotp.OTPMessage) {
			if message.Email == "override-once@example.com" {
				calls.Add(1)
			}
		}, nil, true)
		origin := "http://localhost:3000"
		response, _ := rootPostJSON(t, auth, "/sign-up/email", map[string]any{
			"email": "override-once@example.com", "password": "password", "name": "Test User",
		}, "", &origin, nil)
		if response.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
		}
	})

	t.Run("should call afterEmailVerification hook when override is enabled", func(t *testing.T) {
		var sent emailotp.OTPMessage
		var calls atomic.Int64
		auth := newOverrideAuth(t, func(message emailotp.OTPMessage) { sent = message }, func(_ context.Context, user model.User) error {
			if user.Email != "override-hook@example.com" || !user.EmailVerified {
				t.Fatalf("after verification user=%#v", user)
			}
			calls.Add(1)
			return nil
		}, false)
		origin := "http://localhost:3000"
		response, _ := rootPostJSON(t, auth, "/sign-up/email", map[string]any{
			"email": "override-hook@example.com", "password": "password", "name": "Test User",
		}, "", &origin, nil)
		if response.Code != http.StatusOK || sent.OTP == "" {
			t.Fatalf("sign-up status=%d sent=%#v", response.Code, sent)
		}
		response, body := rootPostJSON(t, auth, "/email-otp/verify-email", map[string]any{
			"email": "override-hook@example.com", "otp": sent.OTP,
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["status"] != true || calls.Load() != 1 {
			t.Fatalf("verify status=%d calls=%d body=%#v", response.Code, calls.Load(), body)
		}
	})
}

func TestUpstreamEmailOTPAdditionalFieldsRuntime(t *testing.T) {
	newAdditionalAuth := func(t *testing.T, sent *emailotp.OTPMessage) *singleauth.Auth {
		t.Helper()
		optional := storage.Bool(false)
		blocked := storage.Bool(false)
		fields := additionalfields.NewFactory(additionalfields.Options{User: additionalfields.Fields{
			{Name: "lang", Attribute: storage.FieldAttribute{Type: storage.FieldString, Required: optional}},
			{Name: "isAdmin", Attribute: storage.FieldAttribute{Type: storage.FieldBoolean, Input: blocked, DefaultValue: storage.StaticValue(false)}},
		}})
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
			PluginFactories: []singleauth.PluginFactory{fields, emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
					*sent = message
					return nil
				},
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}

	t.Run("should sign-up with additional fields", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newAdditionalAuth(t, &sent)
		response, _ := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{"email": "additional@example.com", "type": "sign-in"}, "", nil, nil)
		if response.Code != http.StatusOK || sent.OTP == "" {
			t.Fatalf("send status=%d sent=%#v", response.Code, sent)
		}
		response, body := rootPostJSON(t, auth, "/sign-in/email-otp", map[string]any{
			"email": "additional@example.com", "otp": sent.OTP, "name": "AF User", "lang": "ko",
		}, "", nil, nil)
		user := body["user"].(map[string]any)
		if response.Code != http.StatusOK || body["token"] == "" || user["name"] != "AF User" || user["lang"] != "ko" || user["isAdmin"] != false {
			t.Fatalf("additional sign-up status=%d body=%#v", response.Code, body)
		}
		stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: "additional@example.com"}}})
		if err != nil || stored["lang"] != "ko" || stored["isAdmin"] != false {
			t.Fatalf("stored additional user=%#v err=%v", stored, err)
		}
	})

	t.Run("should ignore input: false fields and use default value", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newAdditionalAuth(t, &sent)
		response, _ := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{"email": "blocked-default@example.com", "type": "sign-in"}, "", nil, nil)
		if response.Code != http.StatusOK || sent.OTP == "" {
			t.Fatalf("send status=%d sent=%#v", response.Code, sent)
		}
		response, body := rootPostJSON(t, auth, "/sign-in/email-otp", map[string]any{
			"email": "blocked-default@example.com", "otp": sent.OTP, "isAdmin": true,
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["token"] == "" || body["user"].(map[string]any)["isAdmin"] != false {
			t.Fatalf("input:false sign-up status=%d body=%#v", response.Code, body)
		}
	})
}

func TestUpstreamEmailOTPCookieCacheIsolationRuntime(t *testing.T) {
	var sent emailotp.OTPMessage
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Session:          singleauth.SessionOptions{CookieCache: singleauth.CookieCacheOptions{Enabled: true}},
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
	origin := "http://localhost:3000"
	response, body := rootPostJSON(t, auth, "/sign-up/email", map[string]any{
		"email": "current-cache@example.com", "password": "current-password", "name": "Current",
	}, "", &origin, nil)
	if response.Code != http.StatusOK || body["token"] == "" {
		t.Fatalf("current sign-up status=%d body=%#v", response.Code, body)
	}
	currentCookies := cookies.ApplySetCookies("", response.Header().Values("Set-Cookie"))
	currentUser, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: "current-cache@example.com"}}})
	if err != nil || currentUser == nil {
		t.Fatalf("current user=%#v err=%v", currentUser, err)
	}
	other := seedRootOTPUser(t, auth, "other-cache@example.com", false)
	if other["id"] == currentUser["id"] {
		t.Fatalf("distinct users share id: current=%#v other=%#v", currentUser, other)
	}
	response, _ = rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
		"email": "other-cache@example.com", "type": "email-verification",
	}, "", nil, nil)
	if response.Code != http.StatusOK || sent.OTP == "" {
		t.Fatalf("other OTP status=%d sent=%#v", response.Code, sent)
	}
	response, body = rootPostJSON(t, auth, "/email-otp/verify-email", map[string]any{
		"email": "other-cache@example.com", "otp": sent.OTP,
	}, currentCookies, &origin, nil)
	if response.Code != http.StatusOK || body["status"] != true {
		t.Fatalf("other verify status=%d body=%#v", response.Code, body)
	}
	currentCookies = cookies.ApplySetCookies(currentCookies, response.Header().Values("Set-Cookie"))
	request := httptest.NewRequest(http.MethodGet, "http://localhost:3000/api/auth/get-session", nil)
	request.Header.Set("Cookie", currentCookies)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	var session map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	sessionUser := session["user"].(map[string]any)
	if recorder.Code != http.StatusOK || sessionUser["email"] != "current-cache@example.com" || sessionUser["emailVerified"] != false {
		t.Fatalf("isolated session status=%d body=%#v cookies=%q", recorder.Code, session, currentCookies)
	}
}

func TestUpstreamEmailOTPRateLimitRuntime(t *testing.T) {
	paths := []struct {
		path string
		body map[string]any
	}{
		{path: "/email-otp/send-verification-otp", body: map[string]any{"email": "rate@example.com", "type": "sign-in"}},
		{path: "/sign-in/email-otp", body: map[string]any{"email": "rate@example.com", "otp": "12312"}},
		{path: "/email-otp/verify-email", body: map[string]any{"email": "rate@example.com", "otp": "12312"}},
	}
	for _, test := range paths {
		t.Run(strings.TrimPrefix(test.path, "/"), func(t *testing.T) {
			now := time.Date(2026, time.August, 9, 14, 0, 0, 0, time.UTC)
			auth, err := singleauth.New(singleauth.Options{
				BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef", Clock: func() time.Time { return now },
				RateLimit: singleauth.RateLimitOptions{Enabled: rootBool(true)},
				PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
					SendVerificationOTP: func(context.Context, emailotp.OTPMessage, *engine.Context) error { return nil },
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 1; attempt <= 4; attempt++ {
				response, _ := rootPostJSON(t, auth, test.path, test.body, "", nil, map[string]string{"X-Forwarded-For": "192.0.2.44"})
				if attempt <= 3 && response.Code == http.StatusTooManyRequests {
					t.Fatalf("attempt %d unexpectedly limited body=%s", attempt, response.Body.String())
				}
				if attempt == 4 && response.Code != http.StatusTooManyRequests {
					t.Fatalf("attempt %d status=%d body=%s", attempt, response.Code, response.Body.String())
				}
			}
			now = now.Add(time.Minute)
			response, _ := rootPostJSON(t, auth, test.path, test.body, "", nil, map[string]string{"X-Forwarded-For": "192.0.2.44"})
			if response.Code == http.StatusTooManyRequests {
				t.Fatalf("window did not reset body=%s", response.Body.String())
			}
		})
	}
}

func TestUpstreamEmailOTPOriginCSRFRuntime(t *testing.T) {
	newAuth := func(t *testing.T, calls *atomic.Int64) *singleauth.Auth {
		t.Helper()
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef", TrustedOrigins: []string{"http://localhost:3000"},
			PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(context.Context, emailotp.OTPMessage, *engine.Context) error {
					calls.Add(1)
					return nil
				},
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}

	t.Run("should block cross-site navigation to the send endpoint (no cookies)", func(t *testing.T) {
		var calls atomic.Int64
		auth := newAuth(t, &calls)
		evil := "https://evil.com"
		response, _ := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
			"email": "attacker@evil.com", "type": "sign-in",
		}, "", &evil, map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"})
		if response.Code != http.StatusForbidden || calls.Load() != 0 {
			t.Fatalf("cross-site status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
		}
	})

	t.Run("should reject a cookieless cross-origin POST to the send endpoint", func(t *testing.T) {
		var calls atomic.Int64
		auth := newAuth(t, &calls)
		evil := "https://evil.com"
		response, _ := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
			"email": "attacker@evil.com", "type": "sign-in",
		}, "", &evil, nil)
		if response.Code != http.StatusForbidden || calls.Load() != 0 {
			t.Fatalf("cross-origin status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
		}
	})

	t.Run("should still allow a cookieless request with no Origin (server-to-server)", func(t *testing.T) {
		var calls atomic.Int64
		auth := newAuth(t, &calls)
		seedRootOTPUser(t, auth, "server@example.com", false)
		response, body := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
			"email": "server@example.com", "type": "email-verification",
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["success"] != true || calls.Load() != 1 {
			t.Fatalf("server request status=%d calls=%d body=%#v", response.Code, calls.Load(), body)
		}
	})
}

func TestRootFactoryPasswordAndUnverifiedAccountIntegration(t *testing.T) {
	newPasswordAuth := func(t *testing.T, requireVerification bool, resetCalls *atomic.Int64, sent *emailotp.OTPMessage) *singleauth.Auth {
		t.Helper()
		auth, err := singleauth.New(singleauth.Options{
			BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
			EmailAndPassword: singleauth.EmailAndPasswordOptions{
				Enabled:                  true,
				RequireEmailVerification: requireVerification,
				Password: singleauth.PasswordOptions{
					Hash:   func(password string) (string, error) { return "hash:" + password, nil },
					Verify: func(hash, password string) bool { return hash == "hash:"+password },
				},
				OnPasswordReset: func(_ context.Context, user model.User) error {
					if resetCalls != nil {
						resetCalls.Add(1)
					}
					return nil
				},
			},
			PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
				GenerateOTP: func(emailotp.OTPData, *engine.Context) (string, error) { return "654321", nil },
				SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
					*sent = message
					return nil
				},
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	origin := "http://localhost:3000"

	t.Run("new and deprecated reset endpoints create a usable credential and call the root hook", func(t *testing.T) {
		for _, requestPath := range []string{"/email-otp/request-password-reset", "/forget-password/email-otp"} {
			requestPath := requestPath
			t.Run(requestPath, func(t *testing.T) {
				var sent emailotp.OTPMessage
				var resets atomic.Int64
				auth := newPasswordAuth(t, false, &resets, &sent)
				email := "reset-new@example.com"
				if strings.Contains(requestPath, "forget-password") {
					email = "reset-deprecated@example.com"
				}
				seedRootOTPUser(t, auth, email, false)
				response, body := rootPostJSON(t, auth, requestPath, map[string]any{"email": email}, "", nil, nil)
				if response.Code != http.StatusOK || body["success"] != true || sent.OTP != "654321" || sent.Type != emailotp.TypeForgetPassword {
					t.Fatalf("request status=%d body=%#v sent=%#v", response.Code, body, sent)
				}
				response, body = rootPostJSON(t, auth, "/email-otp/reset-password", map[string]any{
					"email": email, "otp": sent.OTP, "password": "changed-password",
				}, "", nil, nil)
				if response.Code != http.StatusOK || body["success"] != true || resets.Load() != 1 {
					t.Fatalf("reset status=%d body=%#v callbacks=%d", response.Code, body, resets.Load())
				}
				response, body = rootPostJSON(t, auth, "/sign-in/email", map[string]any{
					"email": email, "password": "changed-password",
				}, "", &origin, nil)
				if response.Code != http.StatusOK || body["token"] == "" {
					t.Fatalf("credential sign-in status=%d body=%#v", response.Code, body)
				}
			})
		}
	})

	t.Run("OTP-created user can establish a password credential", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newPasswordAuth(t, false, nil, &sent)
		response, _ := rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
			"email": "otp-credential@example.com", "type": "sign-in",
		}, "", nil, nil)
		if response.Code != http.StatusOK || sent.OTP != "654321" {
			t.Fatalf("OTP request status=%d sent=%#v", response.Code, sent)
		}
		response, body := rootPostJSON(t, auth, "/sign-in/email-otp", map[string]any{
			"email": "otp-credential@example.com", "otp": sent.OTP,
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["token"] == "" {
			t.Fatalf("OTP sign-up status=%d body=%#v", response.Code, body)
		}
		response, _ = rootPostJSON(t, auth, "/email-otp/request-password-reset", map[string]any{"email": "otp-credential@example.com"}, "", nil, nil)
		if response.Code != http.StatusOK || sent.Type != emailotp.TypeForgetPassword {
			t.Fatalf("reset request status=%d sent=%#v", response.Code, sent)
		}
		response, body = rootPostJSON(t, auth, "/email-otp/reset-password", map[string]any{
			"email": "otp-credential@example.com", "otp": sent.OTP, "password": "password",
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["success"] != true {
			t.Fatalf("reset status=%d body=%#v", response.Code, body)
		}
		response, body = rootPostJSON(t, auth, "/sign-in/email", map[string]any{
			"email": "otp-credential@example.com", "password": "password",
		}, "", &origin, nil)
		if response.Code != http.StatusOK || body["token"] == "" {
			t.Fatalf("password sign-in status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("sign-in OTP adoption removes an unverified credential", func(t *testing.T) {
		var sent emailotp.OTPMessage
		auth := newPasswordAuth(t, true, nil, &sent)
		response, body := rootPostJSON(t, auth, "/sign-up/email", map[string]any{
			"email": "unverified-adopt@example.com", "password": "existing-password", "name": "Unverified",
		}, "", &origin, nil)
		if response.Code != http.StatusOK || body["user"] == nil {
			t.Fatalf("password sign-up status=%d body=%#v", response.Code, body)
		}
		user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: "unverified-adopt@example.com"}}})
		if err != nil || user == nil || user["emailVerified"] != false {
			t.Fatalf("unverified user=%#v err=%v", user, err)
		}
		response, _ = rootPostJSON(t, auth, "/email-otp/send-verification-otp", map[string]any{
			"email": "unverified-adopt@example.com", "type": "sign-in",
		}, "", nil, nil)
		if response.Code != http.StatusOK || sent.OTP != "654321" {
			t.Fatalf("OTP request status=%d sent=%#v", response.Code, sent)
		}
		response, body = rootPostJSON(t, auth, "/sign-in/email-otp", map[string]any{
			"email": "unverified-adopt@example.com", "otp": sent.OTP,
		}, "", nil, nil)
		if response.Code != http.StatusOK || body["token"] == "" {
			t.Fatalf("OTP adoption status=%d body=%#v", response.Code, body)
		}
		userID, _ := user["id"].(string)
		account, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "account", Where: []storage.Where{
			{Field: "userId", Value: userID}, {Field: "providerId", Value: "credential"},
		}})
		if err != nil || account != nil {
			t.Fatalf("credential after adoption=%#v err=%v", account, err)
		}
	})
}
