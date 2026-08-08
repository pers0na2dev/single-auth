package twofactor

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDescriptorSchemaDefaultsAndEndpointSurface(t *testing.T) {
	auth, _ := newHarness(t, Options{}, nil)
	if Version != "1.6.26" {
		t.Fatalf("version=%q", Version)
	}
	wantEndpoints := map[string]struct {
		path       string
		serverOnly bool
	}{
		"generateTOTP":        {"", true},
		"getTOTPURI":          {"/two-factor/get-totp-uri", false},
		"verifyTOTP":          {"/two-factor/verify-totp", false},
		"sendTwoFactorOTP":    {"/two-factor/send-otp", false},
		"verifyTwoFactorOTP":  {"/two-factor/verify-otp", false},
		"verifyBackupCode":    {"/two-factor/verify-backup-code", false},
		"generateBackupCodes": {"/two-factor/generate-backup-codes", false},
		"viewBackupCodes":     {"", true},
		"enableTwoFactor":     {"/two-factor/enable", false},
		"disableTwoFactor":    {"/two-factor/disable", false},
	}
	for name, want := range wantEndpoints {
		endpoint, exists := auth.Registry().Endpoint(name)
		if !exists || endpoint.Path != want.path || endpoint.ServerOnly != want.serverOnly ||
			!reflect.DeepEqual(endpoint.Methods, []string{http.MethodPost}) {
			t.Fatalf("endpoint %s=%#v want=%#v", name, endpoint, want)
		}
	}
	registeredErrors := auth.Registry().ErrorCodes()
	if len(registeredErrors) != 10 {
		t.Fatalf("error catalog=%#v", registeredErrors)
	}

	schema, err := Schema(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defaultValue := func(field storage.FieldAttribute) any {
		if field.DefaultValue == nil {
			return nil
		}
		value, valueErr := field.DefaultValue(storage.ValueContext{})
		if valueErr != nil {
			t.Fatal(valueErr)
		}
		return value
	}
	if schema.Models["twoFactor"].ModelName != "twoFactor" ||
		defaultValue(schema.Models["user"].Fields["twoFactorEnabled"]) != false {
		t.Fatalf("schema=%#v", schema)
	}
	for _, field := range []string{"secret", "backupCodes", "userId", "verified", "failedVerificationCount", "lockedUntil"} {
		if _, exists := schema.Models["twoFactor"].Fields[field]; !exists {
			t.Fatalf("schema field %q missing", field)
		}
	}
	if defaultValue(schema.Models["twoFactor"].Fields["verified"]) != true ||
		defaultValue(schema.Models["twoFactor"].Fields["failedVerificationCount"]) != 0 {
		t.Fatalf("twoFactor defaults=%#v", schema.Models["twoFactor"].Fields)
	}
}

func TestEnrollmentIssuerReenrollmentAndMethodSelection(t *testing.T) {
	t.Run("issuer precedence and pending enrollment", func(t *testing.T) {
		auth, _ := newHarness(t, Options{Issuer: "Configured Issuer"}, func(options *singleauth.Options) {
			options.AppName = "Application Name"
		})
		signed := signUp(t, auth)
		custom := invoke(t, auth, "enableTwoFactor", http.MethodPost, "/two-factor/enable", signed.cookie, map[string]any{
			"password": testPass, "issuer": "Request Issuer",
		})
		if custom.status != http.StatusOK || !strings.Contains(custom.body["totpURI"].(string), "Request%20Issuer:") {
			t.Fatalf("custom issuer=%#v", custom.body)
		}
		user, _ := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
		if enabled, _ := recordBool(user, "twoFactorEnabled"); enabled {
			t.Fatal("pending enrollment enabled 2FA")
		}
		if verified, _ := recordBool(twoFactorRow(t, auth), "verified"); verified {
			t.Fatal("pending enrollment marked verified")
		}

		configured := enable(t, auth, signed.cookie)
		if !strings.Contains(configured.body["totpURI"].(string), "Configured%20Issuer:") {
			t.Fatalf("configured issuer=%#v", configured.body)
		}
	})

	t.Run("app name fallback", func(t *testing.T) {
		auth, _ := newHarness(t, Options{}, func(options *singleauth.Options) { options.AppName = "My Go App" })
		signed := signUp(t, auth)
		result := enable(t, auth, signed.cookie)
		if !strings.Contains(result.body["totpURI"].(string), "My%20Go%20App:") {
			t.Fatalf("app issuer=%#v", result.body)
		}
	})

	t.Run("verified state survives reenrollment", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		result := enable(t, h.auth, h.activeCookie)
		if result.status != http.StatusOK {
			t.Fatalf("reenroll=%#v", result.body)
		}
		row := twoFactorRow(t, h.auth)
		if verified, present := recordBool(row, "verified"); !present || !verified {
			t.Fatalf("verified state=%#v", row)
		}
	})

	t.Run("pre-migration null becomes verified", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		updateTwoFactor(t, h.auth, storage.Record{"verified": nil})
		result := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", h.activeCookie, map[string]any{
			"code": h.currentTOTP(t),
		})
		if result.status != http.StatusOK {
			t.Fatalf("legacy verify status=%d body=%#v", result.status, result.body)
		}
		if verified, present := recordBool(twoFactorRow(t, h.auth), "verified"); !present || !verified {
			t.Fatalf("legacy row=%#v", twoFactorRow(t, h.auth))
		}
	})

	t.Run("method list", func(t *testing.T) {
		capture := &otpCapture{}
		h := setupEnrolled(t, Options{OTP: OTPOptions{SendOTP: capture.send}}, nil)
		challenge := h.challenge(t)
		if got := challenge.body["twoFactorMethods"]; !reflect.DeepEqual(got, []any{"totp", "otp"}) {
			t.Fatalf("methods=%#v", got)
		}

		updateTwoFactor(t, h.auth, storage.Record{"verified": false})
		challenge = h.challenge(t)
		if got := challenge.body["twoFactorMethods"]; !reflect.DeepEqual(got, []any{"otp"}) {
			t.Fatalf("unverified methods=%#v", got)
		}
		invalidTOTP := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{
			"code": h.currentTOTP(t),
		})
		if invalidTOTP.status != http.StatusBadRequest || errorCode(invalidTOTP) != CodeTOTPNotEnabled {
			t.Fatalf("unverified TOTP=%d %#v", invalidTOTP.status, invalidTOTP.body)
		}
		sent := invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
		if sent.status != http.StatusOK {
			t.Fatalf("OTP fallback=%d %#v", sent.status, sent.body)
		}
	})

	t.Run("no enrollment does not redirect", func(t *testing.T) {
		auth, _ := newHarness(t, Options{}, nil)
		_ = signUp(t, auth)
		result := invoke(t, auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
			"email": testEmail, "password": testPass,
		})
		if result.status != http.StatusOK || result.body["twoFactorRedirect"] != nil || result.body["token"] == "" {
			t.Fatalf("unenrolled sign-in=%d %#v", result.status, result.body)
		}
	})

	t.Run("verified TOTP with OTP disabled", func(t *testing.T) {
		h := setupEnrolled(t, Options{}, nil)
		challenge := h.challenge(t)
		if got := challenge.body["twoFactorMethods"]; !reflect.DeepEqual(got, []any{"totp"}) {
			t.Fatalf("TOTP-only methods=%#v", got)
		}
	})

	t.Run("OTP enabled without TOTP row", func(t *testing.T) {
		capture := &otpCapture{}
		auth, _ := newHarness(t, Options{OTP: OTPOptions{SendOTP: capture.send}}, nil)
		signed := signUp(t, auth)
		user, _ := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
		userIDValue, _ := recordString(user, "id")
		_, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userIDValue}},
			Update: storage.Record{"twoFactorEnabled": true},
		})
		if err != nil {
			t.Fatal(err)
		}
		challenge := invoke(t, auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
			"email": testEmail, "password": testPass,
		})
		if got := challenge.body["twoFactorMethods"]; !reflect.DeepEqual(got, []any{"otp"}) {
			t.Fatalf("OTP-only methods=%#v signed=%#v", got, signed.body)
		}
	})

	t.Run("TOTP disabled excludes existing row", func(t *testing.T) {
		capture := &otpCapture{}
		auth, _ := newHarness(t, Options{
			TOTP: TOTPOptions{Disable: true}, OTP: OTPOptions{SendOTP: capture.send},
			SkipVerificationOnEnable: true,
		}, nil)
		signed := signUp(t, auth)
		enabled := enable(t, auth, signed.cookie)
		cookie := cookies.ApplySetCookies(signed.cookie, enabled.headers.Values("Set-Cookie"))
		_ = cookie // the sign-in intentionally starts a fresh credential session
		challenge := invoke(t, auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
			"email": testEmail, "password": testPass,
		})
		if got := challenge.body["twoFactorMethods"]; !reflect.DeepEqual(got, []any{"otp"}) {
			t.Fatalf("TOTP-disabled methods=%#v", got)
		}
		if twoFactorRow(t, auth) == nil {
			t.Fatal("fixture did not retain TOTP row")
		}
	})
}

func TestPasswordlessCredentialIndistinguishabilityAndCustomSchema(t *testing.T) {
	t.Run("passwordless user lifecycle", func(t *testing.T) {
		auth, clock := newHarness(t, Options{AllowPasswordless: true}, nil)
		signed := signUp(t, auth)
		user, _ := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
		userIDValue, _ := recordString(user, "id")
		if _, err := auth.Adapter().DeleteMany(t.Context(), storage.DeleteManyParams{
			Model: "account", Where: []storage.Where{{Field: "userId", Value: userIDValue}},
		}); err != nil {
			t.Fatal(err)
		}
		enrollment := invoke(t, auth, "enableTwoFactor", http.MethodPost, "/two-factor/enable", signed.cookie, map[string]any{})
		if enrollment.status != http.StatusOK {
			t.Fatalf("passwordless enable=%d %#v", enrollment.status, enrollment.body)
		}
		verified := verifyEnrollment(t, auth, clock, signed.cookie)
		activeCookie := verified.cookie
		for _, call := range []struct {
			name, path string
		}{
			{"getTOTPURI", "/two-factor/get-totp-uri"},
			{"generateBackupCodes", "/two-factor/generate-backup-codes"},
			{"disableTwoFactor", "/two-factor/disable"},
		} {
			result := invoke(t, auth, call.name, http.MethodPost, call.path, activeCookie, map[string]any{})
			if result.status != http.StatusOK {
				t.Fatalf("%s=%d %#v", call.name, result.status, result.body)
			}
			if call.name == "disableTwoFactor" {
				break
			}
		}
	})

	t.Run("credential users still require password", func(t *testing.T) {
		auth, _ := newHarness(t, Options{AllowPasswordless: true}, nil)
		signed := signUp(t, auth)
		missing := invoke(t, auth, "enableTwoFactor", http.MethodPost, "/two-factor/enable", signed.cookie, map[string]any{})
		if missing.status != http.StatusBadRequest || errorCode(missing) != string(singleauth.ErrorInvalidPassword) {
			t.Fatalf("missing password=%d %#v", missing.status, missing.body)
		}
	})

	t.Run("missing account and wrong password are indistinguishable", func(t *testing.T) {
		auth, _ := newHarness(t, Options{}, nil)
		signed := signUp(t, auth)
		wrong := invoke(t, auth, "enableTwoFactor", http.MethodPost, "/two-factor/enable", signed.cookie, map[string]any{"password": "wrong"})
		user, _ := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
		userIDValue, _ := recordString(user, "id")
		_, _ = auth.Adapter().DeleteMany(t.Context(), storage.DeleteManyParams{
			Model: "account", Where: []storage.Where{{Field: "userId", Value: userIDValue}},
		})
		missing := invoke(t, auth, "enableTwoFactor", http.MethodPost, "/two-factor/enable", signed.cookie, map[string]any{"password": testPass})
		if errorCode(wrong) != string(singleauth.ErrorInvalidPassword) || errorCode(missing) != errorCode(wrong) ||
			wrong.status != missing.status {
			t.Fatalf("wrong=%d/%#v missing=%d/%#v", wrong.status, wrong.body, missing.status, missing.body)
		}
	})

	t.Run("custom table and field names", func(t *testing.T) {
		options := Options{
			TwoFactorTable: "custom_two_factor",
			Schema: SchemaOptions{
				User: UserSchemaOptions{ModelName: "custom_user", TwoFactorEnabled: "mfa_enabled"},
				TwoFactor: TwoFactorSchemaOptions{
					Secret: "totp_secret", BackupCodes: "recovery_codes", UserID: "owner_id",
					Verified: "confirmed", FailedVerificationCount: "failure_count", LockedUntil: "locked_to",
				},
			},
		}
		h := setupEnrolled(t, options, nil)
		schema, err := Schema(options)
		if err != nil {
			t.Fatal(err)
		}
		model := schema.Models["twoFactor"]
		if schema.Models["user"].ModelName != "custom_user" ||
			schema.Models["user"].Fields["twoFactorEnabled"].FieldName != "mfa_enabled" ||
			model.ModelName != "custom_two_factor" || model.Fields["secret"].FieldName != "totp_secret" ||
			model.Fields["backupCodes"].FieldName != "recovery_codes" || model.Fields["userId"].FieldName != "owner_id" {
			t.Fatalf("custom schema=%#v", model)
		}
		if h.challenge(t).status != http.StatusOK {
			t.Fatal("custom table did not participate in sign-in")
		}
	})
}

func TestOTPStorageModesAndAttemptLimit(t *testing.T) {
	tests := []struct {
		name    string
		storage OTPStorage
	}{
		{name: "plain", storage: OTPStorage{Mode: OTPStoragePlain}},
		{name: "hashed", storage: OTPStorage{Mode: OTPStorageHashed}},
		{name: "encrypted", storage: OTPStorage{Mode: OTPStorageEncrypted}},
		{name: "custom hash", storage: OTPStorage{Hash: func(value string) (string, error) { return "customhash" + value, nil }}},
		{name: "custom encryption", storage: OTPStorage{
			Encrypt: func(value string) (string, error) { return "customencrypted" + value, nil },
			Decrypt: func(value string) (string, error) { return strings.TrimPrefix(value, "customencrypted"), nil },
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := &otpCapture{}
			h := setupEnrolled(t, Options{OTP: OTPOptions{SendOTP: capture.send, Storage: test.storage}}, nil)
			challenge := h.challenge(t)
			sent := invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
			if sent.status != http.StatusOK || capture.get() == "" {
				t.Fatalf("send=%d %#v code=%q", sent.status, sent.body, capture.get())
			}
			if test.name == "hashed" {
				wrong := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": "000000"})
				if wrong.status != http.StatusUnauthorized || errorCode(wrong) != CodeInvalidCode {
					t.Fatalf("hashed wrong=%d %#v", wrong.status, wrong.body)
				}
				// A failed OTP is rearmed with its attempt counter.
			}
			verified := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": capture.get()})
			if verified.status != http.StatusOK || verified.body["token"] == "" {
				t.Fatalf("verify=%d %#v err=%v", verified.status, verified.body, verified.err)
			}
		})
	}

	t.Run("attempt limit", func(t *testing.T) {
		capture := &otpCapture{}
		h := setupEnrolled(t, Options{OTP: OTPOptions{SendOTP: capture.send, AllowedAttempts: 2}}, nil)
		challenge := h.challenge(t)
		_ = invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
		for index := 0; index < 2; index++ {
			wrong := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": "wrong"})
			if wrong.status != http.StatusUnauthorized || errorCode(wrong) != CodeInvalidCode {
				t.Fatalf("attempt %d=%d %#v", index, wrong.status, wrong.body)
			}
		}
		locked := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": capture.get()})
		if locked.status != http.StatusBadRequest || errorCode(locked) != CodeTooManyAttempts {
			t.Fatalf("locked=%d %#v", locked.status, locked.body)
		}
		expired := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": capture.get()})
		if expired.status != http.StatusBadRequest || errorCode(expired) != CodeOTPHasExpired {
			t.Fatalf("spent=%d %#v", expired.status, expired.body)
		}
	})
}

func TestBackupCodeStorageRegenerationAndSingleUse(t *testing.T) {
	tests := []struct {
		name       string
		storage    OTPStorage
		storedMark string
	}{
		{name: "plain", storage: OTPStorage{Mode: OTPStoragePlain}, storedMark: "["},
		{name: "encrypted", storage: OTPStorage{Mode: OTPStorageEncrypted}},
		{name: "custom", storage: OTPStorage{
			Encrypt: func(value string) (string, error) { return "vault:" + value, nil },
			Decrypt: func(value string) (string, error) { return strings.TrimPrefix(value, "vault:"), nil },
		}, storedMark: "vault:"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := setupEnrolled(t, Options{BackupCodes: BackupCodeOptions{Storage: test.storage}}, nil)
			row := twoFactorRow(t, h.auth)
			storedBefore, _ := recordString(row, "backupCodes")
			if test.storedMark != "" && !strings.HasPrefix(storedBefore, test.storedMark) {
				t.Fatalf("stored before=%q", storedBefore)
			}
			challenge := h.challenge(t)
			verified := invoke(t, h.auth, "verifyBackupCode", http.MethodPost, "/two-factor/verify-backup-code", challenge.cookie, map[string]any{"code": h.backupCodes[0]})
			if verified.status != http.StatusOK {
				t.Fatalf("verify=%d %#v", verified.status, verified.body)
			}
			storedAfter, _ := recordString(twoFactorRow(t, h.auth), "backupCodes")
			if storedAfter == storedBefore || (test.storedMark != "" && !strings.HasPrefix(storedAfter, test.storedMark)) {
				t.Fatalf("storage changed format before=%q after=%q", storedBefore, storedAfter)
			}
			view := invoke(t, h.auth, "viewBackupCodes", http.MethodPost, "/two-factor/view-backup-codes", "", map[string]any{"userId": h.userID})
			if view.status != http.StatusOK || len(view.body["backupCodes"].([]any)) != 9 {
				t.Fatalf("view=%d %#v", view.status, view.body)
			}
			for index := 0; index < 3; index++ {
				generated := invoke(t, h.auth, "generateBackupCodes", http.MethodPost, "/two-factor/generate-backup-codes", h.activeCookie, map[string]any{"password": testPass})
				if generated.status != http.StatusOK || len(generated.body["backupCodes"].([]any)) != 10 {
					t.Fatalf("regeneration %d=%d %#v", index, generated.status, generated.body)
				}
				view = invoke(t, h.auth, "viewBackupCodes", http.MethodPost, "/two-factor/view-backup-codes", "", map[string]any{"userId": h.userID})
				if view.status != http.StatusOK || len(view.body["backupCodes"].([]any)) != 10 {
					t.Fatalf("view regeneration %d=%#v", index, view.body)
				}
			}
		})
	}

	t.Run("custom generated codes", func(t *testing.T) {
		custom := []string{"alpha", "beta", "gamma"}
		h := setupEnrolled(t, Options{BackupCodes: BackupCodeOptions{
			CustomGenerate: func() []string { return append([]string(nil), custom...) },
		}}, nil)
		if !reflect.DeepEqual(h.backupCodes, custom) {
			t.Fatalf("custom codes=%#v", h.backupCodes)
		}
	})
}

func TestOTPOnlyEnrollmentAndSkipVerification(t *testing.T) {
	t.Run("OTP-only account adds TOTP", func(t *testing.T) {
		capture := &otpCapture{}
		auth, clock := newHarness(t, Options{AllowPasswordless: true, OTP: OTPOptions{SendOTP: capture.send}}, nil)
		signed := signUp(t, auth)
		user, _ := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
		userIDValue, _ := recordString(user, "id")
		_, _ = auth.Adapter().DeleteMany(t.Context(), storage.DeleteManyParams{Model: "account", Where: []storage.Where{{Field: "userId", Value: userIDValue}}})
		_, _ = auth.Adapter().Update(t.Context(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userIDValue}}, Update: storage.Record{"twoFactorEnabled": true},
		})
		enrollment := invoke(t, auth, "enableTwoFactor", http.MethodPost, "/two-factor/enable", signed.cookie, map[string]any{})
		if enrollment.status != http.StatusOK {
			t.Fatalf("enable=%d %#v", enrollment.status, enrollment.body)
		}
		if verified, present := recordBool(twoFactorRow(t, auth), "verified"); !present || verified {
			t.Fatalf("fresh OTP-only row=%#v", twoFactorRow(t, auth))
		}
		result := verifyEnrollment(t, auth, clock, signed.cookie)
		if result.status != http.StatusOK {
			t.Fatalf("verify=%d %#v", result.status, result.body)
		}
		if verified, _ := recordBool(twoFactorRow(t, auth), "verified"); !verified {
			t.Fatalf("verified row=%#v", twoFactorRow(t, auth))
		}
	})

	t.Run("skip verification enables immediately", func(t *testing.T) {
		auth, _ := newHarness(t, Options{SkipVerificationOnEnable: true}, nil)
		signed := signUp(t, auth)
		enabled := enable(t, auth, signed.cookie)
		user, _ := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
		if value, _ := recordBool(user, "twoFactorEnabled"); !value {
			t.Fatalf("user=%#v", user)
		}
		if value, _ := recordBool(twoFactorRow(t, auth), "verified"); !value {
			t.Fatalf("row=%#v", twoFactorRow(t, auth))
		}
		if responseCookie(enabled.headers.Values("Set-Cookie"), "session_token") == nil {
			t.Fatalf("rotated session cookie missing: %#v", enabled.headers.Values("Set-Cookie"))
		}
	})
}

func TestOTPCallbackAndCustomCodecsAreInvoked(t *testing.T) {
	var sends atomic.Int64
	var hashes atomic.Int64
	capture := &otpCapture{}
	options := Options{OTP: OTPOptions{
		SendOTP: func(ctx context.Context, message OTPMessage, engineCtx *engine.Context) error {
			sends.Add(1)
			return capture.send(ctx, message, engineCtx)
		},
		Storage: OTPStorage{Hash: func(value string) (string, error) {
			hashes.Add(1)
			return "h" + value, nil
		}},
	}}
	h := setupEnrolled(t, options, nil)
	challenge := h.challenge(t)
	_ = invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
	result := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": capture.get()})
	if result.status != http.StatusOK || sends.Load() != 1 || hashes.Load() < 2 {
		t.Fatalf("result=%d sends=%d hashes=%d body=%#v", result.status, sends.Load(), hashes.Load(), result.body)
	}
}

func TestStoredBackupCodesAreJSONArrays(t *testing.T) {
	h := setupEnrolled(t, Options{BackupCodes: BackupCodeOptions{Storage: OTPStorage{Mode: OTPStoragePlain}}}, nil)
	stored, _ := recordString(twoFactorRow(t, h.auth), "backupCodes")
	var values []string
	if err := json.Unmarshal([]byte(stored), &values); err != nil || len(values) != 10 {
		t.Fatalf("stored=%q values=%#v err=%v", stored, values, err)
	}
}
