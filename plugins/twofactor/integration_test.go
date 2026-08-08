package twofactor

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestEnableVerifyChallengeOTPBackupDisableFlow(t *testing.T) {
	capture := &otpCapture{}
	auth, clock := newHarness(t, Options{OTP: OTPOptions{SendOTP: capture.send}}, nil)
	signedUp := signUp(t, auth)
	enrolled := enable(t, auth, signedUp.cookie)
	backupCodes, ok := enrolled.body["backupCodes"].([]any)
	if !ok || len(backupCodes) != 10 {
		t.Fatalf("backup codes = %#v", enrolled.body["backupCodes"])
	}
	uri, _ := enrolled.body["totpURI"].(string)
	if !strings.HasPrefix(uri, "otpauth://totp/single-auth:") ||
		!strings.Contains(uri, "&issuer=single-auth&digits=6&period=30") {
		t.Fatalf("totp URI = %q", uri)
	}
	row := twoFactorRow(t, auth)
	if verified, _ := recordBool(row, "verified"); verified {
		t.Fatalf("fresh enrollment verified = %#v", row["verified"])
	}
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if enabled, _ := recordBool(user, "twoFactorEnabled"); enabled {
		t.Fatal("fresh enrollment enabled user before TOTP verification")
	}

	verifiedEnrollment := verifyEnrollment(t, auth, clock, signedUp.cookie)
	cookie := cookies.ApplySetCookies(signedUp.cookie, verifiedEnrollment.headers.Values("Set-Cookie"))
	user, _ = auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user"})
	if enabled, _ := recordBool(user, "twoFactorEnabled"); !enabled {
		t.Fatalf("verified enrollment user = %#v", user)
	}
	row = twoFactorRow(t, auth)
	if verified, _ := recordBool(row, "verified"); !verified {
		t.Fatalf("verified enrollment row = %#v", row)
	}
	gotURI := invoke(t, auth, "getTOTPURI", http.MethodPost, "/two-factor/get-totp-uri", cookie, map[string]any{
		"password": testPass,
	})
	if gotURI.status != http.StatusOK || !strings.HasPrefix(gotURI.body["totpURI"].(string), "otpauth://totp/single-auth:") {
		t.Fatalf("get TOTP URI status=%d body=%#v", gotURI.status, gotURI.body)
	}

	signIn := invoke(t, auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": testEmail, "password": testPass,
	})
	if signIn.status != http.StatusOK || signIn.body["twoFactorRedirect"] != true {
		t.Fatalf("challenge status=%d body=%#v", signIn.status, signIn.body)
	}
	methods, _ := signIn.body["twoFactorMethods"].([]any)
	if len(methods) != 2 || methods[0] != "totp" || methods[1] != "otp" {
		t.Fatalf("methods = %#v", methods)
	}
	assertOnlyExpiredSessionCookies(t, signIn.headers.Values("Set-Cookie"))

	sent := invoke(t, auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", signIn.cookie, map[string]any{})
	if sent.status != http.StatusOK || len(capture.get()) != 6 {
		t.Fatalf("send OTP status=%d body=%#v code=%q", sent.status, sent.body, capture.get())
	}
	verifiedOTP := invoke(t, auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", signIn.cookie, map[string]any{
		"code": capture.get(), "trustDevice": true,
	})
	if verifiedOTP.status != http.StatusOK || verifiedOTP.body["token"] == "" {
		t.Fatalf("verify OTP status=%d body=%#v err=%v", verifiedOTP.status, verifiedOTP.body, verifiedOTP.err)
	}
	if responseCookie(verifiedOTP.headers.Values("Set-Cookie"), "trust_device") == nil {
		t.Fatalf("trust cookie missing: %#v", verifiedOTP.headers.Values("Set-Cookie"))
	}

	secondChallenge := invoke(t, auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": testEmail, "password": testPass,
	})
	backup := backupCodes[0].(string)
	verifiedBackup := invoke(t, auth, "verifyBackupCode", http.MethodPost, "/two-factor/verify-backup-code", secondChallenge.cookie, map[string]any{
		"code": backup,
	})
	if verifiedBackup.status != http.StatusOK {
		t.Fatalf("verify backup status=%d body=%#v", verifiedBackup.status, verifiedBackup.body)
	}
	viewed := invoke(t, auth, "viewBackupCodes", http.MethodPost, "/two-factor/view-backup-codes", "", map[string]any{
		"userId": user["id"],
	})
	if viewed.status != http.StatusOK || len(viewed.body["backupCodes"].([]any)) != 9 {
		t.Fatalf("viewed backup codes = %#v", viewed.body)
	}
	httpView := dispatch(t, auth, http.MethodPost, "/two-factor/view-backup-codes", "", map[string]any{"userId": user["id"]})
	if httpView.status != http.StatusNotFound {
		t.Fatalf("server-only HTTP status=%d body=%#v", httpView.status, httpView.body)
	}

	disabled := invoke(t, auth, "disableTwoFactor", http.MethodPost, "/two-factor/disable", cookie, map[string]any{
		"password": testPass,
	})
	if disabled.status != http.StatusOK || disabled.body["status"] != true {
		t.Fatalf("disable status=%d body=%#v", disabled.status, disabled.body)
	}
	if row, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "twoFactor"}); err != nil || row != nil {
		t.Fatalf("row after disable=%#v err=%v", row, err)
	}
}

func TestRememberMeAndMissingChallengeCookie(t *testing.T) {
	capture := &otpCapture{}
	h := setupEnrolled(t, Options{OTP: OTPOptions{SendOTP: capture.send}}, nil)
	challenge := invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": testEmail, "password": testPass, "rememberMe": false,
	})
	if challenge.status != http.StatusOK || challenge.body["twoFactorRedirect"] != true {
		t.Fatalf("challenge=%d %#v", challenge.status, challenge.body)
	}
	if responseCookie(challenge.headers.Values("Set-Cookie"), "dont_remember") == nil {
		t.Fatalf("dont_remember missing: %#v", challenge.headers.Values("Set-Cookie"))
	}
	_ = invoke(t, h.auth, "sendTwoFactorOTP", http.MethodPost, "/two-factor/send-otp", challenge.cookie, map[string]any{})
	verified := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", challenge.cookie, map[string]any{"code": capture.get()})
	sessionCookie := responseCookie(verified.headers.Values("Set-Cookie"), "session_token")
	if verified.status != http.StatusOK || sessionCookie == nil || sessionCookie.Attributes.MaxAge != nil {
		t.Fatalf("non-remembered verify=%d cookie=%#v body=%#v", verified.status, sessionCookie, verified.body)
	}

	challenge = invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": testEmail, "password": testPass, "rememberMe": false,
	})
	withoutChallenge := onlyCookie(t, challenge.headers.Values("Set-Cookie"), "dont_remember")
	missing := invoke(t, h.auth, "verifyTwoFactorOTP", http.MethodPost, "/two-factor/verify-otp", withoutChallenge, map[string]any{"code": capture.get()})
	if missing.status != http.StatusUnauthorized || errorCode(missing) != CodeInvalidTwoFactorCookie {
		t.Fatalf("missing challenge=%d %#v", missing.status, missing.body)
	}

	challenge = invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": testEmail, "password": testPass, "rememberMe": false,
	})
	trusted := invoke(t, h.auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", challenge.cookie, map[string]any{
		"code": h.currentTOTP(t), "trustDevice": true,
	})
	if trusted.status != http.StatusOK {
		t.Fatalf("trusted non-remembered verify=%d %#v", trusted.status, trusted.body)
	}
	for _, line := range trusted.headers.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if strings.HasSuffix(parsed.Name, ".dont_remember") && parsed.Attributes.Value != "" {
				t.Fatalf("live dont_remember leaked: %s", line)
			}
		}
	}
}

func TestTOTPCodeAndURI(t *testing.T) {
	const secret = "my-super-secret-key"
	at := time.Unix(1_700_000_000, 0)
	code, err := GenerateTOTP(secret, at, 6, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Generated by @single-auth/utils@0.4.2 createOTP(secret).totp() with
	// Date.now() fixed at 1700000000000.
	if code != "494508" {
		t.Fatalf("TOTP vector=%q", code)
	}
	valid, err := VerifyTOTP(secret, code, at.Add(30*time.Second), 6, 30*time.Second)
	if err != nil || !valid {
		t.Fatalf("window verification=%v err=%v", valid, err)
	}
	const wantURI = "otpauth://totp/My%20App:user%2Btag%40example.com?secret=NV4S243VOBSXELLTMVRXEZLUFVVWK6I&issuer=My+App&digits=6&period=30"
	if got := TOTPURI(secret, "My App", "user+tag@example.com", 6, 30*time.Second); got != wantURI {
		t.Fatalf("URI:\nwant %s\n got %s", wantURI, got)
	}
	const specialURI = "otpauth://totp/A~%20B!*'():user?secret=NV4S243VOBSXELLTMVRXEZLUFVVWK6I&issuer=A%7E+B%21*%27%28%29&digits=6&period=30"
	if got := TOTPURI(secret, "A~ B!*'()", "user", 6, 30*time.Second); got != specialURI {
		t.Fatalf("special URI:\nwant %s\n got %s", specialURI, got)
	}
}

func assertOnlyExpiredSessionCookies(t *testing.T, lines []string) {
	t.Helper()
	for _, line := range lines {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if strings.Contains(parsed.Name, "session_token") || strings.Contains(parsed.Name, "session_data") {
				if parsed.Attributes.Value != "" {
					t.Fatalf("live session cookie leaked: %s", line)
				}
			}
		}
	}
}

func responseCookie(lines []string, suffix string) *cookies.SetCookie {
	for _, line := range lines {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if strings.HasSuffix(parsed.Name, "."+suffix) || parsed.Name == suffix {
				copy := parsed
				return &copy
			}
		}
	}
	return nil
}

func decryptTwoFactorSecret(t *testing.T, row storage.Record) string {
	t.Helper()
	encrypted, _ := recordString(row, "secret")
	plain, err := baCrypto.Decrypt(testSecret, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}
