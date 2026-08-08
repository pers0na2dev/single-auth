package core

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDeleteUserImmediateAndVerificationFlow(t *testing.T) {
	before, after := 0, 0
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		User: UserOptions{DeleteUser: DeleteUserOptions{
			Enabled: true,
			BeforeDelete: func(context.Context, model.User) error {
				before++
				return nil
			},
			AfterDelete: func(context.Context, model.User) error {
				after++
				return nil
			},
		}},
	})
	cookieHeader, _, session := createSessionTestUser(t, auth, "delete@example.com")
	userID := objectString(t, objectValue(t, session, "user"), "id")
	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/delete-user", cookieHeader, map[string]any{
		"password": "wrong-password",
	})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorInvalidPassword) {
		t.Fatalf("wrong delete password status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/delete-user", cookieHeader, map[string]any{
		"password": "password123",
	})
	if status != http.StatusOK || value.(map[string]any)["message"] != "User deleted" {
		t.Fatalf("delete user status=%d value=%#v", status, value)
	}
	if before != 1 || after != 1 {
		t.Fatalf("delete callbacks before=%d after=%d", before, after)
	}
	for _, modelName := range []string{"user", "session", "account"} {
		field := "id"
		if modelName != "user" {
			field = "userId"
		}
		count, err := auth.Adapter().Count(t.Context(), storage.CountParams{
			Model: modelName, Where: []storage.Where{{Field: field, Value: userID}},
		})
		if err != nil || count != 0 {
			t.Fatalf("%s remaining count=%d err=%v", modelName, count, err)
		}
	}

	var deletion DeleteAccountMessage
	verifiedDelete := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		User: UserOptions{DeleteUser: DeleteUserOptions{
			Enabled: true,
			SendDeleteAccountVerification: func(_ context.Context, message DeleteAccountMessage) error {
				deletion = message
				return nil
			},
		}},
	})
	verifiedCookies, _, _ := createSessionTestUser(t, verifiedDelete, "delete-verify@example.com")
	status, _, value = sessionTestRequest(t, verifiedDelete, http.MethodPost, "/delete-user", verifiedCookies, map[string]any{
		"callbackURL": "http://auth.test/deleted",
	})
	if status != http.StatusOK || value.(map[string]any)["message"] != "Verification email sent" || deletion.Token == "" {
		t.Fatalf("delete verification status=%d value=%#v message=%#v", status, value, deletion)
	}
	callback := "/delete-user/callback?token=" + url.QueryEscape(deletion.Token) +
		"&callbackURL=" + url.QueryEscape("http://auth.test/deleted")
	status, headers, _ := sessionTestRequest(t, verifiedDelete, http.MethodGet, callback, verifiedCookies, nil)
	if status != http.StatusFound || headers.Get("Location") != "http://auth.test/deleted" {
		t.Fatalf("delete callback status=%d location=%q", status, headers.Get("Location"))
	}
}

func TestChangeEmailTwoStepAndUnverifiedFastPath(t *testing.T) {
	var verificationMessages []EmailVerificationMessage
	var confirmation ChangeEmailConfirmationMessage
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		EmailVerification: EmailVerificationOptions{
			SendVerificationEmail: func(_ context.Context, message EmailVerificationMessage) error {
				verificationMessages = append(verificationMessages, message)
				return nil
			},
		},
		User: UserOptions{ChangeEmail: ChangeEmailOptions{
			Enabled:                        true,
			UpdateEmailWithoutVerification: true,
		}},
	})
	cookieHeader, _, _ := createSessionTestUser(t, auth, "old@example.com")
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/change-email", cookieHeader, map[string]any{
		"newEmail": "new@example.com",
	})
	if status != http.StatusOK || value.(map[string]any)["status"] != true || len(verificationMessages) != 1 {
		t.Fatalf("unverified change status=%d value=%#v messages=%d", status, value, len(verificationMessages))
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || objectValue(t, value.(map[string]any), "user")["email"] != "new@example.com" {
		t.Fatalf("unverified changed session status=%d value=%#v", status, value)
	}

	verified := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		EmailVerification: EmailVerificationOptions{
			SendVerificationEmail: func(_ context.Context, message EmailVerificationMessage) error {
				verificationMessages = append(verificationMessages, message)
				return nil
			},
		},
		User: UserOptions{ChangeEmail: ChangeEmailOptions{
			Enabled: true,
			SendChangeEmailConfirmation: func(_ context.Context, message ChangeEmailConfirmationMessage) error {
				confirmation = message
				return nil
			},
		}},
	})
	verifiedCookies, _, initial := createSessionTestUser(t, verified, "verified-old@example.com")
	verifiedUserID := objectString(t, objectValue(t, initial, "user"), "id")
	if _, err := verified.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: verifiedUserID}},
		Update: storage.Record{"emailVerified": true},
	}); err != nil {
		t.Fatal(err)
	}
	verificationMessages = nil
	status, _, value = sessionTestRequest(t, verified, http.MethodPost, "/change-email", verifiedCookies, map[string]any{
		"newEmail": "verified-new@example.com",
	})
	if status != http.StatusOK || confirmation.Token == "" {
		t.Fatalf("confirmation status=%d value=%#v message=%#v", status, value, confirmation)
	}
	status, _, value = sessionTestRequest(t, verified, http.MethodGet, "/verify-email?token="+url.QueryEscape(confirmation.Token), verifiedCookies, nil)
	if status != http.StatusOK || len(verificationMessages) != 1 {
		t.Fatalf("confirmation verify status=%d value=%#v messages=%d", status, value, len(verificationMessages))
	}
	secondToken := verificationMessages[0].Token
	status, headers, value = sessionTestRequest(t, verified, http.MethodGet, "/verify-email?token="+url.QueryEscape(secondToken), verifiedCookies, nil)
	if status != http.StatusOK || objectValue(t, value.(map[string]any), "user")["email"] != "verified-new@example.com" {
		t.Fatalf("new email verify status=%d value=%#v", status, value)
	}
	verifiedCookies = cookies.ApplySetCookies(verifiedCookies, headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(t, verified, http.MethodGet, "/get-session", verifiedCookies, nil)
	user := objectValue(t, value.(map[string]any), "user")
	if status != http.StatusOK || user["email"] != "verified-new@example.com" || user["emailVerified"] != true {
		t.Fatalf("verified changed user status=%d user=%#v", status, user)
	}
}
