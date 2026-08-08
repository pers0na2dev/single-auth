package core

import (
	"net/http"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestListAndUnlinkAccounts(t *testing.T) {
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
	})
	cookieHeader, _, session := createSessionTestUser(t, auth, "accounts@example.com")
	userID := objectString(t, objectValue(t, session, "user"), "id")

	status, _, value := sessionTestRequest(t, auth, http.MethodGet, "/list-accounts", cookieHeader, nil)
	accounts, ok := value.([]any)
	if status != http.StatusOK || !ok || len(accounts) != 1 {
		t.Fatalf("list accounts status=%d value=%#v", status, value)
	}
	credential := accounts[0].(map[string]any)
	if _, leaked := credential["password"]; leaked {
		t.Fatalf("credential password leaked: %#v", credential)
	}
	if scopes, ok := credential["scopes"].([]any); !ok || len(scopes) != 0 {
		t.Fatalf("credential scopes = %#v", credential["scopes"])
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/unlink-account", cookieHeader, map[string]any{
		"providerId": "credential",
	})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorFailedToUnlinkLastAccount) {
		t.Fatalf("unlink last status=%d value=%#v", status, value)
	}
	now := time.Now().UTC()
	if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "account",
		Data: storage.Record{
			"id": "social-account", "providerId": "github", "accountId": "gh-1",
			"userId": userID, "accessToken": "secret-token", "scope": "read:user,user:email",
			"createdAt": now, "updatedAt": now,
		},
		ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/list-accounts", cookieHeader, nil)
	accounts = value.([]any)
	if status != http.StatusOK || len(accounts) != 2 {
		t.Fatalf("list linked accounts status=%d value=%#v", status, value)
	}
	for _, item := range accounts {
		if _, leaked := item.(map[string]any)["accessToken"]; leaked {
			t.Fatalf("OAuth token leaked: %#v", item)
		}
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/unlink-account", cookieHeader, map[string]any{
		"providerId": "github", "accountId": "gh-1",
	})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("unlink social status=%d value=%#v", status, value)
	}
}
