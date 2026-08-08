package core

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestUpdateUserAndSessionAdditionalFields(t *testing.T) {
	optional := storage.Bool(false)
	returned := storage.Bool(false)
	input := storage.Bool(false)
	schema, err := storage.CoreSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"theme": {Type: storage.FieldString, Required: optional},
			"admin": {Type: storage.FieldBoolean, Required: optional, Returned: returned, Input: input},
		}},
		"session": {Fields: map[string]storage.FieldAttribute{
			"device": {Type: storage.FieldString, Required: optional},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Schema:           schema,
	})
	cookieHeader, _, _ := createSessionTestUser(t, auth, "update@example.com")

	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/update-user", cookieHeader, map[string]any{
		"name": "Updated User", "image": nil, "theme": "dark",
	})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("update user status=%d value=%#v", status, value)
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK {
		t.Fatalf("get updated user status=%d value=%#v", status, value)
	}
	user := objectValue(t, value.(map[string]any), "user")
	if user["name"] != "Updated User" || user["theme"] != "dark" || user["image"] != nil {
		t.Fatalf("updated user = %#v", user)
	}
	if _, leaked := user["admin"]; leaked {
		t.Fatalf("returned:false field leaked: %#v", user)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/update-user", cookieHeader, map[string]any{"email": "other@example.com"})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorEmailCannotBeUpdated) {
		t.Fatalf("email update status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/update-user", cookieHeader, map[string]any{"admin": true})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorFieldNotAllowed) {
		t.Fatalf("input:false status=%d value=%#v", status, value)
	}

	status, headers, value = sessionTestRequest(t, auth, http.MethodPost, "/update-session", cookieHeader, map[string]any{"device": "laptop"})
	if status != http.StatusOK {
		t.Fatalf("update session status=%d value=%#v", status, value)
	}
	updatedSession := objectValue(t, value.(map[string]any), "session")
	if updatedSession["device"] != "laptop" {
		t.Fatalf("updated session = %#v", updatedSession)
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/update-session", cookieHeader, map[string]any{"token": "forbidden-core"})
	if status != http.StatusBadRequest || value.(map[string]any)["message"] != "No fields to update" {
		t.Fatalf("core session update status=%d value=%#v", status, value)
	}
}

func TestChangePasswordAndServerOnlySetPassword(t *testing.T) {
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
	})
	cookieHeader, _, initial := createSessionTestUser(t, auth, "password@example.com")
	userID := objectString(t, objectValue(t, initial, "user"), "id")

	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/change-password", cookieHeader, map[string]any{
		"currentPassword": "wrong-password", "newPassword": "new-password-123",
	})
	if status != http.StatusBadRequest || value.(map[string]any)["code"] != string(ErrorInvalidPassword) {
		t.Fatalf("wrong current password status=%d value=%#v", status, value)
	}
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/change-password", cookieHeader, map[string]any{
		"currentPassword": "password123", "newPassword": "new-password-123", "revokeOtherSessions": true,
	})
	if status != http.StatusOK || value.(map[string]any)["token"] == nil {
		t.Fatalf("change password status=%d value=%#v", status, value)
	}
	newCookieHeader := cookies.ApplySetCookies(cookieHeader, headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || value != nil {
		t.Fatalf("old session survived password rotation: status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", newCookieHeader, nil)
	if status != http.StatusOK || value == nil {
		t.Fatalf("new session invalid: status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": "password@example.com", "password": "password123",
	})
	if status != http.StatusUnauthorized || value.(map[string]any)["code"] != string(ErrorInvalidEmailOrPassword) {
		t.Fatalf("old password still valid: status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": "password@example.com", "password": "new-password-123",
	})
	if status != http.StatusOK {
		t.Fatalf("new password sign-in status=%d value=%#v", status, value)
	}

	if _, err := auth.Adapter().DeleteMany(t.Context(), storage.DeleteManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	}); err != nil {
		t.Fatal(err)
	}
	requestHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: newCookieHeader})
	body, _ := json.Marshal(map[string]any{"newPassword": "server-password-123"})
	requestHeaders.Set("Content-Type", "application/json")
	directRequest := contract.NewRequest(http.MethodPost, "/:direct", contract.RequestOptions{
		Headers: requestHeaders, Body: body,
	})
	response, err := auth.Invoke("setPassword", engine.DirectInput{Request: directRequest})
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("setPassword direct status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	response, err = auth.Invoke("setPassword", engine.DirectInput{Request: directRequest})
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Code != string(ErrorPasswordAlreadySet) || response.Status() != http.StatusBadRequest {
		t.Fatalf("second setPassword response=%d err=%v", response.Status(), err)
	}
	status, _, _ = sessionTestRequest(t, auth, http.MethodPost, "/set-password", "", map[string]any{"newPassword": "hidden"})
	if status != http.StatusNotFound {
		t.Fatalf("server-only endpoint exposed over HTTP: %d", status)
	}
}
