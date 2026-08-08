package admin

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestAdminUserCRUDListingAuthorizationAndPassword(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "user@example.com", "password123")

	status, _, body := exchange(t, auth, http.MethodGet, "/admin/get-user?id="+url.QueryEscape(user.ID), admin.Cookie, nil)
	if status != http.StatusOK || body["email"] != user.Email || body["role"] != "user" || body["banned"] != false {
		t.Fatalf("get user status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/get-user?id="+url.QueryEscape(admin.ID), user.Cookie, nil)
	assertError(t, status, body, http.StatusForbidden, ErrorNotAllowedToGetUser)

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"name": "Multi Role", "email": "multi@example.com", "password": "test", "role": []string{"user", "admin"},
	})
	if status != http.StatusOK || objectField(t, body, "user")["role"] != "user,admin" {
		t.Fatalf("create multi status=%d body=%#v", status, body)
	}
	multi := objectField(t, body, "user")
	multiID, _ := multi["id"].(string)

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"name": "Passwordless", "email": "passwordless@example.com", "role": "user",
	})
	if status != http.StatusOK {
		t.Fatalf("create passwordless status=%d body=%#v", status, body)
	}
	passwordless := objectField(t, body, "user")
	passwordlessID, _ := passwordless["id"].(string)

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", user.Cookie, map[string]any{
		"name": "Denied", "email": "denied@example.com",
	})
	assertError(t, status, body, http.StatusForbidden, ErrorNotAllowedToCreateUsers)

	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?limit=2", admin.Cookie, nil)
	if status != http.StatusOK || len(body["users"].([]any)) != 2 || body["total"].(jsonNumber).String() == "0" {
		t.Fatalf("list status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?searchValue=Multi&searchField=name&searchOperator=contains", admin.Cookie, nil)
	if status != http.StatusOK || len(body["users"].([]any)) != 1 {
		t.Fatalf("search status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?filterValue=admin&filterField=role&filterOperator=contains", admin.Cookie, nil)
	if status != http.StatusOK || len(body["users"].([]any)) < 2 {
		t.Fatalf("filter status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?filterValue="+url.QueryEscape(user.ID)+"&filterField=_id&filterOperator=ne", admin.Cookie, nil)
	if status != http.StatusOK || containsUserID(body["users"].([]any), user.ID) {
		t.Fatalf("id filter status=%d body=%#v", status, body)
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-role", admin.Cookie, map[string]any{"userId": user.ID, "role": []string{"user", "admin"}})
	if status != http.StatusOK || objectField(t, body, "user")["role"] != "user,admin" {
		t.Fatalf("set role status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": user.ID, "data": map[string]any{"name": "Updated", "email": "UPDATED@EXAMPLE.COM", "emailVerified": false},
	})
	if status != http.StatusOK || body["name"] != "Updated" || body["email"] != "updated@example.com" {
		t.Fatalf("update status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": user.ID, "data": map[string]any{"password": "plaintext"},
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorPasswordCannotBeUpdatedViaUpdateUser)

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-user-password", admin.Cookie, map[string]any{
		"userId": passwordlessID, "newPassword": "new-password",
	})
	if status != http.StatusOK || body["status"] != true {
		t.Fatalf("set password status=%d body=%#v", status, body)
	}
	_ = signInIdentity(t, auth, "passwordless@example.com", "new-password")
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-user-password", admin.Cookie, map[string]any{
		"userId": passwordlessID, "newPassword": "short",
	})
	assertError(t, status, body, http.StatusBadRequest, "PASSWORD_TOO_SHORT")

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/remove-user", admin.Cookie, map[string]any{"userId": multiID})
	if status != http.StatusOK || body["success"] != true {
		t.Fatalf("remove status=%d body=%#v", status, body)
	}
	accounts, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: multiID}},
	})
	if err != nil || len(accounts) != 0 {
		t.Fatalf("removed user accounts=%#v err=%v", accounts, err)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/remove-user", admin.Cookie, map[string]any{"userId": admin.ID})
	assertError(t, status, body, http.StatusBadRequest, ErrorYouCannotRemoveYourself)
}

func TestAdminBanLifecycleExpiredBanAndAuthoritativeAuthorization(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	options := Options{BannedUserMessage: "Custom banned user message", DefaultBanReason: "policy"}
	options.Runtime.Clock = func() time.Time { return now }
	// Root supplies its own clock to the factory. The plugin clock is therefore
	// tested via explicit banExpiresIn and persisted values rather than wall time.
	auth := newRootAuth(t, options)
	admin := signUpIdentity(t, auth, "Admin", "admin-ban@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "user-ban@example.com", "password123")

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/ban-user", admin.Cookie, map[string]any{
		"userId": user.ID, "banReason": "abuse", "banExpiresIn": 3600,
	})
	banned := objectField(t, body, "user")
	if status != http.StatusOK || banned["banned"] != true || banned["banReason"] != "abuse" || banned["banExpires"] == nil {
		t.Fatalf("ban status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users", user.Cookie, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked banned session status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{"email": user.Email, "password": "password123"})
	assertError(t, status, body, http.StatusForbidden, ErrorBannedUser)
	if body["message"] != "Custom banned user message" {
		t.Fatalf("banned message=%#v", body)
	}

	_, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: user.ID}},
		Update: storage.Record{"banned": true, "banExpires": time.Now().Add(-time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = signInIdentity(t, auth, user.Email, "password123")
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: user.ID}}})
	if err != nil || stored["banned"] != false || stored["banReason"] != nil || stored["banExpires"] != nil {
		t.Fatalf("expired ban stored=%#v err=%v", stored, err)
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": admin.ID, "data": map[string]any{"banned": true},
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorYouCannotBanYourself)

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-role", admin.Cookie, map[string]any{"userId": admin.ID, "role": "user"})
	if status != http.StatusOK {
		t.Fatalf("demote status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-role", admin.Cookie, map[string]any{"userId": admin.ID, "role": "admin"})
	assertError(t, status, body, http.StatusForbidden, ErrorNotAllowedToChangeUsersRole)
}

func TestAdminImpersonationSessionListingStopAndRevocation(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "imp-admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "imp-user@example.com", "password123")
	secondAdmin := signUpIdentity(t, auth, "Second Admin", "second-admin@example.com", "password123")

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/impersonate-user", admin.Cookie, map[string]any{"userId": secondAdmin.ID})
	assertError(t, status, body, http.StatusForbidden, ErrorYouCannotImpersonateAdmins)

	status, headers, body := exchange(t, auth, http.MethodPost, "/admin/impersonate-user", admin.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK || objectField(t, body, "user")["id"] != user.ID || objectField(t, body, "session")["impersonatedBy"] != admin.ID {
		t.Fatalf("impersonate status=%d body=%#v", status, body)
	}
	impersonatedCookie := cookies.ApplySetCookies(admin.Cookie, headers.Values("Set-Cookie"))
	status, _, body = exchange(t, auth, http.MethodGet, "/get-session", impersonatedCookie, nil)
	if status != http.StatusOK || objectField(t, body, "user")["id"] != user.ID {
		t.Fatalf("impersonated get-session status=%d body=%#v", status, body)
	}
	status, headers, body = exchange(t, auth, http.MethodPost, "/admin/stop-impersonating", impersonatedCookie, map[string]any{})
	if status != http.StatusOK || objectField(t, body, "user")["id"] != admin.ID {
		t.Fatalf("stop status=%d body=%#v", status, body)
	}
	restoredCookie := cookies.ApplySetCookies(impersonatedCookie, headers.Values("Set-Cookie"))
	status, _, body = exchange(t, auth, http.MethodGet, "/get-session", restoredCookie, nil)
	if status != http.StatusOK || objectField(t, body, "user")["id"] != admin.ID {
		t.Fatalf("restored get-session status=%d body=%#v", status, body)
	}

	userSession := signInIdentity(t, auth, user.Email, "password123")
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/list-user-sessions", restoredCookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK || len(body["sessions"].([]any)) == 0 {
		t.Fatalf("list user sessions status=%d body=%#v", status, body)
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "session", Where: []storage.Where{{Field: "userId", Value: user.ID}}})
	if err != nil || stored == nil {
		t.Fatalf("stored session=%#v err=%v", stored, err)
	}
	token, _ := stored["token"].(string)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/revoke-user-session", restoredCookie, map[string]any{"sessionToken": token})
	if status != http.StatusOK || body["success"] != true {
		t.Fatalf("revoke one status=%d body=%#v", status, body)
	}
	_ = userSession
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/revoke-user-sessions", restoredCookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK || body["success"] != true {
		t.Fatalf("revoke all status=%d body=%#v", status, body)
	}
}

type jsonNumber interface{ String() string }

func containsUserID(users []any, id string) bool {
	for _, raw := range users {
		user, _ := raw.(map[string]any)
		if user["id"] == id {
			return true
		}
	}
	return false
}
