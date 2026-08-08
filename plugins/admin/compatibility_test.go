package admin

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/authorization"
)

func TestAdminNonAdminAuthorizationAndMissingTargetMatrix(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "matrix-admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "matrix-user@example.com", "password123")
	target := signUpIdentity(t, auth, "Target", "matrix-target@example.com", "password123")

	denied := []struct {
		name, method, path, code string
		body                     any
	}{
		{"get", http.MethodGet, "/admin/get-user?id=" + url.QueryEscape(target.ID), ErrorNotAllowedToGetUser, nil},
		{"create", http.MethodPost, "/admin/create-user", ErrorNotAllowedToCreateUsers, map[string]any{"name": "Denied", "email": "matrix-denied@example.com"}},
		{"list", http.MethodGet, "/admin/list-users", ErrorNotAllowedToListUsers, nil},
		{"set role", http.MethodPost, "/admin/set-role", ErrorNotAllowedToChangeUsersRole, map[string]any{"userId": target.ID, "role": "admin"}},
		{"ban", http.MethodPost, "/admin/ban-user", ErrorNotAllowedToBanUsers, map[string]any{"userId": target.ID}},
		{"unban", http.MethodPost, "/admin/unban-user", ErrorNotAllowedToBanUsers, map[string]any{"userId": target.ID}},
		{"impersonate", http.MethodPost, "/admin/impersonate-user", ErrorNotAllowedToImpersonateUsers, map[string]any{"userId": target.ID}},
		{"delete", http.MethodPost, "/admin/remove-user", ErrorNotAllowedToDeleteUsers, map[string]any{"userId": target.ID}},
		{"set password", http.MethodPost, "/admin/set-user-password", ErrorNotAllowedToSetUsersPassword, map[string]any{"userId": target.ID, "newPassword": "new-password"}},
		{"update", http.MethodPost, "/admin/update-user", ErrorNotAllowedToUpdateUsers, map[string]any{"userId": target.ID, "data": map[string]any{"name": "Denied"}}},
		{"list sessions", http.MethodPost, "/admin/list-user-sessions", ErrorNotAllowedToListUsersSessions, map[string]any{"userId": target.ID}},
		{"revoke sessions", http.MethodPost, "/admin/revoke-user-sessions", ErrorNotAllowedToRevokeUsersSessions, map[string]any{"userId": target.ID}},
	}
	for _, test := range denied {
		t.Run("non-admin "+test.name, func(t *testing.T) {
			status, _, body := exchange(t, auth, test.method, test.path, user.Cookie, test.body)
			assertError(t, status, body, http.StatusForbidden, test.code)
		})
	}

	missing := []struct {
		name, path string
		body       map[string]any
	}{
		{"set role", "/admin/set-role", map[string]any{"userId": "missing-user", "role": "admin"}},
		{"ban", "/admin/ban-user", map[string]any{"userId": "missing-user"}},
		{"unban", "/admin/unban-user", map[string]any{"userId": "missing-user"}},
		{"update", "/admin/update-user", map[string]any{"userId": "missing-user", "data": map[string]any{"name": "Missing"}}},
		{"set password", "/admin/set-user-password", map[string]any{"userId": "missing-user", "newPassword": "new-password"}},
	}
	for _, test := range missing {
		t.Run("missing "+test.name, func(t *testing.T) {
			status, _, body := exchange(t, auth, http.MethodPost, test.path, admin.Cookie, test.body)
			assertError(t, status, body, http.StatusNotFound, string(singleauth.ErrorUserNotFound))
		})
	}

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": target.ID, "data": map[string]any{},
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorNoDataToUpdate)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": target.ID, "data": map[string]any{"email": admin.Email},
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorUserAlreadyExistsUseAnotherEmail)

	passwordCases := []struct {
		name, userID, password string
		code                   string
	}{
		{"empty user id", "", "new-password", "VALIDATION_ERROR"},
		{"empty password", target.ID, "", "VALIDATION_ERROR"},
		{"short password", target.ID, "1234567", string(singleauth.ErrorPasswordTooShort)},
		{"long password", target.ID, strings.Repeat("a", 129), string(singleauth.ErrorPasswordTooLong)},
	}
	for _, test := range passwordCases {
		t.Run(test.name, func(t *testing.T) {
			status, _, body := exchange(t, auth, http.MethodPost, "/admin/set-user-password", admin.Cookie, map[string]any{
				"userId": test.userID, "newPassword": test.password,
			})
			assertError(t, status, body, http.StatusBadRequest, test.code)
		})
	}
}

func TestAdminListUsersSearchFilterSortOffsetAndFalsyFilter(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "list-admin@example.com", "password123")
	alpha := createDirectUser(t, auth, map[string]any{"name": "Alpha", "email": "alpha-list@example.com", "role": "user"})
	_ = createDirectUser(t, auth, map[string]any{"name": "Beta", "email": "beta-list@example.com", "role": "admin"})
	gamma := createDirectUser(t, auth, map[string]any{"name": "Gamma", "email": "gamma-list@example.com", "role": "user"})

	status, _, body := exchange(t, auth, http.MethodGet, "/admin/list-users?sortBy=name&sortDirection=asc", admin.Cookie, nil)
	if status != http.StatusOK {
		t.Fatalf("sort asc status=%d body=%#v", status, body)
	}
	names := userNames(body["users"].([]any))
	if !sort.StringsAreSorted(names) {
		t.Fatalf("ascending names=%#v", names)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?sortBy=name&sortDirection=desc&limit=1&offset=1", admin.Cookie, nil)
	if status != http.StatusOK || len(body["users"].([]any)) != 1 || body["limit"].(jsonNumber).String() != "1" || body["offset"].(jsonNumber).String() != "1" {
		t.Fatalf("sort/offset status=%d body=%#v", status, body)
	}

	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?searchValue=Gamma&searchField=name&searchOperator=contains", admin.Cookie, nil)
	if status != http.StatusOK || len(body["users"].([]any)) != 1 || body["users"].([]any)[0].(map[string]any)["id"] != gamma["id"] {
		t.Fatalf("name search status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?filterValue=admin&filterField=role&filterOperator=eq&searchValue=list&searchField=email&searchOperator=contains", admin.Cookie, nil)
	if status != http.StatusOK || len(body["users"].([]any)) != 2 {
		t.Fatalf("combined filter status=%d body=%#v", status, body)
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/ban-user", admin.Cookie, map[string]any{"userId": gamma["id"]})
	if status != http.StatusOK {
		t.Fatalf("ban for falsy filter status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users?filterValue=false&filterField=banned&filterOperator=eq", admin.Cookie, nil)
	if status != http.StatusOK || containsUserID(body["users"].([]any), gamma["id"].(string)) || !containsUserID(body["users"].([]any), alpha["id"].(string)) {
		t.Fatalf("false filter status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/unban-user", admin.Cookie, map[string]any{"userId": gamma["id"]})
	if status != http.StatusOK || objectField(t, body, "user")["banned"] != false {
		t.Fatalf("unban status=%d body=%#v", status, body)
	}
}

func TestAdminDefaultBanAndUpdateBanRevokesSessions(t *testing.T) {
	now := time.Date(2026, 8, 9, 16, 0, 0, 0, time.UTC)
	auth := newRootAuthConfigured(t, Options{DefaultBanReason: "policy", DefaultBanExpiresIn: 2 * time.Hour}, func(options *singleauth.Options) {
		options.Clock = func() time.Time { return now }
	})
	admin := signUpIdentity(t, auth, "Admin", "default-ban-admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "default-ban-user@example.com", "password123")

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/ban-user", admin.Cookie, map[string]any{"userId": user.ID})
	banned := objectField(t, body, "user")
	expiresAt, parseErr := time.Parse(time.RFC3339Nano, banned["banExpires"].(string))
	if status != http.StatusOK || banned["banReason"] != "policy" || parseErr != nil || !expiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("default ban status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/unban-user", admin.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK {
		t.Fatalf("unban status=%d body=%#v", status, body)
	}
	active := signInIdentity(t, auth, user.Email, "password123")
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": user.ID, "data": map[string]any{"banned": true, "banReason": "updated ban"},
	})
	if status != http.StatusOK || body["banned"] != true {
		t.Fatalf("update ban status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/get-session", active.Cookie, nil)
	if status != http.StatusOK || len(body) != 0 {
		t.Fatalf("revoked update-ban session status=%d body=%#v", status, body)
	}
}

func TestAdminCanImpersonateAdminsWithPermissionOrLegacyOption(t *testing.T) {
	_, defaultRoles := DefaultAccessControl()
	roles := map[string]*authorization.Role{
		"admin": defaultRoles["admin"],
		"user":  defaultRoles["user"],
		"super-admin": authorization.NewRole(authorization.Statements{
			"user": {"impersonate", "impersonate-admins"},
		}),
	}
	auth := newRootAuth(t, Options{Roles: roles})
	super := createDirectUser(t, auth, map[string]any{
		"name": "Super", "email": "super-impersonate@example.com", "password": "password123", "role": "super-admin",
	})
	superIdentity := signInIdentity(t, auth, super["email"].(string), "password123")
	target := signUpIdentity(t, auth, "Admin", "target-admin-permission@example.com", "password123")
	status, _, body := exchange(t, auth, http.MethodPost, "/admin/impersonate-user", superIdentity.Cookie, map[string]any{"userId": target.ID})
	if status != http.StatusOK || objectField(t, body, "user")["id"] != target.ID {
		t.Fatalf("permission impersonate status=%d body=%#v", status, body)
	}

	legacy := newRootAuth(t, Options{AllowImpersonatingAdmins: true})
	actor := signUpIdentity(t, legacy, "Admin", "legacy-actor@example.com", "password123")
	legacyTarget := signUpIdentity(t, legacy, "Second Admin", "legacy-target@example.com", "password123")
	status, _, body = exchange(t, legacy, http.MethodPost, "/admin/impersonate-user", actor.Cookie, map[string]any{"userId": legacyTarget.ID})
	if status != http.StatusOK || objectField(t, body, "user")["id"] != legacyTarget.ID {
		t.Fatalf("legacy impersonate status=%d body=%#v", status, body)
	}
}

func userNames(users []any) []string {
	names := make([]string, 0, len(users))
	for _, raw := range users {
		user, _ := raw.(map[string]any)
		name, _ := user["name"].(string)
		names = append(names, name)
	}
	return names
}
