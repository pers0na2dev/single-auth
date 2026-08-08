package admin

import (
	"net/http"
	"testing"

	"github.com/pers0na2dev/single-auth/security/authorization"
)

func TestCustomAccessControlProtectedFieldsRolesAndPermissionResolution(t *testing.T) {
	roles := map[string]*authorization.Role{
		"admin": authorization.NewRole(authorization.Statements{
			"user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "set-email", "get", "update"},
			"session": {"list", "revoke", "delete"},
		}),
		"user":    authorization.NewRole(authorization.Statements{"user": {"get"}}),
		"support": authorization.NewRole(authorization.Statements{"user": {"update"}}),
		"creator": authorization.NewRole(authorization.Statements{"user": {"create"}}),
	}
	auth := newRootAuth(t, Options{Roles: roles})
	admin := signUpIdentity(t, auth, "Admin", "access-admin@example.com", "password123")
	support := createDirectUser(t, auth, map[string]any{
		"name": "Support", "email": "support@example.com", "password": "password123", "role": "support",
	})
	creator := createDirectUser(t, auth, map[string]any{
		"name": "Creator", "email": "creator@example.com", "password": "password123", "role": "creator",
	})
	supportIdentity := signInIdentity(t, auth, support["email"].(string), "password123")
	creatorIdentity := signInIdentity(t, auth, creator["email"].(string), "password123")

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"name": "Initially Banned", "email": "initially-banned@example.com",
		"data": map[string]any{"banned": true, "banReason": "created by admin"},
	})
	if status != http.StatusOK {
		t.Fatalf("protected create status=%d body=%#v", status, body)
	}
	protected := objectField(t, body, "user")
	if protected["banned"] != true || protected["banReason"] != "created by admin" {
		t.Fatalf("protected create user=%#v", protected)
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", supportIdentity.Cookie, map[string]any{
		"userId": support["id"], "data": map[string]any{"name": "Support Updated"},
	})
	if status != http.StatusOK || body["name"] != "Support Updated" {
		t.Fatalf("support update status=%d body=%#v", status, body)
	}
	for _, test := range []struct {
		name string
		data map[string]any
		code string
	}{
		{"role", map[string]any{"role": "admin"}, ErrorNotAllowedToChangeUsersRole},
		{"ban", map[string]any{"banned": true}, ErrorNotAllowedToBanUsers},
		{"email", map[string]any{"email": "support-new@example.com"}, ErrorNotAllowedToSetUsersEmail},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, _, body := exchange(t, auth, http.MethodPost, "/admin/update-user", supportIdentity.Cookie, map[string]any{
				"userId": support["id"], "data": test.data,
			})
			assertError(t, status, body, http.StatusForbidden, test.code)
		})
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", creatorIdentity.Cookie, map[string]any{
		"name": "Created", "email": "created@example.com", "password": "password123",
	})
	if status != http.StatusOK || objectField(t, body, "user")["role"] != "user" {
		t.Fatalf("creator create status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", creatorIdentity.Cookie, map[string]any{
		"name": "Escalated", "email": "escalated@example.com", "role": "admin",
	})
	assertError(t, status, body, http.StatusForbidden, ErrorNotAllowedToChangeUsersRole)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", creatorIdentity.Cookie, map[string]any{
		"name": "Data Escalated", "email": "data-escalated@example.com", "data": map[string]any{"role": "admin"},
	})
	assertError(t, status, body, http.StatusForbidden, ErrorNotAllowedToChangeUsersRole)
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users", creatorIdentity.Cookie, nil)
	assertError(t, status, body, http.StatusForbidden, ErrorNotAllowedToListUsers)

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-role", admin.Cookie, map[string]any{
		"userId": support["id"], "role": "missing",
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorNotAllowedToSetNonExistentValue)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-role", admin.Cookie, map[string]any{
		"userId": support["id"], "role": "creator",
	})
	if status != http.StatusOK || objectField(t, body, "user")["role"] != "creator" {
		t.Fatalf("custom role status=%d body=%#v", status, body)
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"name": "Data Role", "email": "data-role@example.com", "password": "password123",
		"data": map[string]any{"role": "support"},
	})
	if status != http.StatusOK || objectField(t, body, "user")["role"] != "support" {
		t.Fatalf("data role status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"name": "Missing Role", "email": "missing-role@example.com", "data": map[string]any{"role": "missing"},
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorNotAllowedToSetNonExistentValue)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": support["id"], "data": map[string]any{"role": "support"},
	})
	if status != http.StatusOK || body["role"] != "support" {
		t.Fatalf("valid update role status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/update-user", admin.Cookie, map[string]any{
		"userId": support["id"], "data": map[string]any{"role": "missing"},
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorNotAllowedToSetNonExistentValue)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-role", admin.Cookie, map[string]any{
		"userId": support["id"], "role": []string{"creator", "missing"},
	})
	assertError(t, status, body, http.StatusBadRequest, ErrorNotAllowedToSetNonExistentValue)
}

func TestPermissionDirectRoleUserPrecedenceAndUserIDValidation(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "permission-admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "permission-user@example.com", "password123")
	banned := signUpIdentity(t, auth, "User", "permission-banned@example.com", "password123")

	for _, test := range []struct {
		name string
		body map[string]any
		want bool
	}{
		{"role", map[string]any{"role": "admin", "permissions": map[string]any{"user": []string{"create"}}}, true},
		{"user id", map[string]any{"userId": admin.ID, "permissions": map[string]any{"user": []string{"create"}}}, true},
		{"role wins", map[string]any{"userId": user.ID, "role": "admin", "permissions": map[string]any{"user": []string{"create"}}}, true},
		{"role denies", map[string]any{"userId": admin.ID, "role": "user", "permissions": map[string]any{"user": []string{"create"}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, _, value, err := invoke(t, auth, "userHasPermission", http.MethodPost, "", test.body, nil)
			if err != nil || status != http.StatusOK || value.(map[string]any)["success"] != test.want {
				t.Fatalf("status=%d value=%#v err=%v", status, value, err)
			}
		})
	}

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/ban-user", admin.Cookie, map[string]any{"userId": banned.ID})
	if status != http.StatusOK {
		t.Fatalf("ban permission subject status=%d body=%#v", status, body)
	}
	status, _, value, err := invoke(t, auth, "userHasPermission", http.MethodPost, "", map[string]any{
		"userId": banned.ID, "role": "admin", "permissions": map[string]any{"user": []string{"create"}},
	}, nil)
	if err != nil || status != http.StatusOK || value.(map[string]any)["success"] != true {
		t.Fatalf("banned explicit role status=%d value=%#v err=%v", status, value, err)
	}
	status, _, value, err = invoke(t, auth, "userHasPermission", http.MethodPost, "", map[string]any{
		"userId": banned.ID, "permissions": map[string]any{"user": []string{"create"}},
	}, nil)
	if err != nil || status != http.StatusOK || value.(map[string]any)["success"] != false {
		t.Fatalf("banned stored role status=%d value=%#v err=%v", status, value, err)
	}

	for _, test := range []struct {
		name    string
		body    map[string]any
		message string
	}{
		{"missing", map[string]any{"permissions": map[string]any{"user": []string{"list"}}}, "user id or role is required"},
		{"empty", map[string]any{"userId": "", "permissions": map[string]any{"user": []string{"list"}}}, "user id or role is required"},
		{"NaN", map[string]any{"userId": "NaN", "permissions": map[string]any{"user": []string{"list"}}}, "user not found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, _, _, err := invoke(t, auth, "userHasPermission", http.MethodPost, "", test.body, nil)
			if err == nil || status != http.StatusBadRequest || err.Error() != test.message {
				t.Fatalf("status=%d err=%v", status, err)
			}
		})
	}

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/has-permission", admin.Cookie, map[string]any{
		"role": "user", "permissions": map[string]any{"user": []string{"set-role"}},
	})
	if status != http.StatusOK || body["success"] != true {
		t.Fatalf("session precedence status=%d body=%#v", status, body)
	}
}

func TestPermissionChecksCustomResourcesUsingRoleAndUserID(t *testing.T) {
	roles := map[string]*authorization.Role{
		"admin": authorization.NewRole(authorization.Statements{
			"user": {"create", "list"}, "order": {"create", "read"},
		}),
		"user": authorization.NewRole(authorization.Statements{"order": {"read"}}),
	}
	auth := newRootAuth(t, Options{Roles: roles})
	admin := signUpIdentity(t, auth, "Admin", "custom-permission-admin@example.com", "password123")
	tests := []struct {
		name string
		body map[string]any
		want bool
	}{
		{
			name: "role allows every resource",
			body: map[string]any{"role": "admin", "permissions": map[string]any{
				"user": []string{"create"}, "order": []string{"create"},
			}},
			want: true,
		},
		{
			name: "user id resolves role",
			body: map[string]any{"userId": admin.ID, "permissions": map[string]any{
				"user": []string{"create"}, "order": []string{"read"},
			}},
			want: true,
		},
		{
			name: "one denied resource denies request",
			body: map[string]any{"role": "admin", "permissions": map[string]any{
				"user": []string{"create"}, "order": []string{"update-many"},
			}},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, _, value, err := invoke(t, auth, "userHasPermission", http.MethodPost, "", test.body, nil)
			result, ok := value.(map[string]any)
			if err != nil || status != http.StatusOK || !ok || result["success"] != test.want {
				t.Fatalf("status=%d value=%#v err=%v", status, value, err)
			}
		})
	}
}
