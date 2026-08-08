package admin

import (
	"net/http"
	"testing"

	"github.com/pers0na2dev/single-auth/plugins/username"
)

func TestAdminCreateUserInteroperatesWithUsernamePlugin(t *testing.T) {
	auth := newRootAuth(t, Options{}, username.NewFactory(username.Options{}))
	admin := signUpIdentity(t, auth, "Admin", "admin-username@example.com", "password123")

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
		"email":    "testuser1@example.com",
		"password": "some-secure-password",
		"name":     "James Smith",
		"role":     "user",
		"data":     map[string]any{"username": "JamesSmith"},
	})
	if status != http.StatusOK {
		t.Fatalf("normalized create status=%d body=%#v", status, body)
	}
	created := objectField(t, body, "user")
	if created["username"] != "jamessmith" || created["displayUsername"] != "JamesSmith" {
		t.Fatalf("username projection=%#v", created)
	}

	for _, test := range []struct {
		name     string
		email    string
		username string
		code     string
	}{
		{
			name: "duplicate", email: "testuser2@example.com", username: "JamesSmith",
			code: username.CodeUsernameAlreadyTaken,
		},
		{
			name: "format", email: "testuser4@example.com", username: "Invalid Username!",
			code: username.CodeInvalidUsername,
		},
		{
			name: "length", email: "testuser5@example.com", username: "ab",
			code: username.CodeUsernameTooShort,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, _, body := exchange(t, auth, http.MethodPost, "/admin/create-user", admin.Cookie, map[string]any{
				"email":    test.email,
				"password": "some-secure-password",
				"name":     test.name,
				"role":     "user",
				"data":     map[string]any{"username": test.username},
			})
			assertError(t, status, body, http.StatusBadRequest, test.code)
		})
	}
}
