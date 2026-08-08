package username

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
)

func TestReferenceUsernameCallbackAndValidationEndpoint(t *testing.T) {
	auth := newTestAuth(t, Options{MinUsernameLength: 4}, singleauth.EmailVerificationOptions{}, false)
	_, _ = compatibilitySignUp(t, auth, "base@example.com", map[string]any{"username": "priority_user"})

	t.Run("callback URL omitted", func(t *testing.T) {
		status, _, response := usernameExchange(t, auth, http.MethodPost, "/sign-in/username", "", map[string]any{
			"username": "PRIORITY_USER", "password": "password123",
		})
		if status != http.StatusOK || response["redirect"] != false || response["token"] == "" {
			t.Fatalf("status=%d response=%#v", status, response)
		}
		if _, exists := response["url"]; exists {
			t.Fatalf("callbackURL omission must omit url: %#v", response)
		}
	})

	for _, test := range []struct {
		name     string
		username string
		code     string
	}{
		{name: "invalid username", username: "new username", code: CodeInvalidUsername},
		{name: "too short username", username: "new", code: CodeUsernameTooShort},
		{name: "empty username", username: "", code: CodeUsernameTooShort},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, _, response := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
				"name": "Invalid", "email": test.name + "@example.com", "password": "password123", "username": test.username,
			})
			compatibilityRequireError(t, status, response, http.StatusBadRequest, test.code)
		})
	}

	for _, test := range []struct {
		name      string
		username  string
		status    int
		available any
		code      string
	}{
		{name: "unavailable", username: "priority_user", status: http.StatusOK, available: false},
		{name: "unavailable normalized", username: "PRIORITY_USER", status: http.StatusOK, available: false},
		{name: "available", username: "new_username_2.2", status: http.StatusOK, available: true},
		{name: "invalid", username: "invalid username!", status: 422, code: CodeInvalidUsername},
		{name: "too short", username: "abc", status: 422, code: CodeUsernameTooShort},
		{name: "too long", username: strings.Repeat("a", 31), status: 422, code: CodeUsernameTooLong},
	} {
		t.Run("availability "+test.name, func(t *testing.T) {
			status, _, response := usernameExchange(t, auth, http.MethodPost, "/is-username-available", "", map[string]any{
				"username": test.username,
			})
			if status != test.status {
				t.Fatalf("status=%d response=%#v, want %d", status, response, test.status)
			}
			if test.code != "" {
				if response["code"] != test.code {
					t.Fatalf("response=%#v, want code %q", response, test.code)
				}
				return
			}
			if response["available"] != test.available {
				t.Fatalf("response=%#v, want available=%v", response, test.available)
			}
		})
	}
}

func TestReferenceUsernameFieldShapeAndUpdate(t *testing.T) {
	t.Run("display username fallback preserves casing", func(t *testing.T) {
		auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
		_, response := compatibilitySignUp(t, auth, "display-case@example.com", map[string]any{
			"displayUsername": "Test_Username",
		})
		user := usernameObject(t, response, "user")
		if user["username"] != "test_username" || user["displayUsername"] != "Test_Username" {
			t.Fatalf("user=%#v", user)
		}
	})

	t.Run("invalid display-only value keeps nullable username", func(t *testing.T) {
		auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
		_, response := compatibilitySignUp(t, auth, "display-invalid@example.com", map[string]any{
			"displayUsername": "Invalid Username",
		})
		user := usernameObject(t, response, "user")
		username, exists := user["username"]
		if !exists || username != nil || user["displayUsername"] != "Invalid Username" {
			t.Fatalf("user=%#v", user)
		}
	})

	t.Run("explicit empty username blocks display fallback", func(t *testing.T) {
		auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
		status, _, response := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
			"name": "Empty", "email": "explicit-empty@example.com", "password": "password123",
			"username": "", "displayUsername": "valid_username",
		})
		compatibilityRequireError(t, status, response, http.StatusBadRequest, CodeUsernameTooShort)
	})

	t.Run("explicit username and display username survive create and update", func(t *testing.T) {
		auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
		cookie, response := compatibilitySignUp(t, auth, "both-fields@example.com", map[string]any{
			"username": "custom_user", "displayUsername": "Fancy Display Name",
		})
		user := usernameObject(t, response, "user")
		if user["username"] != "custom_user" || user["displayUsername"] != "Fancy Display Name" {
			t.Fatalf("created user=%#v", user)
		}

		status, headers, update := usernameExchange(t, auth, http.MethodPost, "/update-user", cookie, map[string]any{
			"username": "priority_user", "displayUsername": "Priority Display Name",
		})
		if status != http.StatusOK || update["status"] != true {
			t.Fatalf("update status=%d body=%#v", status, update)
		}
		cookie = cookies.ApplySetCookies(cookie, headers.Values("Set-Cookie"))
		user = compatibilitySessionUser(t, auth, cookie)
		if user["username"] != "priority_user" || user["displayUsername"] != "Priority Display Name" {
			t.Fatalf("updated user=%#v", user)
		}

		status, headers, update = usernameExchange(t, auth, http.MethodPost, "/update-user", cookie, map[string]any{
			"username": "New_Priority_User",
		})
		if status != http.StatusOK || update["status"] != true {
			t.Fatalf("second update status=%d body=%#v", status, update)
		}
		cookie = cookies.ApplySetCookies(cookie, headers.Values("Set-Cookie"))
		user = compatibilitySessionUser(t, auth, cookie)
		if user["username"] != "new_priority_user" || user["displayUsername"] != "Priority Display Name" {
			t.Fatalf("username-only update user=%#v", user)
		}
	})
}

func TestReferenceUsernameCustomNormalizationAndValidator(t *testing.T) {
	t.Run("custom username normalization controls uniqueness", func(t *testing.T) {
		auth := newTestAuth(t, Options{
			MinUsernameLength: 4,
			UsernameNormalization: func(value string) string {
				value = strings.ReplaceAll(value, "0", "o")
				value = strings.ReplaceAll(value, "4", "a")
				return strings.ToLower(value)
			},
		}, singleauth.EmailVerificationOptions{}, false)
		_, response := compatibilitySignUp(t, auth, "custom-normal@example.com", map[string]any{"username": "H4XX0R"})
		if usernameObject(t, response, "user")["username"] != "haxxor" {
			t.Fatalf("response=%#v", response)
		}
		status, _, duplicate := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
			"name": "Duplicate", "email": "custom-normal-2@example.com", "password": "password123", "username": "haxxor",
		})
		compatibilityRequireError(t, status, duplicate, http.StatusBadRequest, CodeUsernameAlreadyTaken)
	})

	t.Run("display username normalization", func(t *testing.T) {
		auth := newTestAuth(t, Options{DisplayUsernameNormalization: strings.ToLower}, singleauth.EmailVerificationOptions{}, false)
		_, response := compatibilitySignUp(t, auth, "display-normal@example.com", map[string]any{
			"username": "test_username", "displayUsername": "Test Username",
		})
		user := usernameObject(t, response, "user")
		if user["username"] != "test_username" || user["displayUsername"] != "test username" {
			t.Fatalf("user=%#v", user)
		}
	})

	displayPattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	t.Run("display username validation create inferred and update", func(t *testing.T) {
		auth := newTestAuth(t, Options{
			DisplayUsernameValidator: func(value string) (bool, error) { return displayPattern.MatchString(value), nil },
		}, singleauth.EmailVerificationOptions{}, false)

		_, accepted := compatibilitySignUp(t, auth, "display-valid@example.com", map[string]any{
			"displayUsername": "Valid_Display-123",
		})
		acceptedUser := usernameObject(t, accepted, "user")
		if username, exists := acceptedUser["username"]; !exists || username != nil || acceptedUser["displayUsername"] != "Valid_Display-123" {
			t.Fatalf("accepted user=%#v", acceptedUser)
		}

		status, _, rejected := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
			"name": "Rejected", "email": "display-rejected@example.com", "password": "password123",
			"username": "invalid_display", "displayUsername": "Invalid Display!",
		})
		compatibilityRequireError(t, status, rejected, http.StatusBadRequest, CodeInvalidDisplayUsername)

		_, inferred := compatibilitySignUp(t, auth, "display-inferred@example.com", map[string]any{"username": "valid.username"})
		inferredUser := usernameObject(t, inferred, "user")
		if inferredUser["username"] != "valid.username" || inferredUser["displayUsername"] != "valid.username" {
			t.Fatalf("inferred user=%#v", inferredUser)
		}

		cookie, _ := compatibilitySignUp(t, auth, "display-update@example.com", map[string]any{
			"username": "initial_name", "displayUsername": "Initial_Name",
		})
		status, headers, updated := usernameExchange(t, auth, http.MethodPost, "/update-user", cookie, map[string]any{
			"displayUsername": "Updated_Name-123",
		})
		if status != http.StatusOK || updated["status"] != true {
			t.Fatalf("valid update status=%d response=%#v", status, updated)
		}
		cookie = cookies.ApplySetCookies(cookie, headers.Values("Set-Cookie"))
		user := compatibilitySessionUser(t, auth, cookie)
		if user["username"] != "initial_name" || user["displayUsername"] != "Updated_Name-123" {
			t.Fatalf("valid update user=%#v", user)
		}

		status, _, rejected = usernameExchange(t, auth, http.MethodPost, "/update-user", cookie, map[string]any{
			"displayUsername": "Invalid Display!",
		})
		compatibilityRequireError(t, status, rejected, http.StatusBadRequest, CodeInvalidDisplayUsername)
	})

	t.Run("custom username validator applies to availability signup and signin", func(t *testing.T) {
		auth := newTestAuth(t, Options{
			UsernameValidator: func(value string) (bool, error) { return strings.HasPrefix(value, "user_"), nil },
		}, singleauth.EmailVerificationOptions{}, false)
		status, _, available := usernameExchange(t, auth, http.MethodPost, "/is-username-available", "", map[string]any{"username": "user_valid123"})
		if status != http.StatusOK || available["available"] != true {
			t.Fatalf("valid availability status=%d response=%#v", status, available)
		}
		status, _, invalid := usernameExchange(t, auth, http.MethodPost, "/is-username-available", "", map[string]any{"username": "invalid_user"})
		compatibilityRequireError(t, status, invalid, 422, CodeInvalidUsername)
		status, _, invalid = usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
			"name": "Invalid", "email": "custom-validator@example.com", "password": "password123", "username": "invalid_user",
		})
		compatibilityRequireError(t, status, invalid, http.StatusBadRequest, CodeInvalidUsername)
		status, _, invalid = usernameExchange(t, auth, http.MethodPost, "/sign-in/username", "", map[string]any{
			"username": "invalid_user", "password": "password123",
		})
		compatibilityRequireError(t, status, invalid, 422, CodeInvalidUsername)
	})

	t.Run("post-normalization validates canonical username and preserves raw display", func(t *testing.T) {
		auth := newTestAuth(t, Options{
			ValidationOrder: ValidationOrders{Username: PostNormalization, DisplayUsername: PostNormalization},
			UsernameNormalization: func(value string) string {
				return strings.ToLower(strings.ReplaceAll(value, " ", "_"))
			},
		}, singleauth.EmailVerificationOptions{}, false)
		_, response := compatibilitySignUp(t, auth, "post-normalization@example.com", map[string]any{"username": "Test Username"})
		user := usernameObject(t, response, "user")
		if user["username"] != "test_username" || user["displayUsername"] != "Test Username" {
			t.Fatalf("user=%#v", user)
		}
	})
}

func compatibilitySignUp(t *testing.T, auth *singleauth.Auth, email string, fields map[string]any) (string, map[string]any) {
	t.Helper()
	body := map[string]any{
		"name": "Compatibility User", "email": email, "password": "password123",
	}
	for key, value := range fields {
		body[key] = value
	}
	status, headers, response := usernameExchange(t, auth, http.MethodPost, "/sign-up/email", "", body)
	if status != http.StatusOK {
		t.Fatalf("sign-up status=%d response=%#v", status, response)
	}
	return cookies.ApplySetCookies("", headers.Values("Set-Cookie")), response
}

func compatibilitySessionUser(t *testing.T, auth *singleauth.Auth, cookie string) map[string]any {
	t.Helper()
	status, _, response := usernameExchange(t, auth, http.MethodGet, "/get-session", cookie, nil)
	if status != http.StatusOK {
		t.Fatalf("get-session status=%d response=%#v", status, response)
	}
	return usernameObject(t, response, "user")
}

func compatibilityRequireError(t *testing.T, status int, response map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || response["code"] != wantCode {
		t.Fatalf("status=%d response=%#v, want status=%d code=%q", status, response, wantStatus, wantCode)
	}
}
