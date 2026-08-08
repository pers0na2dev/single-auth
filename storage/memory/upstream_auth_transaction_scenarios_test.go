package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/plugins/additionalfields"
	"github.com/pers0na2dev/single-auth/storage"
)

func supportsMemoryAuthFlowScenario(scenario string) bool {
	switch scenario {
	case "should successfully sign up", "should successfully sign in",
		"should reset password with a single-use token", "should successfully get session",
		"should not sign in with invalid email", "should store and retrieve timestamps correctly across timezones",
		"should sign up with additional fields":
		return true
	default:
		return false
	}
}

func runMemoryAuthFlowScenario(t *testing.T, vector memoryAdapterVector) {
	t.Helper()
	var delivered singleauth.PasswordResetMessage
	options := singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return password, nil },
				Verify: func(hash, password string) bool { return hash == password },
			},
			SendResetPassword: func(_ context.Context, message singleauth.PasswordResetMessage) error {
				delivered = message
				return nil
			},
		},
	}
	if vector.Scenario == "should sign up with additional fields" {
		options.PluginFactories = []singleauth.PluginFactory{additionalfields.NewFactory(additionalfields.Options{
			User: additionalfields.Fields{{
				Name:      "dateField",
				Attribute: storage.FieldAttribute{Type: storage.FieldDate},
			}},
		})}
	}
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	api := auth.API()
	email := "memory-behavior@example.com"
	password := "password-123"

	signUp := func() singleauth.SignUpEmailResult {
		result, err := api.SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
			Name: "Memory Behavior", Email: email, Password: password,
			Image: model.Present(""),
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	switch vector.Scenario {
	case "should successfully sign up":
		result := signUp()
		if result.User.ID == "" || result.User.Email != email || result.User.Name != "Memory Behavior" ||
			result.User.EmailVerified || result.User.CreatedAt.IsZero() || result.User.UpdatedAt.IsZero() {
			t.Fatalf("sign-up result = %#v", result)
		}
		if image, ok := result.User.Image.Get(); !ok || image != "" {
			t.Fatalf("sign-up image = %#v", result.User.Image)
		}
	case "should successfully sign in":
		created := signUp()
		result, err := api.SignInEmail(t.Context(), singleauth.SignInEmailInput{Email: email, Password: password})
		if err != nil || result.User.ID != created.User.ID || result.Token == "" {
			t.Fatalf("sign-in result = %#v, err=%v", result, err)
		}
	case "should successfully get session":
		created := signUp()
		cookie := cookies.ApplySetCookies("", created.Headers.Values("Set-Cookie"))
		session, err := api.GetSession(t.Context(), singleauth.GetSessionInput{Headers: memoryCookieHeaders(cookie)})
		if err != nil || session == nil || session.User.ID != created.User.ID || session.Session.ID == "" {
			t.Fatalf("get-session result = %#v, err=%v", session, err)
		}
		if session.User.Email != created.User.Email || !session.User.CreatedAt.Equal(created.User.CreatedAt) {
			t.Fatalf("session user = %#v, sign-up user=%#v", session.User, created.User)
		}
	case "should not sign in with invalid email":
		if _, err := api.SignInEmail(t.Context(), singleauth.SignInEmailInput{Email: "missing@example.com", Password: password}); err == nil {
			t.Fatal("invalid email sign-in succeeded")
		}
	case "should store and retrieve timestamps correctly across timezones":
		created := signUp()
		signedIn, err := api.SignInEmail(t.Context(), singleauth.SignInEmailInput{Email: email, Password: password})
		if err != nil {
			t.Fatal(err)
		}
		// time.Time is absolute in Go; converting to distant locations must not
		// change the persisted instant.
		london, _ := time.LoadLocation("Europe/London")
		losAngeles, _ := time.LoadLocation("America/Los_Angeles")
		if !created.User.CreatedAt.In(london).Equal(signedIn.User.CreatedAt.In(losAngeles)) {
			t.Fatalf("timezone round-trip = %s / %s", created.User.CreatedAt, signedIn.User.CreatedAt)
		}
	case "should reset password with a single-use token":
		created := signUp()
		requested, err := api.RequestPasswordReset(t.Context(), singleauth.RequestPasswordResetInput{
			Email: email, RedirectTo: "http://localhost:3000/reset-password",
		})
		if err != nil || !requested.Status || len(delivered.Token) <= 10 {
			t.Fatalf("password reset request = %#v delivered=%#v err=%v", requested, delivered, err)
		}
		reset, err := api.ResetPassword(t.Context(), singleauth.ResetPasswordInput{Token: delivered.Token, NewPassword: "new-password-123"})
		if err != nil || !reset.Status {
			t.Fatalf("password reset = %#v, err=%v", reset, err)
		}
		if _, err := api.SignInEmail(t.Context(), singleauth.SignInEmailInput{Email: email, Password: password}); err == nil {
			t.Fatal("old password remained valid")
		}
		signedIn, err := api.SignInEmail(t.Context(), singleauth.SignInEmailInput{Email: email, Password: "new-password-123"})
		if err != nil || signedIn.User.ID != created.User.ID {
			t.Fatalf("new password sign-in = %#v, err=%v", signedIn, err)
		}
		if _, err := api.ResetPassword(t.Context(), singleauth.ResetPasswordInput{Token: delivered.Token, NewPassword: "replay-password-123"}); err == nil {
			t.Fatal("single-use reset token replay succeeded")
		}
	case "should sign up with additional fields":
		dateField := time.Date(2026, 8, 9, 12, 34, 56, 0, time.UTC)
		fields := model.Fields{}
		fields.Set("dateField", dateField.Format(time.RFC3339Nano))
		created, err := api.SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
			Name: "Memory Behavior", Email: email, Password: password, AdditionalFields: fields,
		})
		if err != nil {
			t.Fatal(err)
		}
		cookie := cookies.ApplySetCookies("", created.Headers.Values("Set-Cookie"))
		session, err := api.GetSession(t.Context(), singleauth.GetSessionInput{Headers: memoryCookieHeaders(cookie)})
		if err != nil || session == nil {
			t.Fatalf("additional-field session = %#v, err=%v", session, err)
		}
		value, exists := session.User.AdditionalFields.Lookup("dateField").Get()
		stored, ok := value.(time.Time)
		if !exists || !ok || !stored.Equal(dateField) {
			t.Fatalf("dateField = %#v (exists=%v), want %s", value, exists, dateField)
		}
	default:
		t.Fatalf("unsupported auth-flow scenario %q", vector.Scenario)
	}
}

func memoryCookieHeaders(cookie string) contract.Headers {
	if cookie == "" {
		return contract.Headers{}
	}
	return contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie})
}

func runMemoryTransactionScenario(t *testing.T, vector memoryAdapterVector) {
	t.Helper()
	if vector.Scenario != "transaction ─ should rollback failing transaction" {
		t.Fatalf("unsupported transaction scenario %q", vector.Scenario)
	}
	harness := newMemoryBehaviorHarness(t, vector)
	sentinel := errors.New("rollback")
	err := harness.adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
		mustMemoryCreate(t, transaction, "user", storage.Record{
			"id": harness.id(1), "name": "rollback", "email": "rollback@email.com", "emailVerified": false,
		}, true)
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("transaction error = %v", err)
	}
	count, err := harness.adapter.Count(t.Context(), storage.CountParams{Model: "user"})
	if err != nil || count != 0 {
		t.Fatalf("rolled-back count = %d, err=%v", count, err)
	}
}
