package anonymous

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestSignInAnonymousAndRepeatGuard(t *testing.T) {
	harness := newAnonymousHarness(t, nil)
	response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("sign in status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	result := responseObject(t, response)
	user, ok := result["user"].(map[string]any)
	if !ok || user["name"] != "Anonymous" || user["isAnonymous"] != true || user["emailVerified"] != false {
		t.Fatalf("anonymous user = %#v", result["user"])
	}
	email, _ := user["email"].(string)
	if !strings.HasPrefix(email, "temp@") || !strings.HasSuffix(email, ".com") || len(email) != len("temp@")+32+len(".com") {
		t.Fatalf("anonymous email = %q", email)
	}
	token, _ := result["token"].(string)
	if token == "" {
		t.Fatalf("anonymous token = %#v", result["token"])
	}

	cookie := sessionCookie(response)
	second, secondErr := harness.call(t, http.MethodPost, "/sign-in/anonymous", requestHeaders(cookie))
	if secondErr == nil || second.Status() != http.StatusBadRequest ||
		responseErrorCode(t, second) != ErrorAnonymousUsersCannotSignInAgainAnonymously {
		t.Fatalf("second sign in status=%d body=%s err=%v", second.Status(), second.Body(), secondErr)
	}
	if responseObject(t, second)["message"] != errorMessages[ErrorAnonymousUsersCannotSignInAgainAnonymously] {
		t.Fatalf("second sign in body = %s", second.Body())
	}
}

func TestRegularSessionMaySignInAnonymously(t *testing.T) {
	harness := newAnonymousHarness(t, nil)
	harness.seedUser(t, "regular-user", "regular@example.com", false)
	harness.seedSession(t, "regular-user", "regular-token")
	response, err := harness.call(
		t,
		http.MethodPost,
		"/sign-in/anonymous",
		requestHeaders("single-auth.session_token=regular-token"),
	)
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("regular-to-anonymous status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	if user := responseObject(t, response)["user"].(map[string]any); user["isAnonymous"] != true || user["id"] == "regular-user" {
		t.Fatalf("regular-to-anonymous user = %#v", user)
	}
	stored, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "regular-user"}},
	})
	if findErr != nil || stored == nil {
		t.Fatalf("regular user was unexpectedly cleaned up: %#v err=%v", stored, findErr)
	}
}

func TestAnonymousGeneratorsAndValidation(t *testing.T) {
	t.Run("name and custom email", func(t *testing.T) {
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.GenerateName = func(*engine.Context) (string, error) { return "i-am-anonymous", nil }
			options.GenerateRandomEmail = func() (string, error) { return "custom-user@example.com", nil }
		})
		response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		if err != nil {
			t.Fatal(err)
		}
		user := responseObject(t, response)["user"].(map[string]any)
		if user["name"] != "i-am-anonymous" || user["email"] != "custom-user@example.com" {
			t.Fatalf("generated user = %#v", user)
		}
	})

	t.Run("empty generators fall back", func(t *testing.T) {
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.EmailDomainName = "example.test"
			options.GenerateName = func(*engine.Context) (string, error) { return "", nil }
			options.GenerateRandomEmail = func() (string, error) { return "", nil }
		})
		response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		if err != nil {
			t.Fatal(err)
		}
		user := responseObject(t, response)["user"].(map[string]any)
		if user["name"] != "Anonymous" || !strings.HasPrefix(user["email"].(string), "temp-") ||
			!strings.HasSuffix(user["email"].(string), "@example.test") {
			t.Fatalf("fallback user = %#v", user)
		}
	})

	t.Run("emailDomainName is not independently validated", func(t *testing.T) {
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.EmailDomainName = "not a valid domain"
		})
		response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		if err != nil || response.Status() != http.StatusOK {
			t.Fatalf("unvalidated domain status=%d body=%s err=%v", response.Status(), response.Body(), err)
		}
		user := responseObject(t, response)["user"].(map[string]any)
		if !strings.HasSuffix(user["email"].(string), "@not a valid domain") {
			t.Fatalf("unvalidated domain email = %q", user["email"])
		}
	})

	for _, generated := range []string{"not-an-email", ".guest@example.com", "guest@example.c"} {
		t.Run("invalid "+generated, func(t *testing.T) {
			harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
				options.GenerateRandomEmail = func() (string, error) { return generated, nil }
			})
			response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
			if err == nil || response.Status() != http.StatusBadRequest || responseErrorCode(t, response) != ErrorInvalidEmailFormat {
				t.Fatalf("invalid email status=%d body=%s err=%v", response.Status(), response.Body(), err)
			}
		})
	}
}

func TestSignInFailureMappingAndRuntimeErrors(t *testing.T) {
	t.Run("nil user", func(t *testing.T) {
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.Runtime.CreateUser = func(*engine.Context, storage.Record) (storage.Record, error) {
				return nil, nil
			}
		})
		response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		if err == nil || response.Status() != http.StatusInternalServerError || responseErrorCode(t, response) != ErrorFailedToCreateUser {
			t.Fatalf("nil user status=%d body=%s err=%v", response.Status(), response.Body(), err)
		}
	})

	t.Run("nil session", func(t *testing.T) {
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.Runtime.IssueSession = func(*engine.Context, string) (*SessionState, error) { return nil, nil }
		})
		response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		if err == nil || response.Status() != http.StatusBadRequest || responseErrorCode(t, response) != ErrorCouldNotCreateSession {
			t.Fatalf("nil session status=%d body=%s err=%v", response.Status(), response.Body(), err)
		}
	})

	t.Run("thrown runtime error remains unknown", func(t *testing.T) {
		sentinel := errors.New("database is unavailable")
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.Runtime.CreateUser = func(*engine.Context, storage.Record) (storage.Record, error) {
				return nil, sentinel
			}
		})
		response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		if !errors.Is(err, sentinel) || response.Status() != http.StatusInternalServerError || responseErrorCode(t, response) != "INTERNAL_SERVER_ERROR" {
			t.Fatalf("runtime error status=%d body=%s err=%v", response.Status(), response.Body(), err)
		}
	})

	for _, test := range []struct {
		name      string
		configure func(*Options, error)
	}{
		{
			name: "generate name error",
			configure: func(options *Options, sentinel error) {
				options.GenerateName = func(*engine.Context) (string, error) { return "", sentinel }
			},
		},
		{
			name: "generate email error",
			configure: func(options *Options, sentinel error) {
				options.GenerateRandomEmail = func() (string, error) { return "", sentinel }
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sentinel := errors.New(test.name)
			harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
				test.configure(options, sentinel)
			})
			response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
			if !errors.Is(err, sentinel) || response.Status() != http.StatusInternalServerError || responseErrorCode(t, response) != "INTERNAL_SERVER_ERROR" {
				t.Fatalf("callback error status=%d body=%s err=%v", response.Status(), response.Body(), err)
			}
		})
	}
}

func TestDeleteAnonymousUserRevokesSessionsUserAndCookies(t *testing.T) {
	harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
		options.Runtime.ResolveSessionCookies = func(contract.Request) SessionCookies {
			resolved := DefaultSessionCookies()
			account := Cookie{Name: "single-auth.account_data", Attributes: resolved.SessionData.Attributes}
			oauth := Cookie{Name: "single-auth.oauth_state", Attributes: resolved.SessionData.Attributes}
			resolved.AccountData = &account
			resolved.OAuthState = &oauth
			return resolved
		}
	})
	signedIn, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
	if err != nil {
		t.Fatal(err)
	}
	user := responseObject(t, signedIn)["user"].(map[string]any)
	userID := user["id"].(string)
	cookie := sessionCookie(signedIn) + "; single-auth.session_data.0=a; single-auth.session_data.1=b; single-auth.account_data.0=c"
	deleted, deleteErr := harness.call(t, http.MethodPost, "/delete-anonymous-user", requestHeaders(cookie))
	if deleteErr != nil || deleted.Status() != http.StatusOK || responseObject(t, deleted)["success"] != true {
		t.Fatalf("delete status=%d body=%s err=%v", deleted.Status(), deleted.Body(), deleteErr)
	}
	if user, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	}); findErr != nil || user != nil {
		t.Fatalf("deleted user = %#v, err=%v", user, findErr)
	}
	sessions, findErr := harness.adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if findErr != nil || len(sessions) != 0 {
		t.Fatalf("remaining sessions = %#v, err=%v", sessions, findErr)
	}

	parsed := cookies.ParseSetCookieHeader(strings.Join(deleted.Headers().Values("Set-Cookie"), ", "))
	names := make([]string, 0, len(parsed))
	for _, cookie := range parsed {
		names = append(names, cookie.Name)
		if cookie.Attributes.Value != "" || cookie.Attributes.MaxAge == nil || *cookie.Attributes.MaxAge != 0 {
			t.Fatalf("expiry cookie = %#v", cookie)
		}
	}
	wantNames := []string{
		"single-auth.session_token", "single-auth.session_data",
		"single-auth.account_data", "single-auth.account_data.0",
		"single-auth.oauth_state", "single-auth.session_data.0",
		"single-auth.session_data.1", "single-auth.dont_remember",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("expiry order = %#v, want %#v", names, wantNames)
	}
}

func TestDeleteAnonymousUserErrors(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.DisableDeleteAnonymousUser = true
		})
		signedIn, _ := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		response, err := harness.call(t, http.MethodPost, "/delete-anonymous-user", requestHeaders(sessionCookie(signedIn)))
		assertAPIError(t, response, err, http.StatusBadRequest, ErrorDeleteAnonymousUserDisabled)
	})

	t.Run("non anonymous", func(t *testing.T) {
		harness := newAnonymousHarness(t, nil)
		harness.seedUser(t, "regular-user", "regular@example.com", false)
		harness.seedSession(t, "regular-user", "regular-session")
		response, err := harness.call(t, http.MethodPost, "/delete-anonymous-user", requestHeaders("single-auth.session_token=regular-session"))
		assertAPIError(t, response, err, http.StatusForbidden, ErrorUserIsNotAnonymous)
	})

	t.Run("session cleanup failure", func(t *testing.T) {
		sentinel := errors.New("session cleanup failed")
		var logs atomic.Int64
		harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
			options.Runtime.RevokeSessions = func(*engine.Context, string) error { return sentinel }
			options.Runtime.Error = func(message string, _ ...any) {
				if message == "Failed to delete anonymous user sessions" {
					logs.Add(1)
				}
			}
		})
		signedIn, _ := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		response, err := harness.call(t, http.MethodPost, "/delete-anonymous-user", requestHeaders(sessionCookie(signedIn)))
		assertAPIError(t, response, err, http.StatusInternalServerError, ErrorFailedToDeleteAnonymousUserSessions)
		if logs.Load() != 1 {
			t.Fatalf("session failure logs = %d", logs.Load())
		}
	})

	t.Run("user cleanup failure", func(t *testing.T) {
		sentinel := errors.New("user cleanup failed")
		var logs atomic.Int64
		harness := newAnonymousHarness(t, func(options *Options, harness *anonymousHarness) {
			options.Runtime.Adapter = deleteFailingAdapter{Adapter: harness.adapter, err: sentinel}
			options.Runtime.Error = func(message string, _ ...any) {
				if message == "Failed to delete anonymous user" {
					logs.Add(1)
				}
			}
		})
		signedIn, _ := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
		response, err := harness.call(t, http.MethodPost, "/delete-anonymous-user", requestHeaders(sessionCookie(signedIn)))
		assertAPIError(t, response, err, http.StatusInternalServerError, ErrorFailedToDeleteAnonymousUser)
		if logs.Load() != 1 {
			t.Fatalf("user failure logs = %d", logs.Load())
		}
	})

	t.Run("requires authoritative session", func(t *testing.T) {
		harness := newAnonymousHarness(t, nil)
		response, err := harness.call(t, http.MethodPost, "/delete-anonymous-user", contract.NewHeaders())
		assertAPIError(t, response, err, http.StatusUnauthorized, "UNAUTHORIZED")
		harness.resolutionMu.Lock()
		defer harness.resolutionMu.Unlock()
		if !reflect.DeepEqual(harness.resolutions, []SessionResolution{SessionAuthoritative}) {
			t.Fatalf("session resolutions = %#v", harness.resolutions)
		}
	})
}

func assertAPIError(
	t *testing.T,
	response contract.Response,
	err error,
	status int,
	code string,
) {
	t.Helper()
	if err == nil || response.Status() != status || responseErrorCode(t, response) != code {
		t.Fatalf("status=%d body=%s err=%v, want %d %s", response.Status(), response.Body(), err, status, code)
	}
}

func TestSchemaOverridePreservesFrozenFieldContract(t *testing.T) {
	extension := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"isAnonymous": {FieldName: "is_anon"},
		}},
	}}
	resolved, err := resolveSchema(extension)
	if err != nil {
		t.Fatal(err)
	}
	field := resolved.Models["user"].Fields["isAnonymous"]
	if field.FieldName != "is_anon" || field.Type != storage.FieldBoolean || field.IsRequired() || field.IsInput() {
		t.Fatalf("overridden field = %#v", field)
	}
	originalField := extension.Models["user"].Fields["isAnonymous"]
	if originalField.Type != "" || originalField.Required != nil || originalField.Input != nil || originalField.DefaultValue != nil {
		t.Fatalf("resolveSchema mutated caller field = %#v", originalField)
	}
	factory := NewFactory(Options{Schema: extension})
	mutated := extension.Models["user"].Fields["isAnonymous"]
	mutated.FieldName = "changed_after_factory"
	extension.Models["user"].Fields["isAnonymous"] = mutated
	factorySchema, err := factory.Schema()
	factoryField := factorySchema.Models["user"].Fields["isAnonymous"]
	if err != nil || factoryField.FieldName != "is_anon" || factoryField.Type != storage.FieldBoolean ||
		factoryField.IsRequired() || factoryField.IsInput() {
		t.Fatalf("factory schema = %#v, err=%v", factorySchema, err)
	}
}

func TestNewValidationAndMustNew(t *testing.T) {
	base := Options{Runtime: Runtime{}}
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "Runtime.Adapter") {
		t.Fatalf("adapter error = %v", err)
	}
	harness := newAnonymousHarness(t, nil)
	base.Runtime.Adapter = harness.adapter
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "Runtime.ResolveSession") {
		t.Fatalf("resolve-session error = %v", err)
	}
	base.Runtime.ResolveSession = func(*engine.Context, SessionResolution) (*SessionState, error) { return nil, nil }
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "Runtime.IssueSession") {
		t.Fatalf("issue-session error = %v", err)
	}
	base.Runtime.IssueSession = func(*engine.Context, string) (*SessionState, error) {
		return &SessionState{Session: storage.Record{"token": "x"}}, nil
	}
	if descriptor := MustNew(base); descriptor.ID != "anonymous" {
		t.Fatalf("MustNew descriptor = %#v", descriptor)
	}
}

func ExampleNewFactory() {
	_ = NewFactory(Options{
		EmailDomainName: "example.com",
		GenerateName: func(*engine.Context) (string, error) {
			return "Guest", nil
		},
	})
	fmt.Println("anonymous")
	// Output: anonymous
}
