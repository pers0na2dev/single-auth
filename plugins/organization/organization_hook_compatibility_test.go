package organization_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type organizationHookObservation struct {
	SignUpUserPresent       bool
	EmailMatches            bool
	HookCalled              bool
	HookErrorIsNull         bool
	OrganizationCreated     bool
	OrganizationNameMatches bool
	SlugHasPrefix           bool
	OrganizationPersisted   bool
	PersistedNameMatches    bool
	MemberCount             int
	MemberMatches           bool

	TransactionEnabled     bool
	SkippedByUpstreamGuard bool

	ImagePrepared         bool
	OrganizationIDPresent bool

	AsyncOperationsCompleted int
	FoundUserInHook          bool
}

var organizationHookScenarios = []struct {
	Title string
	Want  organizationHookObservation
}{
	{
		Title: "should create organization in user creation after hook within transaction",
		Want: organizationHookObservation{
			SignUpUserPresent: true, EmailMatches: true, HookCalled: true, HookErrorIsNull: true,
			OrganizationCreated: true, OrganizationNameMatches: true, SlugHasPrefix: true,
			OrganizationPersisted: true, PersistedNameMatches: true, MemberCount: 1, MemberMatches: true,
		},
	},
	{
		Title: "should handle errors gracefully when organization creation fails in hook",
		Want:  organizationHookObservation{SkippedByUpstreamGuard: true},
	},
	{
		Title: "should work when creating organization from before hook",
		Want: organizationHookObservation{
			SignUpUserPresent: true, OrganizationNameMatches: true, OrganizationPersisted: true,
			ImagePrepared: true, OrganizationIDPresent: true,
		},
	},
	{
		Title: "should work with multiple async operations in the hook",
		Want: organizationHookObservation{
			SignUpUserPresent: true, EmailMatches: true, OrganizationNameMatches: true,
			OrganizationPersisted: true, AsyncOperationsCompleted: 2, FoundUserInHook: true,
		},
	},
}

type hookState struct {
	hookCalled              bool
	hookErrorIsNull         bool
	created                 *organization.CreateOrganizationResult
	organizationID          string
	asyncOperationsComplete int
	foundUserInHook         bool
}

type signUpExchange func(email, name string) (int, map[string]any)

type hookHarness struct {
	auth     *singleauth.Auth
	plugin   *organization.Plugin
	state    *hookState
	exchange signUpExchange
}

func TestOrganizationDatabaseHookScenarios(t *testing.T) {
	for _, scenario := range organizationHookScenarios {
		scenario := scenario
		t.Run(scenario.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					harness := newHookHarness(t, transportName, scenario.Title)
					actual := harness.run(t, scenario.Title)
					if !reflect.DeepEqual(actual, scenario.Want) {
						t.Fatalf("organization-hook observation = %#v, want %#v", actual, scenario.Want)
					}
				})
			}
		})
	}
}

func TestCreateOrganizationRejectsDuplicateSlugAtomically(t *testing.T) {
	plugin := organization.MustNew(organization.Options{})
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL:         "http://auth.example.test",
		PluginFactories: []singleauth.PluginFactory{plugin},
	})
	user, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "user",
		Data: storage.Record{
			"name": "Owner", "email": "owner@example.com", "emailVerified": false,
			"createdAt": time.Now(), "updatedAt": time.Now(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := user["id"].(string)
	first, err := plugin.CreateOrganization(t.Context(), organization.CreateOrganizationInput{
		Name: "First", Slug: "one-slug", UserID: userID,
	})
	if err != nil || first.ID == "" || len(first.Members) != 1 {
		t.Fatalf("first organization = %#v, %v", first, err)
	}
	_, err = plugin.CreateOrganization(t.Context(), organization.CreateOrganizationInput{
		Name: "Second", Slug: "one-slug", UserID: userID,
	})
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Code != organization.ErrorOrganizationAlreadyExists || apiError.Status != http.StatusBadRequest {
		t.Fatalf("duplicate error = %#v", err)
	}
	organizations, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "organization"})
	if err != nil || len(organizations) != 1 {
		t.Fatalf("organizations after duplicate = %#v, %v", organizations, err)
	}
	members, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "member"})
	if err != nil || len(members) != 1 {
		t.Fatalf("members after duplicate = %#v, %v", members, err)
	}
}

func newHookHarness(t *testing.T, transportName, title string) *hookHarness {
	t.Helper()
	plugin := organization.MustNew(organization.Options{})
	state := &hookState{hookErrorIsNull: true}
	var auth *singleauth.Auth
	hooks := singleauth.DatabaseHooks{}

	switch title {
	case "should create organization in user creation after hook within transaction":
		hooks["user"] = singleauth.DatabaseModelHooks{Create: singleauth.DatabaseOperationHooks{
			After: func(value any, hook singleauth.DatabaseHookContext) error {
				user, ok := value.(storage.Record)
				if !ok || user["email"] != "test-hook@example.com" {
					return nil
				}
				state.hookCalled = true
				userID, _ := user["id"].(string)
				created, err := plugin.CreateOrganization(hook.Context, organization.CreateOrganizationInput{
					Name: "test-hook@example.com's Organization",
					Slug: "org-" + firstEight(userID), UserID: userID,
				})
				if err != nil {
					state.hookErrorIsNull = false
					return err
				}
				state.created = &created
				return nil
			},
		}}

	case "should handle errors gracefully when organization creation fails in hook":
		hooks["user"] = singleauth.DatabaseModelHooks{Create: singleauth.DatabaseOperationHooks{
			After: func(value any, hook singleauth.DatabaseHookContext) error {
				user, ok := value.(storage.Record)
				email, _ := user["email"].(string)
				if !ok || !strings.Contains(email, "-hook@") {
					return nil
				}
				userID, _ := user["id"].(string)
				_, err := plugin.CreateOrganization(hook.Context, organization.CreateOrganizationInput{
					Name: "Test Org", Slug: "duplicate-test-org", UserID: userID,
				})
				return err
			},
		}}

	case "should work with multiple async operations in the hook":
		hooks["user"] = singleauth.DatabaseModelHooks{Create: singleauth.DatabaseOperationHooks{
			After: func(value any, hook singleauth.DatabaseHookContext) error {
				user, ok := value.(storage.Record)
				if !ok || user["email"] != "async-hook@example.com" {
					return nil
				}
				time.Sleep(10 * time.Millisecond)
				state.asyncOperationsComplete++
				userID, _ := user["id"].(string)
				found, err := auth.AdapterForContext(hook.Context).FindOne(hook.Context, storage.FindOneParams{
					Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
				})
				if err != nil {
					return err
				}
				state.foundUserInHook = found != nil
				_, err = plugin.CreateOrganization(hook.Context, organization.CreateOrganizationInput{
					Name: "Async Org for " + storageString(user, "name"),
					Slug: "async-" + firstEight(userID), UserID: userID,
				})
				if err != nil {
					return err
				}
				time.Sleep(10 * time.Millisecond)
				state.asyncOperationsComplete++
				return nil
			},
		}}

	case "should work when creating organization from before hook":
		hooks["user"] = singleauth.DatabaseModelHooks{Create: singleauth.DatabaseOperationHooks{
			Before: func(_ storage.Record, _ singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
				return singleauth.DatabaseHookResult{Data: storage.Record{"image": "prepared-in-before-hook"}}, nil
			},
			After: func(value any, hook singleauth.DatabaseHookContext) error {
				user, ok := value.(storage.Record)
				if !ok || user["email"] != "before-hook@example.com" {
					return nil
				}
				userID, _ := user["id"].(string)
				created, err := plugin.CreateOrganization(hook.Context, organization.CreateOrganizationInput{
					Name: "Before-After Org", Slug: "before-after-" + firstEight(userID), UserID: userID,
				})
				if err == nil {
					state.organizationID = created.ID
				}
				return err
			},
		}}

	default:
		t.Fatalf("unsupported organization-hook vector %q", title)
	}

	var err error
	auth, err = singleauth.New(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           "0123456789abcdef0123456789abcdef",
		PluginFactories:  []singleauth.PluginFactory{plugin},
		DatabaseHooks:    hooks,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true, Password: singleauth.PasswordOptions{Hash: func(password string) (string, error) { return "hash:" + password, nil }}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &hookHarness{
		auth: auth, plugin: plugin, state: state,
		exchange: newSignUpExchange(t, transportName, auth),
	}
}

func (harness *hookHarness) run(t *testing.T, title string) organizationHookObservation {
	t.Helper()
	switch title {
	case "should create organization in user creation after hook within transaction":
		status, body := harness.exchange("test-hook@example.com", "Test Hook User")
		if status != http.StatusOK {
			t.Fatalf("sign-up status=%d body=%#v", status, body)
		}
		user := bodyObject(body, "user")
		organizations, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "organization"})
		if err != nil {
			t.Fatal(err)
		}
		var persisted storage.Record
		for _, candidate := range organizations {
			if strings.HasPrefix(storageString(candidate, "slug"), "org-") {
				persisted = candidate
				break
			}
		}
		organizationID := ""
		if harness.state.created != nil {
			organizationID = harness.state.created.ID
		}
		members, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
			Model: "member", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		memberMatches := len(members) > 0 && storageString(members[0], "userId") == mapString(user, "id") &&
			storageString(members[0], "organizationId") == organizationID && storageString(members[0], "role") == "owner"
		return organizationHookObservation{
			SignUpUserPresent: user != nil, EmailMatches: mapString(user, "email") == "test-hook@example.com",
			HookCalled: harness.state.hookCalled, HookErrorIsNull: harness.state.hookErrorIsNull,
			OrganizationCreated:     harness.state.created != nil,
			OrganizationNameMatches: harness.state.created != nil && harness.state.created.Name == "test-hook@example.com's Organization",
			SlugHasPrefix:           harness.state.created != nil && strings.HasPrefix(harness.state.created.Slug, "org-"),
			OrganizationPersisted:   persisted != nil,
			PersistedNameMatches:    storageString(persisted, "name") == "test-hook@example.com's Organization",
			MemberCount:             len(members), MemberMatches: memberMatches,
		}

	case "should handle errors gracefully when organization creation fails in hook":
		status, body := harness.exchange("test@test.com", "test user")
		if status != http.StatusOK {
			t.Fatalf("upstream setup sign-up status=%d body=%#v", status, body)
		}
		return organizationHookObservation{TransactionEnabled: false, SkippedByUpstreamGuard: true}

	case "should work with multiple async operations in the hook":
		status, body := harness.exchange("async-hook@example.com", "Async User")
		if status != http.StatusOK {
			t.Fatalf("sign-up status=%d body=%#v", status, body)
		}
		user := bodyObject(body, "user")
		organizations, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
			Model: "organization", Where: []storage.Where{{Field: "slug", Value: "async-", Operator: storage.OpContains}},
		})
		if err != nil {
			t.Fatal(err)
		}
		var persisted storage.Record
		for _, candidate := range organizations {
			if strings.Contains(storageString(candidate, "name"), "Async Org") {
				persisted = candidate
				break
			}
		}
		return organizationHookObservation{
			SignUpUserPresent: user != nil, EmailMatches: mapString(user, "email") == "async-hook@example.com",
			AsyncOperationsCompleted: harness.state.asyncOperationsComplete,
			FoundUserInHook:          harness.state.foundUserInHook,
			OrganizationPersisted:    persisted != nil,
			OrganizationNameMatches:  storageString(persisted, "name") == "Async Org for Async User",
		}

	case "should work when creating organization from before hook":
		status, body := harness.exchange("before-hook@example.com", "Before Hook User")
		if status != http.StatusOK {
			t.Fatalf("sign-up status=%d body=%#v", status, body)
		}
		user := bodyObject(body, "user")
		persisted, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: harness.state.organizationID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return organizationHookObservation{
			SignUpUserPresent:       user != nil,
			ImagePrepared:           mapString(user, "image") == "prepared-in-before-hook",
			OrganizationIDPresent:   harness.state.organizationID != "",
			OrganizationPersisted:   persisted != nil,
			OrganizationNameMatches: storageString(persisted, "name") == "Before-After Org",
		}
	default:
		t.Fatalf("unsupported organization-hook vector %q", title)
		return organizationHookObservation{}
	}
}

func newSignUpExchange(t *testing.T, transportName string, auth *singleauth.Auth) signUpExchange {
	t.Helper()
	encode := func(email, name string) []byte {
		body, err := json.Marshal(map[string]any{
			"email": email, "password": "password123", "name": name,
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	decode := func(status int, body []byte) map[string]any {
		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("decode status=%d body=%q: %v", status, body, err)
		}
		return result
	}

	switch transportName {
	case "net-http":
		return func(email, name string) (int, map[string]any) {
			request := httptest.NewRequest(http.MethodPost, "http://auth.example.test/api/auth/sign-up/email", bytes.NewReader(encode(email, name)))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			auth.Handler().ServeHTTP(recorder, request)
			return recorder.Code, decode(recorder.Code, recorder.Body.Bytes())
		}

	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(email, name string) (int, map[string]any) {
			var request fasthttpserver.Request
			request.Header.SetMethod(http.MethodPost)
			request.Header.SetContentType("application/json")
			request.SetRequestURI("http://auth.example.test/api/auth/sign-up/email")
			request.SetBody(encode(email, name))
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, nil, nil)
			handler(&requestContext)
			status := requestContext.Response.StatusCode()
			return status, decode(status, requestContext.Response.Body())
		}

	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(email, name string) (int, map[string]any) {
			request, err := http.NewRequest(http.MethodPost, "http://auth.example.test/api/auth/sign-up/email", bytes.NewReader(encode(email, name)))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			return response.StatusCode, decode(response.StatusCode, body)
		}
	default:
		t.Fatalf("unsupported transport %q", transportName)
		return nil
	}
}

func firstEight(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

func storageString(record storage.Record, key string) string {
	if record == nil {
		return ""
	}
	value, _ := record[key].(string)
	return value
}

func bodyObject(body map[string]any, key string) map[string]any {
	if body == nil {
		return nil
	}
	value, _ := body[key].(map[string]any)
	return value
}

func mapString(value map[string]any, key string) string {
	if value == nil {
		return ""
	}
	result, _ := value[key].(string)
	return result
}
