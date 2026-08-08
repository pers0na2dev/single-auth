package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type scimPatchErrorResult struct {
	Status   int      `json:"status"`
	Code     *string  `json:"code"`
	Message  *string  `json:"message"`
	Detail   *string  `json:"detail"`
	Schemas  []string `json:"schemas"`
	SCIMType *string  `json:"scimType"`
}

type scimPatchResourceResult struct {
	Active        bool    `json:"active"`
	DisplayName   string  `json:"displayName"`
	EmailPrimary  bool    `json:"emailPrimary"`
	EmailValue    string  `json:"emailValue"`
	ExternalID    *string `json:"externalId"`
	NameFormatted string  `json:"nameFormatted"`
	UserName      string  `json:"userName"`
}

type scimPatchResult struct {
	Status   int                      `json:"status"`
	Error    *scimPatchErrorResult    `json:"error"`
	Resource *scimPatchResourceResult `json:"resource"`
}

func TestSCIMPatchBehaviorAcrossTransports(t *testing.T) {
	if len(scimPatchExpectedCases) != 19 {
		t.Fatalf("SCIM PATCH scenario count=%d, want 19", len(scimPatchExpectedCases))
	}
	seenModes := make(map[string]struct{}, len(scimPatchExpectedCases))
	for _, testCase := range scimPatchExpectedCases {
		testCase := testCase
		if _, exists := seenModes[testCase.Mode]; exists {
			t.Fatalf("duplicate SCIM PATCH mode %q", testCase.Mode)
		}
		seenModes[testCase.Mode] = struct{}{}
		t.Run(testCase.Name, func(t *testing.T) {
			for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					actual := observeSCIMPatch(t, testCase.Mode, transport)
					if !reflect.DeepEqual(actual, testCase.Want) {
						want, _ := json.MarshalIndent(testCase.Want, "", "  ")
						got, _ := json.MarshalIndent(actual, "", "  ")
						t.Fatalf("SCIM PATCH result differs\ngot=%s\nwant=%s", got, want)
					}
				})
			}
		})
	}
}

func TestSCIMPatchDescriptorAndSchema(t *testing.T) {
	plugin := MustNew(Options{Runtime: Runtime{
		AdapterForContext: func(context.Context) storage.TransactionAdapter {
			return nil
		},
	}})
	if plugin.ID != "scim" || plugin.Version != Version || len(plugin.Endpoints) != 10 {
		t.Fatalf("SCIM plugin descriptor=%#v", plugin)
	}
	var endpoint engine.Endpoint
	for _, candidate := range plugin.Endpoints {
		if candidate.Name == EndpointPatchSCIMUser {
			endpoint = candidate
			break
		}
	}
	if endpoint.Name != EndpointPatchSCIMUser ||
		endpoint.Path != "/scim/v2/Users/:userId" ||
		!reflect.DeepEqual(endpoint.Methods, []string{http.MethodPatch}) ||
		len(endpoint.Use) != 1 || endpoint.Handler == nil {
		t.Fatalf("SCIM PATCH endpoint=%#v", endpoint)
	}
	schema := Schema(Options{})
	provider, ok := schema.Models["scimProvider"]
	if !ok || len(provider.Fields) != 3 || !provider.Fields["providerId"].Unique ||
		!provider.Fields["scimToken"].Unique {
		t.Fatalf("SCIM provider schema=%#v", schema)
	}
}

type scimPatchCreate struct {
	UserName      string
	NameFormatted string
	PrimaryEmail  string
}

type scimPatchScenario struct {
	Create     *scimPatchCreate
	Operations []Operation
	UserID     string
	Anonymous  bool
}

func scimPatchScenarioForMode(t *testing.T, mode string) scimPatchScenario {
	t.Helper()
	operationScenarios := func(operation string) map[string]scimPatchScenario {
		return map[string]scimPatchScenario{
			"partial-" + operation: {
				Create: &scimPatchCreate{
					UserName: "the-username", NameFormatted: "Juan Perez",
					PrimaryEmail: "primary-email@test.com",
				},
				Operations: []Operation{
					{Op: operation, Path: "/externalId", Value: "external-username"},
					{Op: operation, Path: "/userName", Value: "other-username"},
					{Op: operation, Path: "/name/givenName", Value: "Daniel"},
				},
			},
			"name-" + operation: {
				Create: &scimPatchCreate{UserName: "sub-attribute-test-user", NameFormatted: "Original Name"},
				Operations: []Operation{
					{Op: operation, Path: "/name/givenName", Value: "Updated"},
					{Op: operation, Path: "/name/familyName", Value: "Value"},
				},
			},
			"nested-" + operation: {
				Create: &scimPatchCreate{UserName: "nested-test-user", NameFormatted: "Original Name"},
				Operations: []Operation{
					{Op: operation, Path: "name", Value: map[string]any{"givenName": "Nested"}},
					{Op: operation, Path: "name", Value: map[string]any{"familyName": "User"}},
					{Op: operation, Path: "userName", Value: "nested-test-user-updated"},
				},
			},
			"no-path-" + operation: {
				Create: &scimPatchCreate{UserName: "no-path-test-user"},
				Operations: []Operation{{
					Op: operation,
					Value: map[string]any{
						"name":     map[string]any{"formatted": "No Path Name"},
						"userName": "Username",
					},
				}},
			},
			"case-" + operation: {
				Create: &scimPatchCreate{UserName: "user-case-insensitive", NameFormatted: "Original"},
				Operations: []Operation{{
					Op: stringsUpper(operation), Path: "name.formatted", Value: "user-case",
				}},
			},
		}
	}
	for _, operation := range []string{"replace", "add"} {
		if scenario, ok := operationScenarios(operation)[mode]; ok {
			return scenario
		}
	}
	switch mode {
	case "mixed":
		return scimPatchScenario{
			Create: &scimPatchCreate{
				UserName: "the-username", NameFormatted: "Juan Perez",
				PrimaryEmail: "primary-email@test.com",
			},
			Operations: []Operation{
				{Op: "add", Path: "/externalId", Value: "external-username"},
				{Op: "replace", Path: "/userName", Value: "other-username"},
				{Op: "add", Path: "/name/formatted", Value: "Daniel Lopez"},
			},
		}
	case "dot-path":
		return scimPatchScenario{
			Create: &scimPatchCreate{UserName: "dot-notation-user", NameFormatted: "Original Name"},
			Operations: []Operation{
				{Op: "replace", Path: "name.familyName", Value: "Dot"},
				{Op: "add", Path: "name.givenName", Value: "User"},
				{Op: "add", Path: "userName", Value: "Username"},
			},
		}
	case "add-existing":
		return scimPatchScenario{
			Create:     &scimPatchCreate{UserName: "add-same-info-user", NameFormatted: "Existing Name"},
			Operations: []Operation{{Op: "add", Path: "/name/formatted", Value: "Existing Name"}},
		}
	case "unknown-path-replace", "unknown-path-add":
		op := "replace"
		if mode == "unknown-path-add" {
			op = "add"
		}
		return scimPatchScenario{
			Create:     &scimPatchCreate{UserName: "non-existing-path", NameFormatted: "Original Name"},
			Operations: []Operation{{Op: op, Path: "/nonExistentField", Value: "Some Value"}},
		}
	case "unknown-operation":
		return scimPatchScenario{
			Create:     &scimPatchCreate{UserName: "non-existing-operation"},
			Operations: []Operation{{Op: "update", Path: "userName", Value: "Some Value"}},
		}
	case "missing-user":
		return scimPatchScenario{
			UserID:     "missing",
			Operations: []Operation{{Op: "replace", Path: "/externalId", Value: "external-username"}},
		}
	case "empty-operations":
		return scimPatchScenario{Create: &scimPatchCreate{UserName: "the-username"}, Operations: []Operation{}}
	case "anonymous":
		return scimPatchScenario{
			UserID: "missing", Anonymous: true,
			Operations: []Operation{{Op: "replace", Path: "/externalId", Value: "external-username"}},
		}
	default:
		t.Fatalf("unknown SCIM PATCH mode %q", mode)
		return scimPatchScenario{}
	}
}

func observeSCIMPatch(t *testing.T, mode string, transport string) scimPatchResult {
	t.Helper()
	scenario := scimPatchScenarioForMode(t, mode)
	fixedNow := time.Date(2026, time.August, 9, 16, 0, 0, 0, time.UTC)
	rateLimitEnabled := false
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:         "http://localhost:3000",
		Secret:          "0123456789abcdef0123456789abcdef",
		Clock:           func() time.Time { return fixedNow },
		RateLimit:       singleauth.RateLimitOptions{Enabled: &rateLimitEnabled},
		Logger:          logger.Options{Disabled: true},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := auth.Adapter()
	const (
		providerID = "the-saml-provider-1"
		secret     = "scim-patch-secret"
	)
	if _, err = adapter.Create(t.Context(), storage.CreateParams{
		Model: "scimProvider", ForceAllowID: true,
		Data: storage.Record{
			"id": "scim-provider-1", "providerId": providerID, "scimToken": secret,
		},
	}); err != nil {
		t.Fatal(err)
	}
	userID := scenario.UserID
	if scenario.Create != nil {
		userID = "scim-user-1"
		email := scenario.Create.UserName
		if scenario.Create.PrimaryEmail != "" {
			email = scenario.Create.PrimaryEmail
		}
		name := scenario.Create.NameFormatted
		if name == "" {
			name = email
		}
		if _, err = adapter.Create(t.Context(), storage.CreateParams{
			Model: "user", ForceAllowID: true,
			Data: storage.Record{
				"id": userID, "email": email, "name": name, "emailVerified": false,
				"createdAt": fixedNow, "updatedAt": fixedNow,
			},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err = adapter.Create(t.Context(), storage.CreateParams{
			Model: "account", ForceAllowID: true,
			Data: storage.Record{
				"id": "scim-account-1", "userId": userID,
				"providerId": providerID, "accountId": scenario.Create.UserName,
				"createdAt": fixedNow, "updatedAt": fixedNow,
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(PatchRequest{
		Schemas: []string{PatchOpSchema}, Operations: scenario.Operations,
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	if !scenario.Anonymous {
		headers.Set("Authorization", "Bearer "+EncodeBearerToken(secret, providerID, ""))
	}
	status, responseBody := exchangeSCIMPatch(
		t,
		transport,
		auth,
		"/api/auth/scim/v2/Users/"+userID,
		headers,
		body,
	)
	observation := scimPatchResult{Status: status}
	if status >= 400 {
		var body struct {
			Code     *string  `json:"code"`
			Message  *string  `json:"message"`
			Detail   *string  `json:"detail"`
			Schemas  []string `json:"schemas"`
			SCIMType *string  `json:"scimType"`
		}
		if err := json.Unmarshal(responseBody, &body); err != nil {
			t.Fatalf("decode SCIM PATCH error body %q: %v", responseBody, err)
		}
		if body.Schemas == nil {
			body.Schemas = []string{}
		}
		observation.Error = &scimPatchErrorResult{
			Status: status, Code: body.Code, Message: body.Message,
			Detail: body.Detail, Schemas: body.Schemas, SCIMType: body.SCIMType,
		}
		return observation
	}
	if status != http.StatusNoContent || len(responseBody) != 0 {
		t.Fatalf("SCIM PATCH success status/body=%d/%q", status, responseBody)
	}
	user, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil || user == nil {
		t.Fatalf("load updated SCIM user: row=%#v err=%v", user, err)
	}
	account, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}, {Field: "providerId", Value: providerID}},
	})
	if err != nil || account == nil {
		t.Fatalf("load updated SCIM account: row=%#v err=%v", account, err)
	}
	email := recordString(user, "email")
	name := recordString(user, "name")
	externalID := recordString(account, "accountId")
	active := true
	if banned, ok := user["banned"].(bool); ok {
		active = !banned
	}
	observation.Resource = &scimPatchResourceResult{
		Active: active, DisplayName: name, EmailPrimary: true, EmailValue: email,
		ExternalID: &externalID, NameFormatted: name, UserName: email,
	}
	return observation
}

func exchangeSCIMPatch(
	t *testing.T,
	transport string,
	auth *singleauth.Auth,
	target string,
	headers http.Header,
	body []byte,
) (int, []byte) {
	t.Helper()
	switch transport {
	case "net/http":
		request := httptest.NewRequest(
			http.MethodPatch,
			"http://localhost:3000"+target,
			bytes.NewReader(body),
		)
		request.Header = headers.Clone()
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		return recorder.Code, append([]byte(nil), recorder.Body.Bytes()...)
	case "fasthttp":
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPatch)
		request.Header.SetHost("localhost:3000")
		request.SetRequestURI(target)
		request.SetBody(body)
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(
			&request,
			&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
			nil,
		)
		fasthttptransport.NewHandler(auth.Dispatcher())(&requestContext)
		return requestContext.Response.StatusCode(), append([]byte(nil), requestContext.Response.Body()...)
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(
			http.MethodPatch,
			"http://localhost:3000"+target,
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header = headers.Clone()
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, responseBody
	default:
		t.Fatalf("unsupported SCIM transport %q", transport)
		return 0, nil
	}
}

func stringsUpper(value string) string {
	result := make([]byte, len(value))
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' {
			character -= 'a' - 'A'
		}
		result[index] = character
	}
	return string(result)
}

func TestSCIMPatchPublicOperationsAreRaceSafe(t *testing.T) {
	user := storage.Record{"email": "race@example.com", "name": "Race User"}
	operations := []Operation{
		{Op: "replace", Path: "/name/givenName", Value: "Safe"},
		{Op: "replace", Path: "/userName", Value: "SAFE@EXAMPLE.COM"},
	}
	const workers = 32
	errorsChannel := make(chan error, workers)
	for index := 0; index < workers; index++ {
		go func() {
			resources, err := BuildUserPatch(user, operations)
			if err == nil && (resources.User["name"] != "Safe User" || resources.User["email"] != "safe@example.com") {
				err = fmt.Errorf("unexpected resources %#v", resources)
			}
			errorsChannel <- err
		}()
	}
	for index := 0; index < workers; index++ {
		if err := <-errorsChannel; err != nil {
			t.Fatal(err)
		}
	}
}
