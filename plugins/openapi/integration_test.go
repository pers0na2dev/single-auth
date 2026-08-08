package openapi_test

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
	"github.com/pers0na2dev/single-auth/plugins/openapi"
	"github.com/pers0na2dev/single-auth/plugins/passkey"
	"github.com/pers0na2dev/single-auth/plugins/username"
	"github.com/pers0na2dev/single-auth/storage"
)

func generateDocument(t *testing.T, options singleauth.Options) openapi.Document {
	t.Helper()
	if options.BaseURL == "" {
		options.BaseURL = "http://localhost:3000"
	}
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	if len(options.Schema.Models) != 0 {
		schema, err = schema.Merge(options.Schema)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, plugin := range options.Plugins {
		if len(plugin.Schema.Models) != 0 {
			schema, err = schema.Merge(plugin.Schema)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, factory := range options.PluginFactories {
		extension, schemaErr := factory.Schema()
		if schemaErr != nil {
			t.Fatal(schemaErr)
		}
		if len(extension.Models) != 0 {
			schema, err = schema.Merge(extension)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	generator, err := openapi.NewGenerator(openapi.GeneratorOptions{
		Schema: schema, ListEndpoints: auth.Registry().Endpoints,
		BaseURL: options.BaseURL + "/api/auth", DisabledPaths: options.DisabledPaths,
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := generator.Generate(contract.NewRequest("GET", "/", contract.RequestOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func postSchema(t *testing.T, document openapi.Document, path string) openapi.Schema {
	t.Helper()
	operation := document.Paths[path].Post
	if operation == nil || operation.RequestBody == nil {
		t.Fatalf("%s has no POST body", path)
	}
	media := operation.RequestBody.Content["application/json"]
	if media.Schema == nil {
		t.Fatalf("%s has no JSON schema", path)
	}
	return *media.Schema
}

func TestModelComponentsAndAdditionalUserFieldsMatchFrozenContract(t *testing.T) {
	required, optional := storage.Bool(true), storage.Bool(false)
	document := generateDocument(t, singleauth.Options{Schema: storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"role":        {Type: storage.FieldString, Required: required, DefaultValue: storage.StaticValue("user")},
			"preferences": {Type: storage.FieldString, Required: optional},
		}},
	}}})
	user, session := document.Components.Schemas["User"], document.Components.Schemas["Session"]
	if !user.Properties["id"].ReadOnly || user.Properties["id"].Type != "string" ||
		!session.Properties["id"].ReadOnly || !containsString(user.Required, "id") || !containsString(session.Required, "id") {
		t.Fatalf("user=%#v session=%#v", user, session)
	}
	if user.Properties["emailVerified"].Default != false || !user.Properties["emailVerified"].ReadOnly ||
		user.Properties["role"].Default != "user" || user.Properties["role"].Type != "string" ||
		user.Properties["preferences"].Type != "string" || !containsString(user.Required, "role") || containsString(user.Required, "preferences") {
		t.Fatalf("user schema=%#v", user)
	}
	for _, model := range []string{"User", "Session"} {
		for _, field := range []string{"createdAt", "updatedAt"} {
			if schema, exists := document.Components.Schemas[model].Properties[field]; exists && schema.Default != nil {
				t.Fatalf("%s.%s runtime default leaked: %#v", model, field, schema.Default)
			}
		}
	}
}

func TestAdditionalUserFieldsMergeIntoSignUpAndUpdateBodies(t *testing.T) {
	required, optional := storage.Bool(true), storage.Bool(false)
	document := generateDocument(t, singleauth.Options{Schema: storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"nickname":     {Type: storage.FieldString, Required: required},
			"optionalNote": {Type: storage.FieldString, Required: optional},
			"role":         {Type: storage.FieldString, Required: required, DefaultValue: storage.StaticValue("user")},
		}},
	}}})
	signUp, update := postSchema(t, document, "/sign-up/email"), postSchema(t, document, "/update-user")
	for _, schema := range []openapi.Schema{signUp, update} {
		for _, field := range []string{"nickname", "optionalNote", "role"} {
			if schema.Properties[field].Type != "string" {
				t.Fatalf("field %s missing from %#v", field, schema)
			}
		}
	}
	if !containsString(signUp.Required, "nickname") || containsString(signUp.Required, "optionalNote") ||
		containsString(signUp.Required, "role") || containsString(update.Required, "nickname") {
		t.Fatalf("sign-up required=%v update required=%v", signUp.Required, update.Required)
	}
}

func TestUsernamePluginFieldsMergeIntoUserInputBodies(t *testing.T) {
	document := generateDocument(t, singleauth.Options{
		PluginFactories: []singleauth.PluginFactory{username.NewFactory(username.Options{})},
	})
	for _, path := range []string{"/sign-up/email", "/update-user"} {
		schema := postSchema(t, document, path)
		if schema.Properties["username"].Type != "string" || schema.Properties["displayUsername"].Type != "string" ||
			containsString(schema.Required, "username") || containsString(schema.Required, "displayUsername") {
			t.Fatalf("%s schema=%#v", path, schema)
		}
	}
}

func TestCoreNestedOptionalNullableOperationAndPathSemantics(t *testing.T) {
	document := generateDocument(t, singleauth.Options{})
	social := document.Paths["/sign-in/social"].Post
	schema := postSchema(t, document, "/sign-in/social")
	idToken := schema.Properties["idToken"]
	if idToken.Type != "object" || len(idToken.AnyOf) != 0 || idToken.Nullable != nil ||
		idToken.Properties["token"].Type != "string" || idToken.Properties["accessToken"].Type != "string" ||
		idToken.Properties["refreshToken"].Type != "string" || !containsString(idToken.Required, "token") ||
		containsString(idToken.Required, "accessToken") || containsString(idToken.Required, "refreshToken") ||
		containsString(schema.Required, "idToken") {
		t.Fatalf("social request=%#v", schema)
	}
	response := social.Responses["200"].Content["application/json"].Schema
	if response == nil || !reflect.DeepEqual(response.Required, []string{"redirect"}) ||
		response.Properties["redirect"].Type != "boolean" || len(response.Properties["redirect"].Enum) != 0 ||
		response.Properties["token"].Type == nil || response.Properties["user"].Type == nil || response.Properties["url"].Type == nil {
		t.Fatalf("social response=%#v", response)
	}
	getSession := document.Paths["/get-session"]
	if getSession.Get.OperationID != "getSession" || getSession.Post.OperationID != "getSessionPost" {
		t.Fatalf("get-session=%#v", getSession)
	}
	nullable := getSession.Post.Responses["200"].Content["application/json"].Schema
	if nullable == nil || !reflect.DeepEqual(nullable.Type, []any{"object", "null"}) && !reflect.DeepEqual(nullable.Type, []string{"object", "null"}) || nullable.Nullable != nil {
		t.Fatalf("get-session schema=%#v", nullable)
	}
	for _, operation := range []*openapi.Operation{document.Paths["/callback/{id}"].Get, document.Paths["/callback/{id}"].Post} {
		if operation == nil || len(operation.Parameters) != 1 || operation.Parameters[0].Name != "id" || operation.Parameters[0].In != "path" || operation.Parameters[0].Required == nil || !*operation.Parameters[0].Required {
			t.Fatalf("callback operation=%#v", operation)
		}
	}
	seen := map[string]struct{}{}
	for _, item := range document.Paths {
		for _, operation := range []*openapi.Operation{item.Get, item.Post, item.Put, item.Patch, item.Delete} {
			if operation == nil || operation.OperationID == "" {
				continue
			}
			if _, duplicate := seen[operation.OperationID]; duplicate {
				t.Fatalf("duplicate operationId %s", operation.OperationID)
			}
			seen[operation.OperationID] = struct{}{}
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil || strings.Contains(string(encoded), "[Circular ref") {
		t.Fatalf("marshal err=%v", err)
	}
}

func TestDefaultBooleanRequestFieldsKeepTheirInnerType(t *testing.T) {
	document := generateDocument(t, singleauth.Options{})
	for _, path := range []string{"/sign-in/email", "/sign-up/email"} {
		field := postSchema(t, document, path).Properties["rememberMe"]
		if field.Type != "boolean" || field.Default != nil {
			t.Fatalf("%s rememberMe=%#v", path, field)
		}
	}
}

func TestEmailOTPPostBodiesAndIntersectionSemantics(t *testing.T) {
	factory := emailotp.NewFactory(emailotp.Options{
		SendVerificationOTP: func(context.Context, emailotp.OTPMessage, *engine.Context) error { return nil },
	})
	document := generateDocument(t, singleauth.Options{PluginFactories: []singleauth.PluginFactory{factory}})
	paths := []string{
		"/email-otp/send-verification-otp", "/email-otp/check-verification-otp",
		"/email-otp/verify-email", "/sign-in/email-otp",
		"/email-otp/request-password-reset", "/forget-password/email-otp",
		"/email-otp/reset-password", "/email-otp/request-email-change", "/email-otp/change-email",
	}
	for _, path := range paths {
		if document.Paths[path].Post == nil || document.Paths[path].Post.RequestBody == nil {
			t.Fatalf("missing body for %s", path)
		}
	}
	signInOperation := document.Paths["/sign-in/email-otp"].Post
	signIn := postSchema(t, document, "/sign-in/email-otp")
	if signInOperation.RequestBody.Required == nil || !*signInOperation.RequestBody.Required || signIn.Type != "object" ||
		!reflect.DeepEqual(signIn.Required, []string{"email", "otp"}) || signIn.Properties["email"].Type != "string" ||
		signIn.Properties["otp"].Type != "string" || signIn.Properties["name"].Type != "string" || signIn.Properties["image"].Type != "string" {
		t.Fatalf("email OTP sign-in=%#v", signIn)
	}
	encoded, _ := json.Marshal(signIn.AdditionalProperties)
	if string(encoded) != "{}" {
		t.Fatalf("additionalProperties=%s", encoded)
	}
	reset := postSchema(t, document, "/email-otp/reset-password")
	if !reflect.DeepEqual(reset.Required, []string{"email", "otp", "password"}) || reset.AdditionalProperties != nil {
		t.Fatalf("reset schema=%#v", reset)
	}
}

func TestPasskeyQueryParametersRemainAtOperationLevel(t *testing.T) {
	document := generateDocument(t, singleauth.Options{
		PluginFactories: []singleauth.PluginFactory{passkey.NewFactory(passkey.Options{})},
	})
	operation := document.Paths["/passkey/generate-register-options"].Get
	if operation == nil {
		t.Fatal("missing passkey operation")
	}
	names := make([]string, 0, len(operation.Parameters))
	for _, parameter := range operation.Parameters {
		if parameter.In != "query" || parameter.Required == nil || *parameter.Required {
			t.Fatalf("parameter=%#v", parameter)
		}
		names = append(names, parameter.Name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"authenticatorAttachment", "context", "name"}) {
		t.Fatalf("parameters=%v", names)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
