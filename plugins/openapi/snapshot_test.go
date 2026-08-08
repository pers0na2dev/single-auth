package openapi_test

import (
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/openapi"
)

func TestGeneratedCoreDocumentContract(t *testing.T) {
	document := generateDocument(t, singleauth.Options{})
	if document.OpenAPI != "3.1.1" || document.Info.Title != "single-auth" ||
		document.Info.Version != "1.1.0" {
		t.Fatalf("document metadata = %#v", document)
	}
	if len(document.Paths) != 30 || countOpenAPIOperations(document) != 32 {
		t.Fatalf("document inventory: paths=%d operations=%d", len(document.Paths), countOpenAPIOperations(document))
	}
	if len(document.Components.Schemas) != 4 {
		t.Fatalf("component schemas=%d, want 4", len(document.Components.Schemas))
	}
	for _, name := range []string{"Account", "Session", "User", "Verification"} {
		if _, exists := document.Components.Schemas[name]; !exists {
			t.Errorf("component schema %q is missing", name)
		}
	}
	if len(document.Components.SecuritySchemes) != 2 ||
		document.Components.SecuritySchemes["apiKeyCookie"].Type != "apiKey" ||
		document.Components.SecuritySchemes["bearerAuth"].Scheme != "bearer" {
		t.Fatalf("security schemes=%#v", document.Components.SecuritySchemes)
	}
	if len(document.Servers) != 1 || document.Servers[0].URL != "http://localhost:3000/api/auth" ||
		len(document.Tags) != 1 || document.Tags[0].Name != "Default" {
		t.Fatalf("servers=%#v tags=%#v", document.Servers, document.Tags)
	}

	criticalOperations := map[string]string{
		"/sign-up/email": "signUpWithEmailAndPassword",
		"/sign-in/email": "signInEmail",
		"/update-user":   "updateUser",
	}
	for path, operationID := range criticalOperations {
		item, exists := document.Paths[path]
		if !exists || item.Post == nil || item.Post.OperationID != operationID {
			t.Errorf("POST %s = %#v, want operationId %q", path, item.Post, operationID)
		}
	}
	getSession := document.Paths["/get-session"]
	if getSession.Get == nil || getSession.Post == nil ||
		getSession.Get.OperationID != "getSession" || getSession.Post.OperationID != "getSessionPost" {
		t.Fatalf("get-session operations=%#v", getSession)
	}
	callback := document.Paths["/callback/{id}"]
	if callback.Get == nil || callback.Post == nil {
		t.Fatalf("callback operations=%#v", callback)
	}

	signUp := document.Paths["/sign-up/email"].Post
	for _, status := range []string{"200", "400", "401", "403", "404", "422", "429", "500"} {
		if _, exists := signUp.Responses[status]; !exists {
			t.Errorf("sign-up response %s is missing", status)
		}
	}
	if signUp.RequestBody == nil || signUp.RequestBody.Content["application/json"].Schema == nil {
		t.Fatal("sign-up JSON request body is missing")
	}
}

func countOpenAPIOperations(document openapi.Document) int {
	count := 0
	for _, item := range document.Paths {
		for _, operation := range []*openapi.Operation{
			item.Get, item.Post, item.Put, item.Patch, item.Delete,
		} {
			if operation != nil {
				count++
			}
		}
	}
	return count
}
