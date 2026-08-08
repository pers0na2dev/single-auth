package mcp

import (
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestMCPDescriptorAndFrozenOIDCSchema(t *testing.T) {
	schema := Schema()
	if got := len(schema.Models); got != 3 {
		t.Fatalf("models=%d", got)
	}
	application := schema.Models["oauthApplication"]
	if application.ModelName != "oauthApplication" || len(application.Fields) != 11 {
		t.Fatalf("oauthApplication=%#v", application)
	}
	if !application.Fields["clientId"].Unique || application.Fields["clientSecret"].IsRequired() {
		t.Fatalf("client fields=%#v", application.Fields)
	}
	if application.Fields["userId"].References == nil ||
		application.Fields["userId"].References.OnDelete != storage.Cascade {
		t.Fatalf("user relation=%#v", application.Fields["userId"])
	}
	access := schema.Models["oauthAccessToken"]
	if len(access.Fields) != 9 || !access.Fields["accessToken"].Unique || !access.Fields["refreshToken"].Unique {
		t.Fatalf("oauthAccessToken=%#v", access)
	}
	consent := schema.Models["oauthConsent"]
	if len(consent.Fields) != 6 || consent.Fields["consentGiven"].Type != storage.FieldBoolean {
		t.Fatalf("oauthConsent=%#v", consent)
	}

	first := Schema()
	first.Models["oauthApplication"] = storage.ModelSchema{}
	if reflect.DeepEqual(first, Schema()) {
		t.Fatal("Schema must return independent copies")
	}

	harness := newHarness(t, nil)
	wantEndpoints := map[string]string{
		"oAuthConsent":            ConsentPath,
		"getMcpOAuthConfig":       DiscoveryPath,
		"getMCPProtectedResource": ProtectedResourcePath,
		"mcpOAuthAuthorize":       AuthorizePath,
		"mcpOAuthToken":           TokenPath,
		"registerMcpClient":       RegisterPath,
		"getMcpSession":           SessionPath,
	}
	for name, path := range wantEndpoints {
		endpoint, ok := harness.auth.Registry().Endpoint(name)
		if !ok || endpoint.Path != path {
			t.Fatalf("endpoint %s=%#v ok=%v", name, endpoint, ok)
		}
	}
}
