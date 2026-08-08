package engine

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func textHandler(body string) HandlerFunc {
	return func(*Context) (contract.Response, error) {
		return contract.TextResponse(contract.StatusOK, body), nil
	}
}

func TestRegistryDetectsMethodAndDynamicShapeConflicts(t *testing.T) {
	_, err := NewRegistry(nil,
		Plugin{
			ID: "first",
			Endpoints: []Endpoint{{
				Name:    "firstUser",
				Path:    "/users/:id",
				Methods: []string{"GET", "POST"},
				Handler: textHandler("first"),
			}},
		},
		Plugin{
			ID: "second",
			Endpoints: []Endpoint{{
				Name:    "secondUser",
				Path:    "/users/:userID",
				Methods: []string{"POST", "DELETE"},
				Handler: textHandler("second"),
			}},
		},
	)
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("NewRegistry() error = %T %v, want *ConflictError", err, err)
	}
	if got, want := conflict.Conflicts, []EndpointConflict{{
		Path:             "/users/:userID",
		Method:           "POST",
		ExistingEndpoint: "firstUser",
		ExistingPlugin:   "first",
		NewEndpoint:      "secondUser",
		NewPlugin:        "second",
	}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("conflicts = %#v, want %#v", got, want)
	}
}

func TestRegistryAllowsSamePathWithDifferentMethods(t *testing.T) {
	registry, err := NewRegistry([]Endpoint{
		{Name: "read", Path: "/resource", Methods: []string{"GET"}, Handler: textHandler("read")},
		{Name: "write", Path: "/resource", Methods: []string{"POST"}, Handler: textHandler("write")},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	for method, want := range map[string]string{"GET": "read", "POST": "write"} {
		match, matchErr := registry.Match(method, "/resource")
		if matchErr != nil {
			t.Fatalf("Match(%s) error = %v", method, matchErr)
		}
		if match.Endpoint.Name != want {
			t.Fatalf("Match(%s) endpoint = %q, want %q", method, match.Endpoint.Name, want)
		}
	}
}

func TestRegistryEndpointOverrideReplacesCoreAndNarrowsMethods(t *testing.T) {
	registry, err := NewRegistry(
		[]Endpoint{{
			Name: "getSession", Path: "/get-session", Methods: []string{"GET", "POST"},
			Handler: textHandler("core"),
		}},
		Plugin{ID: "custom-session", Endpoints: []Endpoint{{
			Name: "getSession", Path: "/get-session", Methods: []string{"GET"}, Override: true,
			Handler: textHandler("custom"),
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := registry.Endpoints()
	if len(endpoints) != 1 || endpoints[0].Name != "getSession" || !endpoints[0].Override {
		t.Fatalf("endpoints=%#v", endpoints)
	}
	match, err := registry.Match("GET", "/get-session")
	if err != nil || match.Endpoint.pluginID != "custom-session" {
		t.Fatalf("GET match=%#v err=%v", match, err)
	}
	response, err := match.Endpoint.Handler(newContext(contract.NewRequest("GET", "/get-session", contract.RequestOptions{}), false))
	if err != nil || string(response.Body()) != "custom" {
		t.Fatalf("override response=%q err=%v", response.Body(), err)
	}
	if _, err := registry.Match("POST", "/get-session"); err == nil {
		t.Fatal("original POST method survived endpoint replacement")
	}
	direct, ok := registry.Endpoint("getSession")
	if !ok || direct.pluginID != "custom-session" {
		t.Fatalf("direct endpoint=%#v ok=%v", direct, ok)
	}
}

func TestRegistryRejectsInvalidEndpointOverrides(t *testing.T) {
	core := []Endpoint{{
		Name: "getSession", Path: "/get-session", Methods: []string{"GET", "POST"},
		Handler: textHandler("core"),
	}}
	tests := []struct {
		name     string
		endpoint Endpoint
		want     string
	}{
		{
			name: "missing target",
			endpoint: Endpoint{Name: "missing", Path: "/missing", Methods: []string{"GET"},
				Override: true, Handler: textHandler("missing")},
			want: "override target is not registered",
		},
		{
			name: "different path",
			endpoint: Endpoint{Name: "getSession", Path: "/other", Methods: []string{"GET"},
				Override: true, Handler: textHandler("other")},
			want: "must retain endpoint path",
		},
		{
			name: "broader methods",
			endpoint: Endpoint{Name: "getSession", Path: "/get-session", Methods: []string{"DELETE"},
				Override: true, Handler: textHandler("other")},
			want: "must be a subset",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRegistry(core, Plugin{ID: "override", Endpoints: []Endpoint{test.endpoint}})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestRegistryRoutingSpecificityAndDecodedParams(t *testing.T) {
	registry, err := NewRegistry([]Endpoint{
		{Name: "wildcard", Path: "/files/**", Methods: []string{"GET"}, Handler: textHandler("wildcard")},
		{Name: "dynamic", Path: "/files/:fileID", Methods: []string{"GET"}, Handler: textHandler("dynamic")},
		{Name: "static", Path: "/files/new", Methods: []string{"GET"}, Handler: textHandler("static")},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	staticMatch, err := registry.Match("GET", "/files/new")
	if err != nil || staticMatch.Endpoint.Name != "static" {
		t.Fatalf("static Match() = %#v, %v", staticMatch, err)
	}
	dynamicMatch, err := registry.Match("GET", "/files/a%2Fb")
	if err != nil || dynamicMatch.Endpoint.Name != "dynamic" {
		t.Fatalf("dynamic Match() = %#v, %v", dynamicMatch, err)
	}
	if got := dynamicMatch.Params["fileID"]; got != "a/b" {
		t.Fatalf("decoded fileID = %q, want %q", got, "a/b")
	}
	wildcardMatch, err := registry.Match("GET", "/files/a/b")
	if err != nil || wildcardMatch.Endpoint.Name != "wildcard" {
		t.Fatalf("wildcard Match() = %#v, %v", wildcardMatch, err)
	}
	if got := wildcardMatch.Params["*"]; got != "a/b" {
		t.Fatalf("wildcard param = %q, want %q", got, "a/b")
	}
}

func TestRegistryMethodNotAllowedCarriesAllowHeader(t *testing.T) {
	registry, err := NewRegistry([]Endpoint{{
		Name:    "resource",
		Path:    "/resource",
		Methods: []string{"GET", "PATCH"},
		Handler: textHandler("resource"),
	}})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	_, err = registry.Match("DELETE", "/resource")
	apiError, ok := contract.AsAPIError(err)
	if !ok {
		t.Fatalf("Match() error = %T %v, want APIError", err, err)
	}
	if apiError.Status != contract.StatusMethodNotAllowed || apiError.Code != "METHOD_NOT_ALLOWED" {
		t.Fatalf("APIError = %#v", apiError)
	}
	if got, _ := apiError.Headers.Get("Allow"); got != "GET, PATCH" {
		t.Fatalf("Allow = %q, want %q", got, "GET, PATCH")
	}
}

func TestServerOnlyEndpointNeverOccupiesHTTPRouter(t *testing.T) {
	registry, err := NewRegistry(
		[]Endpoint{{Name: "public", Path: "/probe", Methods: []string{"POST"}, Handler: textHandler("public")}},
		Plugin{ID: "secret", Endpoints: []Endpoint{{
			Name:       "secretProbe",
			Path:       "/probe",
			Methods:    []string{"POST"},
			ServerOnly: true,
			Handler:    textHandler("secret"),
		}}},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	match, err := registry.Match("POST", "/probe")
	if err != nil || match.Endpoint.Name != "public" {
		t.Fatalf("Match() = %#v, %v", match, err)
	}
	if endpoint, ok := registry.Endpoint("secretProbe"); !ok || !endpoint.ServerOnly {
		t.Fatalf("direct server-only endpoint = %#v, %v", endpoint, ok)
	}
}

func TestRegistryIsImmutableAfterConstruction(t *testing.T) {
	methods := []string{"GET"}
	metadata := map[string]any{"visibility": "public"}
	plugin := Plugin{ID: "immutable", Endpoints: []Endpoint{{
		Name: "probe", Path: "/probe", Methods: methods, Metadata: metadata,
		Handler: textHandler("original"),
	}}}
	registry, err := NewRegistry(nil, plugin)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	methods[0] = "DELETE"
	metadata["visibility"] = "private"
	plugin.Endpoints[0].Path = "/changed"
	listed := registry.Endpoints()
	listed[0].Methods[0] = "PATCH"
	listed[0].Metadata["visibility"] = "internal"
	listed[0].Path = "/also-changed"

	match, err := registry.Match("GET", "/probe")
	if err != nil || match.Endpoint.Name != "probe" {
		t.Fatalf("immutable Match() = %#v, %v", match, err)
	}
	if _, err := registry.Match("DELETE", "/probe"); err == nil {
		t.Fatal("mutating the source methods changed the registry")
	}
	if got := match.Endpoint.Metadata["visibility"]; got != "public" {
		t.Fatalf("metadata visibility = %#v, want public", got)
	}
}
