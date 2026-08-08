package authorization

import (
	"errors"
	"reflect"
	"testing"
)

func testRole() *Role {
	return CreateAccessControl(Statements{
		"project": {"create", "update", "delete", "delete-many"},
		"ui":      {"view", "edit", "comment", "hide"},
	}).NewRole(Statements{
		"project": {"create", "update", "delete"},
		"ui":      {"view", "edit", "comment"},
	})
}

func TestAuthorizeResourceAndActionConnectors(t *testing.T) {
	role := testRole()
	tests := []struct {
		name      string
		request   AuthorizeRequest
		connector []Connector
		want      AuthorizeResponse
	}{
		{
			name: "one allowed", request: AuthorizeRequest{{"project", []string{"create"}}},
			want: AuthorizeResponse{Success: true},
		},
		{
			name: "one denied", request: AuthorizeRequest{{"project", []string{"delete-many"}}},
			want: AuthorizeResponse{Error: `unauthorized to access resource "project"`},
		},
		{
			name: "multiple resources allowed", request: AuthorizeRequest{
				{"project", []string{"create"}}, {"ui", []string{"view"}},
			}, want: AuthorizeResponse{Success: true},
		},
		{
			name: "multiple resources one denied", request: AuthorizeRequest{
				{"project", []string{"delete-many"}}, {"ui", []string{"view"}},
			}, want: AuthorizeResponse{Error: `unauthorized to access resource "project"`},
		},
		{
			name: "outer OR", request: AuthorizeRequest{
				{"project", []string{"create", "delete-many"}}, {"ui", []string{"hide"}},
			}, connector: []Connector{OR}, want: AuthorizeResponse{Success: false, Error: "Not authorized"},
		},
		{
			name: "outer OR later resource", request: AuthorizeRequest{
				{"project", []string{"create", "delete-many"}}, {"ui", []string{"view", "edit"}},
			}, connector: []Connector{OR}, want: AuthorizeResponse{Success: true},
		},
		{
			name: "inner OR", request: AuthorizeRequest{
				{"project", ActionRequest{Actions: []any{"create", "delete-many"}, Connector: OR}},
				{"ui", []string{"view", "edit"}},
			}, want: AuthorizeResponse{Success: true},
		},
		{
			name: "inner OR then other denied", request: AuthorizeRequest{
				{"project", ActionRequest{Actions: []string{"create", "delete-many"}, Connector: OR}},
				{"ui", []string{"view", "hide"}},
			}, want: AuthorizeResponse{Error: `unauthorized to access resource "ui"`},
		},
		{
			name: "unknown connector is AND", request: AuthorizeRequest{
				{"project", ActionRequest{Actions: []string{"create", "delete-many"}, Connector: "XOR"}},
			}, want: AuthorizeResponse{Error: `unauthorized to access resource "project"`},
		},
		{
			name: "non string action", request: AuthorizeRequest{{"project", []any{"create", 1}}},
			want: AuthorizeResponse{Error: `unauthorized to access resource "project"`},
		},
		{
			name: "unknown outer connector falls through", request: AuthorizeRequest{
				{"project", []string{"delete-many"}}, {"ui", []string{"view"}},
			}, connector: []Connector{"XOR"}, want: AuthorizeResponse{Success: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := role.Authorize(test.request, test.connector...)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Authorize()=%#v want=%#v", got, test.want)
			}
		})
	}
}

func TestAuthorizeEmptyUnknownAndMalformedRequests(t *testing.T) {
	role := testRole()
	for _, request := range []AuthorizeRequest{
		{},
		{{"project", []string{}}},
		{{"project", ActionRequest{Actions: []string{}, Connector: AND}}},
		{{"project", ActionRequest{Actions: []string{}, Connector: OR}}},
	} {
		for _, connector := range []Connector{AND, OR} {
			response, err := role.Authorize(request, connector)
			if err != nil || response.Success {
				t.Fatalf("request=%#v connector=%s response=%#v err=%v", request, connector, response, err)
			}
		}
	}

	unknown, err := role.Authorize(AuthorizeRequest{{"audit", []string{"read"}}})
	if err != nil || unknown != (AuthorizeResponse{Error: "You are not allowed to access resource: audit"}) {
		t.Fatalf("unknown=%#v err=%v", unknown, err)
	}
	response, err := role.Authorize(AuthorizeRequest{
		{"audit", []string{"read"}}, {"project", []string{"create"}},
	}, OR)
	if err != nil || !response.Success {
		t.Fatalf("OR unknown/later allowed=%#v err=%v", response, err)
	}
	response, err = role.Authorize(AuthorizeRequest{
		{"audit", []string{"read"}}, {"project", []string{"delete-many"}},
	}, OR)
	if err != nil || response != (AuthorizeResponse{Error: "Not authorized"}) {
		t.Fatalf("OR all denied=%#v err=%v", response, err)
	}

	for _, malformed := range []any{nil, "create", 1, true} {
		_, err := role.Authorize(AuthorizeRequest{{"project", malformed}})
		if !errors.Is(err, ErrInvalidAccessControlRequest) {
			t.Fatalf("malformed=%#v error=%v", malformed, err)
		}
	}
	for _, emptyObject := range []any{
		ActionRequest{}, map[string]any{}, map[string]any{"actions": "create", "connector": "OR"}, struct{}{},
	} {
		response, err := role.Authorize(AuthorizeRequest{{"project", emptyObject}})
		if err != nil || response.Success || response.Error != `unauthorized to access resource "project"` {
			t.Fatalf("empty object=%#v response=%#v err=%v", emptyObject, response, err)
		}
	}
}

func TestAccessControlSnapshotsAndMapConvenience(t *testing.T) {
	statements := Statements{"project": {"create"}}
	control := CreateAccessControl(statements)
	fullRole := control.NewRole(control.Statements())
	fullResponse, err := fullRole.Authorize(AuthorizeRequest{{"project", []string{"create"}}})
	if err != nil || !fullResponse.Success {
		t.Fatalf("full declared role response=%#v err=%v", fullResponse, err)
	}
	statements["project"][0] = "mutated"
	if got := control.Statements()["project"][0]; got != "create" {
		t.Fatalf("control statement alias=%q", got)
	}
	role := control.NewRole(Statements{"project": {"create"}})
	returned := role.Statements()
	returned["project"][0] = "mutated"
	response, err := role.AuthorizeMap(map[string]any{"project": []string{"create"}})
	if err != nil || !response.Success {
		t.Fatalf("map response=%#v err=%v", response, err)
	}
}

func TestAuthorizeIsRaceSafe(t *testing.T) {
	role := testRole()
	done := make(chan error, 64)
	for index := 0; index < cap(done); index++ {
		go func() {
			response, err := role.Authorize(AuthorizeRequest{{"project", []string{"create"}}})
			if err == nil && !response.Success {
				err = errors.New("unexpected denial")
			}
			done <- err
		}()
	}
	for index := 0; index < cap(done); index++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
