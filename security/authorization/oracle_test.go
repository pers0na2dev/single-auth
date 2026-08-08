package authorization

import (
	"errors"
	"testing"
)

type authorizationScenario struct {
	name     string
	response *AuthorizeResponse
	error    string
}

func TestAuthorizationScenarios(t *testing.T) {
	scenarios := []authorizationScenario{
		{name: "allowed", response: &AuthorizeResponse{Success: true}},
		{name: "denied", response: &AuthorizeResponse{Error: `unauthorized to access resource "project"`}},
		{name: "inner-or", response: &AuthorizeResponse{Success: true}},
		{name: "outer-or-skips-unknown", response: &AuthorizeResponse{Success: true}},
		{name: "unknown-and", response: &AuthorizeResponse{Error: "You are not allowed to access resource: audit"}},
		{name: "empty", response: &AuthorizeResponse{Error: `unauthorized to access resource "project"`}},
		{name: "non-string", response: &AuthorizeResponse{Error: `unauthorized to access resource "project"`}},
		{name: "invalid-scalar", error: "Invalid access control request"},
		{name: "missing-actions", response: &AuthorizeResponse{Error: `unauthorized to access resource "project"`}},
	}

	role := testRole()
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			request, outer := authorizationScenarioInput(scenario.name)
			response, err := role.Authorize(request, outer...)
			if scenario.error != "" {
				if !errors.Is(err, ErrInvalidAccessControlRequest) || err.Error() != scenario.error {
					t.Fatalf("error=%v want=%q", err, scenario.error)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario.response == nil || response != *scenario.response {
				t.Fatalf("response=%#v want=%#v", response, scenario.response)
			}
		})
	}
}

func authorizationScenarioInput(name string) (AuthorizeRequest, []Connector) {
	switch name {
	case "allowed":
		return AuthorizeRequest{{"project", []string{"create"}}}, nil
	case "denied":
		return AuthorizeRequest{{"project", []string{"delete-many"}}}, nil
	case "inner-or":
		return AuthorizeRequest{
			{"project", ActionRequest{Actions: []string{"create", "delete-many"}, Connector: OR}},
			{"ui", []string{"view", "edit"}},
		}, nil
	case "outer-or-skips-unknown":
		return AuthorizeRequest{
			{"audit", []string{"read"}}, {"project", []string{"create"}},
		}, []Connector{OR}
	case "unknown-and":
		return AuthorizeRequest{
			{"audit", []string{"read"}}, {"project", []string{"create"}},
		}, nil
	case "empty":
		return AuthorizeRequest{{"project", []string{}}}, nil
	case "non-string":
		return AuthorizeRequest{{"project", []any{"create", 1}}}, nil
	case "invalid-scalar":
		return AuthorizeRequest{{"project", "create"}}, nil
	case "missing-actions":
		return AuthorizeRequest{{"project", map[string]any{"connector": "OR"}}}, nil
	default:
		panic("unknown authorization scenario: " + name)
	}
}
