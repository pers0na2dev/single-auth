package engine

import (
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestDispatcherRequiresBasePathAsLeadingSlashBoundaryPrefix(t *testing.T) {
	registry, err := NewRegistry([]Endpoint{{
		Name: "root", Path: "/", Methods: []string{"GET"},
		Handler: func(*Context) (contract.Response, error) {
			return contract.TextResponse(contract.StatusOK, "root"), nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/auth",
		"/x/api/auth/",
		"/api/authentic/",
	} {
		response, _ := dispatcher.Dispatch(contract.NewRequest("GET", path, contract.RequestOptions{}))
		if response.Status() != contract.StatusNotFound {
			t.Fatalf("path %q status=%d, want 404", path, response.Status())
		}
	}
	response, err := dispatcher.Dispatch(contract.NewRequest("GET", "/api/auth/", contract.RequestOptions{}))
	if err != nil || response.Status() != contract.StatusOK {
		t.Fatalf("leading-prefix root status=%d err=%v", response.Status(), err)
	}
}
