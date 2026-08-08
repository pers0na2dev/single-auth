package engine

import (
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestDispatcherSkipTrailingSlashesMatchesWithoutRewritingRoutePath(t *testing.T) {
	observedRoutePath := ""
	registry, err := NewRegistry([]Endpoint{
		{
			Name: "plain", Path: "/plain", Methods: []string{"GET"},
			Handler: func(ctx *Context) (contract.Response, error) {
				observedRoutePath = ctx.RoutePath()
				return contract.TextResponse(contract.StatusOK, "plain"), nil
			},
		},
		{
			Name: "declaredSlash", Path: "/declared-slash/", Methods: []string{"GET"},
			Handler: func(ctx *Context) (contract.Response, error) {
				observedRoutePath = ctx.RoutePath()
				return contract.TextResponse(contract.StatusOK, "slash"), nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	strict, err := NewDispatcher(registry, DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	response, _ := strict.Dispatch(contract.NewRequest("GET", "/plain/", contract.RequestOptions{}))
	if response.Status() != contract.StatusNotFound {
		t.Fatalf("strict trailing slash status=%d", response.Status())
	}

	permissive, err := NewDispatcher(registry, DispatcherOptions{SkipTrailingSlashes: true})
	if err != nil {
		t.Fatal(err)
	}
	response, err = permissive.Dispatch(contract.NewRequest("GET", "/plain/", contract.RequestOptions{}))
	if err != nil || response.Status() != contract.StatusOK || observedRoutePath != "/plain/" {
		t.Fatalf("permissive plain response=%d route=%q err=%v", response.Status(), observedRoutePath, err)
	}
	response, err = permissive.Dispatch(contract.NewRequest("GET", "/declared-slash", contract.RequestOptions{}))
	if err != nil || response.Status() != contract.StatusOK || observedRoutePath != "/declared-slash" {
		t.Fatalf("permissive declared-slash response=%d route=%q err=%v", response.Status(), observedRoutePath, err)
	}
	response, _ = permissive.Dispatch(contract.NewRequest("GET", "/plain//", contract.RequestOptions{}))
	if response.Status() != contract.StatusNotFound {
		t.Fatalf("repeated trailing slash status=%d", response.Status())
	}
}
