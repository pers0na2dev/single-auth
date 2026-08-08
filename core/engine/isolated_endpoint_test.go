package engine

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestRunEndpointIsolatedCopiesInputAndKeepsResponseHeadersIsolated(t *testing.T) {
	source := newContext(contract.NewRequest("POST", "/outer", contract.RequestOptions{}), true)
	source.setRoutePath("/outer")
	source.Set("shared", "value")
	source.AddResponseHeader("X-Outer", "keep")

	endpoint := Endpoint{
		Name: "inner", Path: "/inner", Methods: []string{"GET"},
		Handler: func(ctx *Context) (contract.Response, error) {
			if !ctx.IsDirect() || ctx.RoutePath() != "/inner" || ctx.Path() != "/inner" {
				t.Fatalf("inner context route/direct state is wrong")
			}
			if value, ok := ctx.Value("shared"); !ok || value != "value" {
				t.Fatalf("copied value=%#v ok=%v", value, ok)
			}
			if ctx.Request().Method() != "GET" {
				t.Fatalf("inner method=%q", ctx.Request().Method())
			}
			ctx.AddSetCookie("one=1")
			ctx.AddSetCookie("two=2")
			ctx.SetResponseHeader("X-Inner", "present")
			return contract.TextResponse(contract.StatusOK, "inner"), nil
		},
	}
	response, err := RunEndpointIsolated(source, source.Request().WithMethod("GET"), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Headers().Values("Set-Cookie"); !reflect.DeepEqual(got, []string{"one=1", "two=2"}) {
		t.Fatalf("inner cookies=%#v", got)
	}
	if got, _ := response.Headers().Get("X-Inner"); got != "present" {
		t.Fatalf("inner header=%q", got)
	}
	if response.Headers().Has("X-Outer") {
		t.Fatal("outer response header leaked into isolated response")
	}
	outer := source.takeResponseHeaders()
	if got, _ := outer.Get("X-Outer"); got != "keep" || outer.Has("X-Inner") || outer.Has("Set-Cookie") {
		t.Fatalf("outer headers=%#v", outer.Fields())
	}
}

func TestRunEndpointIsolatedReturnsSelfContainedErrorResponse(t *testing.T) {
	source := newContext(contract.NewRequest("GET", "/probe", contract.RequestOptions{}), false)
	want := contract.NewAPIError(contract.StatusBadRequest, "INNER_FAILURE", "Inner failure")
	response, err := RunEndpointIsolated(source, source.Request(), Endpoint{
		Name: "probe", Path: "/probe", Methods: []string{"GET"},
		Handler: func(ctx *Context) (contract.Response, error) {
			ctx.SetResponseHeader("X-Inner", "error")
			return contract.Response{}, want
		},
	})
	if !errors.Is(err, want) || response.Status() != contract.StatusBadRequest {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if got, _ := response.Headers().Get("X-Inner"); got != "error" {
		t.Fatalf("error headers=%#v", response.Headers().Fields())
	}
}

func TestRunEndpointIsolatedRunsEndpointMiddlewareInDeclarationOrder(t *testing.T) {
	source := newContext(contract.NewRequest("GET", "/outer", contract.RequestOptions{}), true)
	order := make([]string, 0, 3)
	endpoint := Endpoint{
		Name: "inner", Path: "/inner", Methods: []string{"GET"},
		Use: []EndpointMiddlewareFunc{
			func(*Context) (EndpointMiddlewareResult, error) {
				order = append(order, "first")
				return EndpointMiddlewareResult{Values: map[string]any{"first": true}}, nil
			},
			func(ctx *Context) (EndpointMiddlewareResult, error) {
				order = append(order, "second")
				if value, ok := ctx.Value("first"); !ok || value != true {
					t.Fatalf("first middleware value=%#v ok=%v", value, ok)
				}
				return EndpointMiddlewareResult{}, nil
			},
		},
		Handler: func(*Context) (contract.Response, error) {
			order = append(order, "handler")
			return contract.JSONResponse(contract.StatusOK, map[string]bool{"ok": true})
		},
	}

	response, err := RunEndpointIsolated(source, source.Request(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"first", "second", "handler"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("middleware order=%#v, want %#v", order, want)
	}
	if response.Status() != contract.StatusOK {
		t.Fatalf("status=%d", response.Status())
	}
}
