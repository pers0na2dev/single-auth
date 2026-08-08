package core

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestPasswordHashFactoryWrappersComposeInInitializationOrder(t *testing.T) {
	var calls []string
	var paths []string
	var lateWrap func(PluginPasswordHashWrapper) error

	first := &testPluginFactory{id: "password-hash-first"}
	first.build = func(host PluginHost) (engine.Plugin, error) {
		lateWrap = host.WrapPasswordHash
		if err := host.WrapPasswordHash(func(next PluginPasswordHash) PluginPasswordHash {
			return func(ctx *engine.Context, password string) (string, error) {
				calls = append(calls, "first:before")
				paths = append(paths, ctx.RoutePath())
				hash, err := next(ctx, password)
				calls = append(calls, "first:after")
				return "first(" + hash + ")", err
			}
		}); err != nil {
			return engine.Plugin{}, err
		}
		return engine.Plugin{ID: "password-hash-first"}, nil
	}
	second := &testPluginFactory{id: "password-hash-second"}
	second.build = func(host PluginHost) (engine.Plugin, error) {
		if err := host.WrapPasswordHash(func(next PluginPasswordHash) PluginPasswordHash {
			return func(ctx *engine.Context, password string) (string, error) {
				calls = append(calls, "second:before")
				hash, err := next(ctx, password)
				calls = append(calls, "second:after")
				return "second(" + hash + ")", err
			}
		}); err != nil {
			return engine.Plugin{}, err
		}
		return engine.Plugin{ID: "password-hash-second"}, nil
	}

	auth := MustNew(Options{
		EmailAndPassword: EmailAndPasswordOptions{
			Enabled: true,
			Password: PasswordOptions{Hash: func(password string) (string, error) {
				calls = append(calls, "base")
				return "base:" + password, nil
			}},
		},
		PluginFactories: []PluginFactory{first, second},
	})

	status, _, body := sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Wrapped", "email": "wrapped-hash@example.com", "password": "password123",
	})
	if status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%#v", status, body)
	}
	wantCalls := []string{"second:before", "first:before", "base", "first:after", "second:after"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("hash calls=%#v want=%#v", calls, wantCalls)
	}
	if !reflect.DeepEqual(paths, []string{"/sign-up/email"}) {
		t.Fatalf("wrapper paths=%#v", paths)
	}
	account, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{{Field: "providerId", Value: "credential"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if account == nil || account["password"] != "second(first(base:password123))" {
		t.Fatalf("stored account=%#v", account)
	}
	if lateWrap == nil {
		t.Fatal("factory did not capture WrapPasswordHash")
	}
	if err := lateWrap(func(next PluginPasswordHash) PluginPasswordHash { return next }); err == nil ||
		!strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("late wrapper error=%v", err)
	}
}

func TestPasswordHashFactoryRejectsInvalidWrappers(t *testing.T) {
	tests := []struct {
		name    string
		wrapper PluginPasswordHashWrapper
		want    string
	}{
		{name: "nil", wrapper: nil, want: "password hash wrapper is nil"},
		{name: "nil result", wrapper: func(PluginPasswordHash) PluginPasswordHash { return nil }, want: "password hash wrapper returned nil"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := &testPluginFactory{id: "invalid-password-hash"}
			factory.build = func(host PluginHost) (engine.Plugin, error) {
				return engine.Plugin{ID: "invalid-password-hash"}, host.WrapPasswordHash(test.wrapper)
			}
			_, err := New(Options{PluginFactories: []PluginFactory{factory}})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestPasswordHashTypedErrorIsPreservedBeforeUserCreation(t *testing.T) {
	compromised := contract.NewAPIError(
		http.StatusBadRequest,
		"PASSWORD_COMPROMISED",
		"Password is compromised",
	).WithHeaders(contract.NewHeaders(contract.HeaderField{Name: "X-Password-Check", Value: "blocked"}))
	factory := &testPluginFactory{id: "reject-password"}
	factory.build = func(host PluginHost) (engine.Plugin, error) {
		if err := host.WrapPasswordHash(func(next PluginPasswordHash) PluginPasswordHash {
			return func(ctx *engine.Context, password string) (string, error) {
				if ctx != nil && ctx.RoutePath() == "/sign-up/email" {
					return "", compromised
				}
				return next(ctx, password)
			}
		}); err != nil {
			return engine.Plugin{}, err
		}
		return engine.Plugin{ID: "reject-password"}, nil
	}
	auth := MustNew(Options{
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		PluginFactories:  []PluginFactory{factory},
	})

	status, headers, body := sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Rejected", "email": "compromised@example.com", "password": "password123",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%#v", status, body)
	}
	errorBody, ok := body.(map[string]any)
	if !ok || errorBody["code"] != compromised.Code || errorBody["message"] != compromised.Message {
		t.Fatalf("body=%#v", body)
	}
	if headers.Get("X-Password-Check") != "blocked" {
		t.Fatalf("typed error headers=%#v", headers)
	}
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "compromised@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatalf("rejected user was created: %#v", user)
	}
}
