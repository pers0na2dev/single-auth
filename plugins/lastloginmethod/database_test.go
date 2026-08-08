package lastloginmethod

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type failingMethodUpdateAdapter struct {
	storage.Adapter
	failures atomic.Int64
	err      error
}

func (adapter *failingMethodUpdateAdapter) Update(
	ctx context.Context,
	params storage.UpdateParams,
) (storage.Record, error) {
	if params.Model == "user" {
		if _, exists := params.Update["lastLoginMethod"]; exists {
			adapter.failures.Add(1)
			return nil, adapter.err
		}
	}
	return adapter.Adapter.Update(ctx, params)
}

func TestSessionDatabaseUpdateFailureIsLoggedAndAuthenticationContinues(t *testing.T) {
	extension, err := Schema(Options{StoreInDatabase: true})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(extension)
	if err != nil {
		t.Fatal(err)
	}
	base, err := memory.New(memory.WithSchema(schema))
	if err != nil {
		t.Fatal(err)
	}
	updateFailure := errors.New("forced last method update failure")
	adapter := &failingMethodUpdateAdapter{Adapter: base, err: updateFailure}
	var mu sync.Mutex
	var messages []string

	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           integrationSecret,
		Database:         adapter,
		EmailAndPassword: fastEmailPasswordOptions(),
		Logger: logger.Options{Log: func(
			_ logger.Level,
			message string,
			_ ...any,
		) {
			mu.Lock()
			messages = append(messages, message)
			mu.Unlock()
		}},
		PluginFactories: []singleauth.PluginFactory{
			NewFactory(Options{StoreInDatabase: true}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Failure User", Email: "failure@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatalf("authentication failed because optional database update failed: %v", err)
	}
	if result.Token == nil || *result.Token == "" {
		t.Fatalf("sign-up result = %#v", result)
	}
	if got := adapter.failures.Load(); got != 1 {
		t.Fatalf("last method update attempts = %d, want 1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 1 || messages[0] != "Failed to update lastLoginMethod" {
		t.Fatalf("logger messages = %#v", messages)
	}
}

func TestOAuthAndGenericProviderDatabaseHooksUseRouteParameters(t *testing.T) {
	extension, err := Schema(Options{StoreInDatabase: true})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(extension)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithInitialData(map[string][]storage.Record{"user": {{
			"id": "user-1", "name": "Provider User", "email": "provider@example.com",
			"emailVerified": true,
		}}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	var registered singleauth.DatabaseHooks
	plugin, err := New(Options{
		StoreInDatabase: true,
		Runtime: Runtime{
			Adapter: adapter,
			RegisterDatabaseHooks: func(hooks singleauth.DatabaseHooks) error {
				registered = hooks
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	methods := make(chan string, 2)
	probe := func(name, path string) engine.Endpoint {
		return engine.Endpoint{
			Name: name, Path: path, Methods: []string{"GET"},
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				hookContext := singleauth.DatabaseHookContext{
					Context: ctx.GoContext(), Endpoint: ctx, Model: "user", Operation: "create",
				}
				before, hookErr := registered["user"].Create.Before(
					storage.Record{"email": "new@example.com"}, hookContext,
				)
				if hookErr != nil {
					return contract.Response{}, hookErr
				}
				method, _ := before.Data["lastLoginMethod"].(string)
				methods <- method
				hookContext.Model = "session"
				if hookErr := registered["session"].Create.After(
					storage.Record{"userId": "user-1"}, hookContext,
				); hookErr != nil {
					return contract.Response{}, hookErr
				}
				return contract.NewResponse(contract.StatusOK, contract.Headers{}, nil), nil
			},
		}
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{
		probe("oauthCallbackProbe", "/callback/:id"),
		probe("genericCallbackProbe", "/oauth2/callback/:providerId"),
	}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.NewRequest("GET", "/:direct", contract.RequestOptions{
		Scheme: "https", Host: "auth.example.test",
	})
	tests := []struct {
		endpoint string
		params   map[string]string
		want     string
	}{
		{endpoint: "oauthCallbackProbe", params: map[string]string{"id": "google"}, want: "google"},
		{
			endpoint: "genericCallbackProbe",
			params:   map[string]string{"providerId": "my-provider-id"},
			want:     "my-provider-id",
		},
	}
	for _, test := range tests {
		if _, err := dispatcher.Invoke(test.endpoint, engine.DirectInput{
			Request: request, Params: test.params,
		}); err != nil {
			t.Fatal(err)
		}
		if got := <-methods; got != test.want {
			t.Fatalf("%s create hook method = %q, want %q", test.endpoint, got, test.want)
		}
		user, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "user-1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if user["lastLoginMethod"] != test.want {
			t.Fatalf("%s stored user = %#v", test.endpoint, user)
		}
	}
}

func TestPathlessDatabaseContextsAreNormalizedForCustomResolver(t *testing.T) {
	extension, err := Schema(Options{StoreInDatabase: true})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(extension)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := memory.New(memory.WithSchema(schema))
	if err != nil {
		t.Fatal(err)
	}
	var registered singleauth.DatabaseHooks
	var paths []string
	plugin, err := New(Options{
		StoreInDatabase: true,
		CustomResolveMethod: func(ctx HookContext) (*string, error) {
			paths = append(paths, ctx.Path)
			return nil, nil
		},
		Runtime: Runtime{
			Adapter: adapter,
			RegisterDatabaseHooks: func(hooks singleauth.DatabaseHooks) error {
				registered = hooks
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := engine.Endpoint{
		Name: "pathlessDatabaseProbe", ServerOnly: true, Methods: []string{"POST"},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			databaseContext := singleauth.DatabaseHookContext{
				Context: ctx.GoContext(), Endpoint: ctx,
			}
			result, hookErr := registered["user"].Create.Before(
				storage.Record{"email": "pathless@example.com"}, databaseContext,
			)
			if hookErr != nil {
				return contract.Response{}, hookErr
			}
			if len(result.Data) != 0 {
				return contract.Response{}, errors.New("pathless user hook returned data")
			}
			if hookErr := registered["session"].Create.After(
				storage.Record{"userId": "user-1"}, databaseContext,
			); hookErr != nil {
				return contract.Response{}, hookErr
			}
			return contract.NewResponse(contract.StatusOK, contract.Headers{}, nil), nil
		},
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{endpoint}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.NewRequest("POST", "/:direct", contract.RequestOptions{})
	if _, err := dispatcher.Invoke("pathlessDatabaseProbe", engine.DirectInput{Request: request}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		// user.create, session.create, then the plugin's global after hook.
		t.Fatalf("custom resolver paths = %#v", paths)
	}
	for _, path := range paths {
		if path != "" {
			t.Fatalf("custom resolver paths = %#v, want empty strings", paths)
		}
	}
}
