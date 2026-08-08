package multisession_test

import (
	"reflect"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/multisession"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestDescriptorMatchesReferenceSurface(t *testing.T) {
	runtime := descriptorRuntime(t)
	plugin, err := multisession.New(multisession.Options{Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	if plugin.ID != "multi-session" || plugin.Version != multisession.Version ||
		len(plugin.Schema.Models) != 0 || len(plugin.RateLimit) != 0 {
		t.Fatalf("descriptor = %#v", plugin)
	}
	wantNames := []string{"listDeviceSessions", "setActiveSession", "revokeDeviceSession"}
	wantPaths := []string{
		"/multi-session/list-device-sessions",
		"/multi-session/set-active",
		"/multi-session/revoke",
	}
	wantMethods := [][]string{{"GET"}, {"POST"}, {"POST"}}
	for index, endpoint := range plugin.Endpoints {
		if endpoint.Name != wantNames[index] || endpoint.Path != wantPaths[index] ||
			!reflect.DeepEqual(endpoint.Methods, wantMethods[index]) ||
			endpoint.OperationID != wantNames[index] {
			t.Fatalf("endpoint %d = %#v", index, endpoint)
		}
	}
	if len(plugin.Hooks.After) != 2 || len(plugin.Hooks.Before) != 0 {
		t.Fatalf("hooks = %#v", plugin.Hooks)
	}
	definition, exists := plugin.ErrorCodes[multisession.ErrorInvalidSessionToken]
	if !exists || definition.Message != "Invalid session token" || len(plugin.ErrorCodes) != 1 {
		t.Fatalf("errors = %#v", plugin.ErrorCodes)
	}
}

func TestFactoryIdentityAndEmptySchema(t *testing.T) {
	factory := multisession.NewFactory(multisession.Options{})
	if factory.PluginID() != "multi-session" {
		t.Fatalf("factory ID = %q", factory.PluginID())
	}
	schema, err := factory.Schema()
	if err != nil || len(schema.Models) != 0 {
		t.Fatalf("schema = %#v, err=%v", schema, err)
	}
	var _ singleauth.PluginFactory = factory
}

func TestStaticConfigurationValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*multisession.Runtime)
		wantErr string
	}{
		{"secret", func(runtime *multisession.Runtime) { runtime.Secret = "" }, "Runtime.Secret"},
		{"session", func(runtime *multisession.Runtime) { runtime.ResolveSession = nil }, "Runtime.ResolveSession"},
		{"refresh", func(runtime *multisession.Runtime) { runtime.RefreshSession = nil }, "Runtime.RefreshSession"},
		{"new-session", func(runtime *multisession.Runtime) { runtime.NewSession = nil }, "Runtime.NewSession"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := descriptorRuntime(t)
			test.mutate(&runtime)
			if _, err := multisession.New(multisession.Options{Runtime: runtime}); err == nil ||
				!contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func descriptorRuntime(t *testing.T) multisession.Runtime {
	t.Helper()
	adapter := memory.MustNew()
	return multisession.Runtime{
		Adapter: adapter, Secret: testSecret,
		ResolveSession: func(*engine.Context) (*multisession.SessionState, error) {
			return nil, nil
		},
		RefreshSession: func(*engine.Context, multisession.SessionState, bool) error { return nil },
		NewSession:     func(*engine.Context) *multisession.SessionState { return nil },
	}
}

func TestStandaloneSerializersAndExplicitZeroMaximum(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	adapter := memory.MustNew(memory.WithInitialData(map[string][]storage.Record{
		"user": {{"id": "u1", "name": "User", "email": "u@example.test", "emailVerified": true,
			"createdAt": now, "updatedAt": now}},
		"session": {{"id": "s1", "token": "TokenABC", "userId": "u1", "expiresAt": now.Add(time.Hour),
			"createdAt": now, "updatedAt": now}},
	}))
	state := &multisession.SessionState{
		Session: storage.Record{"token": "TokenABC", "userId": "u1", "expiresAt": now.Add(time.Hour)},
		User:    storage.Record{"id": "u1", "email": "u@example.test"},
	}
	plugin, err := multisession.New(multisession.Options{
		MaximumSessions: multisession.Int(0),
		Runtime: multisession.Runtime{
			Adapter: adapter, Clock: func() time.Time { return now }, Secret: testSecret,
			ResolveSession:   func(*engine.Context) (*multisession.SessionState, error) { return state, nil },
			RefreshSession:   func(*engine.Context, multisession.SessionState, bool) error { return nil },
			NewSession:       func(*engine.Context) *multisession.SessionState { return state },
			SerializeSession: func(storage.Record) any { return map[string]any{"kind": "session"} },
			SerializeUser:    func(storage.Record) any { return map[string]any{"kind": "user"} },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	probe := engine.Endpoint{
		Name: "probe", Path: "/probe", Methods: []string{"POST"},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			ctx.AddSetCookie("single-auth.session_token=value")
			return contract.JSONResponse(contract.StatusOK, map[string]any{"ok": true})
		},
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{probe}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := dispatcher.Dispatch(contract.NewRequest("POST", "/probe", contract.RequestOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range response.Headers().Values("Set-Cookie") {
		if contains(line, "_multi-") {
			t.Fatalf("maximumSessions=0 set multi cookie: %q", line)
		}
	}
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return fragment == ""
}
