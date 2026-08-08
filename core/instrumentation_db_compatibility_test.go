package core

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/instrumentation"
	"github.com/pers0na2dev/single-auth/storage"
)

type databaseInstrumentationCase struct {
	Suite       string
	Title       string
	Observation databaseInstrumentationObservation
}

type databaseInstrumentationObservation struct {
	Spans []databaseInstrumentationSpan `json:"spans"`
}

type databaseInstrumentationSpan struct {
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes"`
}

func TestDatabaseInstrumentationScenarios(t *testing.T) {
	for _, testCase := range databaseInstrumentationCases() {
		testCase := testCase
		t.Run(testCase.Suite+"/"+testCase.Title, func(t *testing.T) {
			provider := &databaseInstrumentationRecordingProvider{}
			restore := instrumentation.SetTracerProvider(provider)
			defer restore()

			runDatabaseInstrumentationCase(t, testCase.Title)
			actual := databaseInstrumentationSelectSpans(
				t,
				provider.Finished(),
				testCase.Observation.Spans,
			)
			if !reflect.DeepEqual(actual, testCase.Observation.Spans) {
				actualJSON, _ := json.MarshalIndent(actual, "", "  ")
				expectedJSON, _ := json.MarshalIndent(testCase.Observation.Spans, "", "  ")
				t.Fatalf("database instrumentation spans:\n%s\nwant:\n%s", actualJSON, expectedJSON)
			}
		})
	}
}

func runDatabaseInstrumentationCase(t *testing.T, title string) {
	t.Helper()
	ctx := t.Context()
	switch title {
	case "emits db create span":
		auth := MustNew(Options{DatabaseHooks: databaseInstrumentationHooks()})
		databaseInstrumentationCreateUser(t, ctx, auth.Adapter())
	case "emits db findOne span":
		auth := MustNew(Options{DatabaseHooks: databaseInstrumentationHooks()})
		user := databaseInstrumentationCreateUser(t, ctx, auth.Adapter())
		session := databaseInstrumentationCreateSession(t, ctx, auth.Adapter(), user)
		found, err := auth.Adapter().FindOne(ctx, storage.FindOneParams{
			Model: "session",
			Where: []storage.Where{{Field: "token", Value: session["token"]}},
		})
		if err != nil || found == nil {
			t.Fatalf("findOne session = %#v, %v", found, err)
		}
	case "emits db findMany span":
		auth := MustNew(Options{DatabaseHooks: databaseInstrumentationHooks()})
		user := databaseInstrumentationCreateUser(t, ctx, auth.Adapter())
		databaseInstrumentationCreateSession(t, ctx, auth.Adapter(), user)
		rows, err := auth.Adapter().FindMany(ctx, storage.FindManyParams{Model: "session"})
		if err != nil || len(rows) != 1 {
			t.Fatalf("findMany sessions = %#v, %v", rows, err)
		}
	case "emits db update span":
		auth := MustNew(Options{DatabaseHooks: databaseInstrumentationHooks()})
		user := databaseInstrumentationCreateUser(t, ctx, auth.Adapter())
		updated, err := auth.Adapter().Update(ctx, storage.UpdateParams{
			Model:  "user",
			Where:  []storage.Where{{Field: "id", Value: user["id"]}},
			Update: storage.Record{"name": "Updated Name"},
		})
		if err != nil || updated == nil || updated["name"] != "Updated Name" {
			t.Fatalf("updated user = %#v, %v", updated, err)
		}
	case "emits db delete span":
		auth := MustNew(Options{DatabaseHooks: databaseInstrumentationHooks()})
		user := databaseInstrumentationCreateUser(t, ctx, auth.Adapter())
		session := databaseInstrumentationCreateSession(t, ctx, auth.Adapter(), user)
		if err := auth.Adapter().Delete(ctx, storage.DeleteParams{
			Model: "session",
			Where: []storage.Where{{Field: "token", Value: session["token"]}},
		}); err != nil {
			t.Fatal(err)
		}
	case "emits db deleteMany span":
		auth := MustNew(Options{DatabaseHooks: databaseInstrumentationHooks()})
		user := databaseInstrumentationCreateUser(t, ctx, auth.Adapter())
		databaseInstrumentationCreateSession(t, ctx, auth.Adapter(), user)
		deleted, err := auth.Adapter().DeleteMany(ctx, storage.DeleteManyParams{Model: "session"})
		if err != nil || deleted != 1 {
			t.Fatalf("deleted sessions = %d, %v", deleted, err)
		}
	case "emits plugin id on db hook spans when hooks come from plugin":
		auth := MustNew(Options{PluginFactories: []PluginFactory{
			databaseInstrumentationPluginFactory{},
		}})
		databaseInstrumentationCreateUser(t, ctx, auth.Adapter())
	default:
		t.Fatalf("unknown database instrumentation test %q", title)
	}
}

func databaseInstrumentationHooks() DatabaseHooks {
	beforeWrite := func(data storage.Record, _ DatabaseHookContext) (DatabaseHookResult, error) {
		return DatabaseHookResult{Data: cloneStorageRecord(data)}, nil
	}
	after := func(any, DatabaseHookContext) error { return nil }
	modelHooks := DatabaseModelHooks{
		Create: DatabaseOperationHooks{Before: beforeWrite, After: after},
		Update: DatabaseOperationHooks{Before: beforeWrite, After: after},
		Delete: DatabaseOperationHooks{
			Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
				return DatabaseHookResult{}, nil
			},
			After: after,
		},
	}
	return DatabaseHooks{"user": modelHooks, "session": modelHooks}
}

type databaseInstrumentationPluginFactory struct{}

func (databaseInstrumentationPluginFactory) PluginID() string { return "db-hooks-plugin" }

func (databaseInstrumentationPluginFactory) Schema() (storage.Schema, error) {
	return storage.Schema{}, nil
}

func (databaseInstrumentationPluginFactory) Build(host PluginHost) (engine.Plugin, error) {
	hooks := databaseInstrumentationHooks()
	delete(hooks, "session")
	if err := host.RegisterDatabaseHooks(hooks); err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{ID: "db-hooks-plugin"}, nil
}

func databaseInstrumentationCreateUser(
	t *testing.T,
	ctx context.Context,
	adapter storage.TransactionAdapter,
) storage.Record {
	t.Helper()
	now := time.Date(2026, time.August, 9, 0, 0, 0, 0, time.UTC)
	created, err := adapter.Create(ctx, storage.CreateParams{Model: "user", Data: storage.Record{
		"name":          "Test user",
		"email":         "user@test.com",
		"emailVerified": false,
		"createdAt":     now,
		"updatedAt":     now,
	}})
	if err != nil || created == nil {
		t.Fatalf("create user = %#v, %v", created, err)
	}
	return created
}

func databaseInstrumentationCreateSession(
	t *testing.T,
	ctx context.Context,
	adapter storage.TransactionAdapter,
	user storage.Record,
) storage.Record {
	t.Helper()
	now := time.Date(2026, time.August, 9, 0, 0, 0, 0, time.UTC)
	created, err := adapter.Create(ctx, storage.CreateParams{Model: "session", Data: storage.Record{
		"token":     "instrumentation-session-token",
		"userId":    fmt.Sprint(user["id"]),
		"expiresAt": now.Add(time.Hour),
		"createdAt": now,
		"updatedAt": now,
	}})
	if err != nil || created == nil {
		t.Fatalf("create session = %#v, %v", created, err)
	}
	return created
}

func databaseInstrumentationSelectSpans(
	t *testing.T,
	finished []databaseInstrumentationSpan,
	expected []databaseInstrumentationSpan,
) []databaseInstrumentationSpan {
	t.Helper()
	result := make([]databaseInstrumentationSpan, 0, len(expected))
	for _, target := range expected {
		found := false
		for _, span := range finished {
			if span.Name != target.Name {
				continue
			}
			result = append(result, span)
			found = true
			break
		}
		if !found {
			t.Fatalf("span %q not found in %#v", target.Name, finished)
		}
	}
	return result
}

type databaseInstrumentationRecordingProvider struct {
	mu       sync.Mutex
	finished []databaseInstrumentationSpan
}

func (provider *databaseInstrumentationRecordingProvider) Tracer(scope, version string) instrumentation.Tracer {
	if scope != instrumentation.InstrumentationScope || version != instrumentation.InstrumentationVersion {
		panic(fmt.Sprintf("unexpected instrumentation scope %s@%s", scope, version))
	}
	return databaseInstrumentationRecordingTracer{provider: provider}
}

func (provider *databaseInstrumentationRecordingProvider) Finished() []databaseInstrumentationSpan {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	result := make([]databaseInstrumentationSpan, len(provider.finished))
	for index, span := range provider.finished {
		result[index] = databaseInstrumentationSpan{
			Name:       span.Name,
			Attributes: cloneDatabaseInstrumentationAttributes(span.Attributes),
		}
	}
	return result
}

type databaseInstrumentationRecordingTracer struct {
	provider *databaseInstrumentationRecordingProvider
}

func (tracer databaseInstrumentationRecordingTracer) Start(
	ctx context.Context,
	name string,
	attributes map[string]any,
) (context.Context, instrumentation.Span) {
	return ctx, &databaseInstrumentationRecordingSpan{
		provider:   tracer.provider,
		name:       name,
		attributes: cloneDatabaseInstrumentationAttributes(attributes),
	}
}

type databaseInstrumentationRecordingSpan struct {
	provider   *databaseInstrumentationRecordingProvider
	name       string
	attributes map[string]any
	mu         sync.Mutex
	ended      bool
}

func (span *databaseInstrumentationRecordingSpan) End() {
	span.mu.Lock()
	if span.ended {
		span.mu.Unlock()
		return
	}
	span.ended = true
	snapshot := databaseInstrumentationSpan{
		Name:       span.name,
		Attributes: cloneDatabaseInstrumentationAttributes(span.attributes),
	}
	span.mu.Unlock()

	span.provider.mu.Lock()
	span.provider.finished = append(span.provider.finished, snapshot)
	span.provider.mu.Unlock()
}

func (span *databaseInstrumentationRecordingSpan) SetAttribute(key string, value any) {
	span.mu.Lock()
	span.attributes[key] = value
	span.mu.Unlock()
}

func (*databaseInstrumentationRecordingSpan) SetStatus(any)       {}
func (*databaseInstrumentationRecordingSpan) RecordException(any) {}

func (span *databaseInstrumentationRecordingSpan) UpdateName(name string) instrumentation.Span {
	span.mu.Lock()
	span.name = name
	span.mu.Unlock()
	return span
}

func cloneDatabaseInstrumentationAttributes(attributes map[string]any) map[string]any {
	clone := make(map[string]any, len(attributes))
	for key, value := range attributes {
		clone[key] = value
	}
	return clone
}

func TestDatabaseInstrumentationScenarioDefinitions(t *testing.T) {
	cases := databaseInstrumentationCases()
	if len(cases) != 7 {
		t.Fatalf("database instrumentation scenarios=%d, want 7", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, testCase := range cases {
		if testCase.Suite == "" || testCase.Title == "" || len(testCase.Observation.Spans) == 0 {
			t.Fatalf("invalid database instrumentation scenario: suite=%q title=%q", testCase.Suite, testCase.Title)
		}
		key := testCase.Suite + "\x00" + testCase.Title
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate database instrumentation scenario %q / %q", testCase.Suite, testCase.Title)
		}
		seen[key] = struct{}{}
	}
}

func databaseInstrumentationCases() []databaseInstrumentationCase {
	span := func(name, model, operation string) databaseInstrumentationSpan {
		return databaseInstrumentationSpan{Name: name, Attributes: map[string]any{
			"db.collection.name": model, "db.operation.name": operation,
		}}
	}
	hook := func(name, model, contextName, hookType string) databaseInstrumentationSpan {
		return databaseInstrumentationSpan{Name: name, Attributes: map[string]any{
			"db.collection.name": model, "single_auth.context": contextName, "single_auth.hook.type": hookType,
		}}
	}
	return []databaseInstrumentationCase{
		{Suite: "database instrumentation", Title: "emits db create span", Observation: databaseInstrumentationObservation{Spans: []databaseInstrumentationSpan{
			span("db create user", "user", "create"),
			hook("db create.before user", "user", "user", "create.before"),
			hook("db create.after user", "user", "user", "create.after"),
		}}},
		{Suite: "database instrumentation", Title: "emits db delete span", Observation: databaseInstrumentationObservation{Spans: []databaseInstrumentationSpan{
			span("db delete session", "session", "delete"),
			hook("db delete.before session", "session", "user", "delete.before"),
			hook("db delete.after session", "session", "user", "delete.after"),
		}}},
		{Suite: "database instrumentation", Title: "emits db deleteMany span", Observation: databaseInstrumentationObservation{Spans: []databaseInstrumentationSpan{
			span("db deleteMany session", "session", "deleteMany"),
			hook("db delete.before session", "session", "user", "delete.before"),
			hook("db delete.after session", "session", "user", "delete.after"),
		}}},
		{Suite: "database instrumentation", Title: "emits db findMany span", Observation: databaseInstrumentationObservation{Spans: []databaseInstrumentationSpan{
			span("db findMany session", "session", "findMany"),
		}}},
		{Suite: "database instrumentation", Title: "emits db findOne span", Observation: databaseInstrumentationObservation{Spans: []databaseInstrumentationSpan{
			span("db findOne session", "session", "findOne"),
		}}},
		{Suite: "database instrumentation", Title: "emits db update span", Observation: databaseInstrumentationObservation{Spans: []databaseInstrumentationSpan{
			span("db update user", "user", "update"),
			hook("db update.before user", "user", "user", "update.before"),
			hook("db update.after user", "user", "user", "update.after"),
		}}},
		{Suite: "database instrumentation", Title: "emits plugin id on db hook spans when hooks come from plugin", Observation: databaseInstrumentationObservation{Spans: []databaseInstrumentationSpan{
			hook("db create.before user", "user", "plugin:db-hooks-plugin", "create.before"),
			hook("db create.after user", "user", "plugin:db-hooks-plugin", "create.after"),
		}}},
	}
}
