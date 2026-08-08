package singleauth_test

import (
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/core/engine"
)

type endpointConflictObservation struct {
	ErrorCalls    int
	ErrorMessages []string
}

type endpointConflictCase struct {
	Suite       string
	Title       string
	Observation endpointConflictObservation
}

type endpointConflictSpyLogger struct {
	messages []string
}

func (logger *endpointConflictSpyLogger) Error(message string, _ ...any) {
	logger.messages = append(logger.messages, message)
}

func TestEndpointConflictBehavior(t *testing.T) {
	for _, vector := range endpointConflictCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			plugins := endpointConflictPlugins(t, vector.Title)
			spy := &endpointConflictSpyLogger{messages: []string{}}
			conflicts := engine.CheckEndpointConflicts(plugins, spy)
			if len(spy.messages) != vector.Observation.ErrorCalls {
				t.Fatalf("logger error calls = %d, want %d", len(spy.messages), vector.Observation.ErrorCalls)
			}
			if !reflect.DeepEqual(spy.messages, vector.Observation.ErrorMessages) {
				t.Fatalf("logger messages = %#v, want %#v", spy.messages, vector.Observation.ErrorMessages)
			}
			if (len(conflicts) > 0) != (vector.Observation.ErrorCalls > 0) {
				t.Fatalf("conflicts = %#v, expected error calls = %d", conflicts, vector.Observation.ErrorCalls)
			}
		})
	}
}

func endpointConflictPlugins(t *testing.T, title string) []engine.Plugin {
	t.Helper()
	endpoint := func(name, path string, methods ...string) engine.Endpoint {
		return engine.Endpoint{Name: name, Path: path, Methods: methods}
	}
	switch title {
	case "should not log errors when there are no endpoint conflicts":
		return []engine.Plugin{
			{ID: "plugin1", Endpoints: []engine.Endpoint{
				endpoint("endpoint1", "/api/endpoint1", "GET"),
				endpoint("endpoint2", "/api/endpoint2", "POST"),
			}},
			{ID: "plugin2", Endpoints: []engine.Endpoint{
				endpoint("endpoint3", "/api/endpoint3", "GET"),
				endpoint("endpoint4", "/api/endpoint4", "POST"),
			}},
		}
	case "should NOT log an error when two plugins use the same endpoint path with different methods":
		return []engine.Plugin{
			{ID: "plugin1", Endpoints: []engine.Endpoint{endpoint("endpoint1", "/api/shared", "GET")}},
			{ID: "plugin2", Endpoints: []engine.Endpoint{endpoint("endpoint2", "/api/shared", "POST")}},
		}
	case "should log an error when two plugins use the same endpoint path with the same method":
		return []engine.Plugin{
			{ID: "plugin1", Endpoints: []engine.Endpoint{endpoint("endpoint1", "/api/shared", "GET")}},
			{ID: "plugin2", Endpoints: []engine.Endpoint{endpoint("endpoint2", "/api/shared", "GET")}},
		}
	case "should NOT detect conflicts when plugins use different methods on same paths":
		return []engine.Plugin{
			{ID: "plugin1", Endpoints: []engine.Endpoint{
				endpoint("endpoint1", "/api/resource1", "GET"),
				endpoint("endpoint2", "/api/resource2", "POST"),
			}},
			{ID: "plugin2", Endpoints: []engine.Endpoint{endpoint("endpoint3", "/api/resource1", "POST")}},
			{ID: "plugin3", Endpoints: []engine.Endpoint{endpoint("endpoint4", "/api/resource2", "GET")}},
		}
	case "should detect conflicts when plugins use the same method on the same path":
		return []engine.Plugin{
			{ID: "plugin1", Endpoints: []engine.Endpoint{endpoint("endpoint1", "/api/conflict", "GET")}},
			{ID: "plugin2", Endpoints: []engine.Endpoint{endpoint("endpoint2", "/api/conflict", "GET")}},
		}
	case "should allow multiple endpoints from the same plugin using the same path with different methods":
		return []engine.Plugin{{ID: "plugin1", Endpoints: []engine.Endpoint{
			endpoint("endpoint1", "/api/same", "GET"),
			endpoint("endpoint2", "/api/same", "POST"),
		}}}
	case "should detect conflicts when same plugin has duplicate methods on same path":
		return []engine.Plugin{{ID: "plugin1", Endpoints: []engine.Endpoint{
			endpoint("endpoint1", "/api/same", "GET"),
			endpoint("endpoint2", "/api/same", "GET"),
		}}}
	case "should allow three plugins on the same path with different methods":
		return []engine.Plugin{
			{ID: "plugin1", Endpoints: []engine.Endpoint{endpoint("endpoint1", "/api/resource", "GET")}},
			{ID: "plugin2", Endpoints: []engine.Endpoint{endpoint("endpoint2", "/api/resource", "POST")}},
			{ID: "plugin3", Endpoints: []engine.Endpoint{endpoint("endpoint3", "/api/resource", "DELETE")}},
		}
	case "should detect conflicts when endpoints don't specify a method (wildcard)":
		return []engine.Plugin{
			{ID: "plugin1", Endpoints: []engine.Endpoint{endpoint("endpoint1", "/api/wildcard", "*")}},
			{ID: "plugin2", Endpoints: []engine.Endpoint{endpoint("endpoint2", "/api/wildcard", "GET")}},
		}
	case "should handle plugins with no endpoints":
		return []engine.Plugin{{ID: "plugin1"}, {ID: "plugin2", Endpoints: []engine.Endpoint{}}}
	case "should handle options with no plugins":
		return nil
	case "should handle options with empty plugins array":
		return []engine.Plugin{}
	case "should handle plugins with endpoints that don't have a path":
		return []engine.Plugin{{ID: "plugin1", Endpoints: []engine.Endpoint{
			endpoint("endpoint1", "", "GET"),
			endpoint("endpoint2", "", "GET"),
		}}}
	default:
		t.Fatalf("unknown endpoint-conflict vector %q", title)
		return nil
	}
}

func TestEndpointConflictScenarioDefinitions(t *testing.T) {
	cases := endpointConflictCases()
	if len(cases) != 13 {
		t.Fatalf("endpoint-conflict scenarios=%d, want 13", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, vector := range cases {
		name := vector.Suite + "::" + vector.Title
		if vector.Suite != "checkEndpointConflicts" || vector.Title == "" {
			t.Fatalf("invalid endpoint-conflict scenario: %#v", vector)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate endpoint-conflict scenario %q", name)
		}
		seen[name] = struct{}{}
	}
}

func endpointConflictCases() []endpointConflictCase {
	const suite = "checkEndpointConflicts"
	noConflict := endpointConflictObservation{ErrorMessages: []string{}}
	conflict := func(detail string) endpointConflictObservation {
		return endpointConflictObservation{
			ErrorCalls: 1,
			ErrorMessages: []string{
				"Endpoint path conflicts detected! Multiple plugins are trying to use the same endpoint paths with conflicting HTTP methods:\n" +
					"  - " + detail + "\n\n" +
					"To resolve this, you can:\n" +
					"\t1. Use only one of the conflicting plugins\n" +
					"\t2. Configure the plugins to use different paths (if supported)\n" +
					"\t3. Ensure plugins use different HTTP methods for the same path\n",
			},
		}
	}
	return []endpointConflictCase{
		{Suite: suite, Title: "should allow multiple endpoints from the same plugin using the same path with different methods", Observation: noConflict},
		{Suite: suite, Title: "should allow three plugins on the same path with different methods", Observation: noConflict},
		{Suite: suite, Title: "should detect conflicts when endpoints don't specify a method (wildcard)", Observation: conflict(`"/api/wildcard" [*, GET] used by plugins: plugin1, plugin2`)},
		{Suite: suite, Title: "should detect conflicts when plugins use the same method on the same path", Observation: conflict(`"/api/conflict" [GET] used by plugins: plugin1, plugin2`)},
		{Suite: suite, Title: "should detect conflicts when same plugin has duplicate methods on same path", Observation: conflict(`"/api/same" [GET] used by plugins: plugin1`)},
		{Suite: suite, Title: "should handle options with empty plugins array", Observation: noConflict},
		{Suite: suite, Title: "should handle options with no plugins", Observation: noConflict},
		{Suite: suite, Title: "should handle plugins with endpoints that don't have a path", Observation: noConflict},
		{Suite: suite, Title: "should handle plugins with no endpoints", Observation: noConflict},
		{Suite: suite, Title: "should log an error when two plugins use the same endpoint path with the same method", Observation: conflict(`"/api/shared" [GET] used by plugins: plugin1, plugin2`)},
		{Suite: suite, Title: "should NOT detect conflicts when plugins use different methods on same paths", Observation: noConflict},
		{Suite: suite, Title: "should NOT log an error when two plugins use the same endpoint path with different methods", Observation: noConflict},
		{Suite: suite, Title: "should not log errors when there are no endpoint conflicts", Observation: noConflict},
	}
}
