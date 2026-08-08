package engine

import (
	"reflect"
	"strings"
	"testing"
)

type endpointConflictTestLogger struct {
	messages []string
}

func (logger *endpointConflictTestLogger) Error(message string, _ ...any) {
	logger.messages = append(logger.messages, message)
}

func TestCheckEndpointConflictsMethodArraysAndOrdering(t *testing.T) {
	logger := &endpointConflictTestLogger{}
	conflicts := CheckEndpointConflicts([]Plugin{
		{ID: "plugin-a", Endpoints: []Endpoint{{Name: "multi-a", Path: "/multi", Methods: []string{"GET", "POST"}}}},
		{ID: "plugin-b", Endpoints: []Endpoint{{Name: "multi-b", Path: "/multi", Methods: []string{"POST", "DELETE"}}}},
		{ID: "plugin-c", Endpoints: []Endpoint{{Name: "wild-c", Path: "/wild", Methods: []string{"GET"}}}},
		{ID: "plugin-d", Endpoints: []Endpoint{{Name: "wild-d", Path: "/wild"}}},
	}, logger)

	want := []PluginEndpointConflict{
		{Path: "/multi", Plugins: []string{"plugin-a", "plugin-b"}, ConflictingMethods: []string{"POST"}},
		{Path: "/wild", Plugins: []string{"plugin-c", "plugin-d"}, ConflictingMethods: []string{"GET", "*"}},
	}
	if !reflect.DeepEqual(conflicts, want) {
		t.Fatalf("conflicts = %#v, want %#v", conflicts, want)
	}
	if len(logger.messages) != 1 ||
		!strings.Contains(logger.messages[0], `"/multi" [POST]`) ||
		!strings.Contains(logger.messages[0], `"/wild" [GET, *]`) {
		t.Fatalf("aggregate conflict log = %#v", logger.messages)
	}
}
