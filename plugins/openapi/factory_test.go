package openapi_test

import (
	"encoding/json"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/openapi"
	"github.com/pers0na2dev/single-auth/storage"
)

type endpointListProbeFactory struct {
	duringBuild []engine.Endpoint
	list        func() []engine.Endpoint
}

func (*endpointListProbeFactory) PluginID() string                { return "endpoint-list-probe" }
func (*endpointListProbeFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }
func (factory *endpointListProbeFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	factory.list = host.ListEndpoints
	if factory.list != nil {
		factory.duringBuild = factory.list()
	}
	return engine.Plugin{ID: factory.PluginID()}, nil
}

func TestPluginHostEndpointEnumerationIsLazyAndReturnsSnapshots(t *testing.T) {
	probe := &endpointListProbeFactory{}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:         "http://auth.example.test",
		PluginFactories: []singleauth.PluginFactory{probe, openapi.NewFactory(openapi.Options{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if probe.list == nil || probe.duringBuild != nil {
		t.Fatalf("list=%v duringBuild=%#v", probe.list != nil, probe.duringBuild)
	}
	first := probe.list()
	if len(first) == 0 {
		t.Fatal("finalized endpoint list is empty")
	}
	first[0].Path = "/mutated"
	first[0].Methods = []string{"DELETE"}
	second := probe.list()
	if len(second) == 0 || second[0].Path == "/mutated" || len(second[0].Methods) == 0 || second[0].Methods[0] == "DELETE" {
		t.Fatalf("endpoint snapshots alias: first=%#v second=%#v", first[0], second[0])
	}
	if auth.Registry() == nil {
		t.Fatal("auth registry was not finalized")
	}
}

func TestRootFactoryHonorsDisabledPathsInGeneratedDocument(t *testing.T) {
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test", DisabledPaths: []string{"/ok"},
		PluginFactories: []singleauth.PluginFactory{openapi.NewFactory(openapi.Options{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := auth.API().Call(t.Context(), "generateOpenAPISchema", singleauth.DirectCallInput{})
	if err != nil {
		t.Fatal(err)
	}
	var document openapi.Document
	if err := json.Unmarshal(result.Response.Body(), &document); err != nil {
		t.Fatal(err)
	}
	if _, exists := document.Paths["/ok"]; exists {
		t.Fatal("disabled /ok path leaked into document")
	}
}
