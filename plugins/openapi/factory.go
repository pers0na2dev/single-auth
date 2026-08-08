package openapi

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// NewFactory binds the generator to the final root schema, public base URL,
// disabled-path configuration, and lazily finalized endpoint registry.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string                { return "open-api" }
func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if host.ListEndpoints == nil {
		return engine.Plugin{}, fmt.Errorf("openapi: root host ListEndpoints is required")
	}
	return New(factory.options, Runtime{
		Schema: host.Options.Schema, ListEndpoints: host.ListEndpoints,
		ResolveBaseURL: host.ResolveBaseURL, BaseURL: host.Options.BaseURL,
		DisabledPaths: host.Options.DisabledPaths,
	})
}
