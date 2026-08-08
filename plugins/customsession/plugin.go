package customsession

import (
	"fmt"
	"net/http"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type plugin struct{ options Options }

// New validates and snapshots a single-auth custom-session descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "custom-session", Version: Version,
		Endpoints: []engine.Endpoint{{
			Name: "getSession", Path: "/get-session", Methods: []string{http.MethodGet},
			Override: true, Handler: implementation.getSession,
		}},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    "custom-session-list-device-sessions",
			Matcher: implementation.matchesListDeviceSessions,
			Handler: implementation.mutateListDeviceSessions,
		}}},
	}, nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	descriptor, err := New(options)
	if err != nil {
		panic(err)
	}
	return descriptor
}

// NewFactory binds the custom session projection to the final root runtime.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "custom-session" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.GetSession = host.GetSession
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	if input.Enrich == nil {
		return nil, fmt.Errorf("customsession: Enrich is required")
	}
	if input.Runtime.GetSession == nil {
		return nil, fmt.Errorf("customsession: Runtime.GetSession is required")
	}
	return &plugin{options: input}, nil
}
