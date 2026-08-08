package onetap

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type plugin struct{ options Options }

func New(options Options) (engine.Plugin, error) {
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "one-tap", Version: Version,
		Endpoints: []engine.Endpoint{{
			Name: "oneTapCallback", Path: "/one-tap/callback",
			Methods: []string{"POST"}, OperationID: "oneTapCallback",
			Handler: implementation.callback,
		}},
	}, nil
}

func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

func NewFactory(options Options) singleauth.PluginFactory {
	snapshot := options
	snapshot.Runtime = Runtime{}
	return &rootFactory{options: snapshot}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "one-tap" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime = Runtime{
		Logger: host.Logger, SocialProvider: host.SocialProvider,
		HandleOAuthUser: host.HandleOAuthUser, RefreshSession: host.RefreshSession,
		SerializeUser: func(record map[string]any) any {
			return host.SerializeUser(storage.Record(record))
		},
	}
	return New(options)
}

func normalize(options Options) (*plugin, error) {
	switch {
	case options.Runtime.SocialProvider == nil:
		return nil, fmt.Errorf("onetap: Runtime.SocialProvider is required")
	case options.Runtime.HandleOAuthUser == nil:
		return nil, fmt.Errorf("onetap: Runtime.HandleOAuthUser is required")
	case options.Runtime.RefreshSession == nil:
		return nil, fmt.Errorf("onetap: Runtime.RefreshSession is required")
	case options.Runtime.SerializeUser == nil:
		return nil, fmt.Errorf("onetap: Runtime.SerializeUser is required")
	}
	return &plugin{options: options}, nil
}
