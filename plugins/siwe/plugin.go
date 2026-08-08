package siwe

import (
	"fmt"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const nonceLifetime = 15 * time.Minute

type plugin struct {
	options Options
	schema  storage.Schema
	clock   func() time.Time
}

// New validates and snapshots a transport-neutral SIWE plugin.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "siwe", Version: Version, Schema: implementation.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "getSiweNonce", Path: "/siwe/nonce", Methods: []string{"POST"}, Handler: implementation.nonce},
			{Name: "getNonce", Path: "/siwe/get-nonce", Methods: []string{"POST"}, Handler: implementation.nonce},
			{Name: "verifySiweMessage", Path: "/siwe/verify", Methods: []string{"POST"}, Handler: implementation.verify},
		},
	}, nil
}

func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

// NewFactory binds persistence, base URL resolution, user hooks, session
// cookies, secondary verification storage, and the root clock.
func NewFactory(options Options) singleauth.PluginFactory {
	options.Schema = options.Schema.Clone()
	options.Anonymous = cloneBool(options.Anonymous)
	options.Runtime = Runtime{}
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "siwe" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return resolveSchema(factory.options.Schema)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime = Runtime{
		Adapter: host.Adapter, Clock: host.Clock, ResolveBaseURL: host.ResolveBaseURL,
		CreateVerification:  host.CreateVerification,
		ConsumeVerification: host.ConsumeVerification,
		CreateUser:          host.CreateUser,
		IssueSession: func(ctx *engine.Context, userID string) (*SessionState, error) {
			state, err := host.IssueSession(ctx, userID, false)
			if err != nil || state == nil {
				return nil, err
			}
			return &SessionState{Session: state.Session, User: state.User}, nil
		},
	}
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	switch {
	case input.Domain == "":
		return nil, fmt.Errorf("siwe: Domain is required")
	case input.GetNonce == nil:
		return nil, fmt.Errorf("siwe: GetNonce is required")
	case input.VerifyMessage == nil:
		return nil, fmt.Errorf("siwe: VerifyMessage is required")
	case input.Runtime.Adapter == nil:
		return nil, fmt.Errorf("siwe: Runtime.Adapter is required")
	case input.Runtime.CreateVerification == nil:
		return nil, fmt.Errorf("siwe: Runtime.CreateVerification is required")
	case input.Runtime.ConsumeVerification == nil:
		return nil, fmt.Errorf("siwe: Runtime.ConsumeVerification is required")
	case input.Runtime.CreateUser == nil:
		return nil, fmt.Errorf("siwe: Runtime.CreateUser is required")
	case input.Runtime.IssueSession == nil:
		return nil, fmt.Errorf("siwe: Runtime.IssueSession is required")
	case input.EmailDomainName == "" && input.Runtime.ResolveBaseURL == nil:
		return nil, fmt.Errorf("siwe: Runtime.ResolveBaseURL is required when EmailDomainName is empty")
	}
	options := input
	options.Schema = input.Schema.Clone()
	options.Anonymous = cloneBool(input.Anonymous)
	schema, err := resolveSchema(options.Schema)
	if err != nil {
		return nil, fmt.Errorf("siwe: schema: %w", err)
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	return &plugin{options: options, schema: schema, clock: clock}, nil
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
