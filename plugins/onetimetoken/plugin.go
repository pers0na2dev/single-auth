package onetimetoken

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const defaultExpiry = 3 * time.Minute

type plugin struct {
	options Options
	expires time.Duration
	clock   func() time.Time
	random  io.Reader
}

func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "one-time-token", Version: Version,
		Endpoints: []engine.Endpoint{
			{
				Name: "generateOneTimeToken", Path: "/one-time-token/generate",
				Methods: []string{"GET"}, Handler: implementation.generate,
			},
			{
				Name: "verifyOneTimeToken", Path: "/one-time-token/verify",
				Methods: []string{"POST"}, Handler: implementation.verify,
			},
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    "one-time-token-new-session-header",
			Matcher: func(*engine.Context) (bool, error) { return true, nil },
			Handler: implementation.afterNewSession,
		}}},
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
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "one-time-token" }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.ResolveSession = func(ctx *engine.Context) (*SessionState, error) {
		state, err := host.ResolveSession(ctx, singleauth.PluginSessionRequired)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.FindSession = func(ctx context.Context, token string) (*SessionState, error) {
		state, err := host.FindSession(ctx, token)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.RefreshSession = func(ctx *engine.Context, state SessionState) error {
		return host.RefreshSession(ctx, singleauth.PluginSessionState{
			Session: state.Session, User: state.User,
		}, false)
	}
	options.Runtime.NewSession = func(ctx *engine.Context) *SessionState {
		state := host.NewSession(ctx)
		if state == nil {
			return nil
		}
		return &SessionState{Session: state.Session, User: state.User}
	}
	options.Runtime.SerializeSession = host.SerializeSession
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.CreateVerification = host.CreateVerification
	options.Runtime.ConsumeVerification = host.ConsumeVerification
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	options := input
	if options.Storage.Mode == "" {
		options.Storage.Mode = StorePlain
	}
	switch options.Storage.Mode {
	case StorePlain, StoreHashed:
		if options.Storage.CustomHash != nil {
			return nil, fmt.Errorf("onetimetoken: custom hasher requires StoreCustom")
		}
	case StoreCustom:
		if options.Storage.CustomHash == nil {
			return nil, fmt.Errorf("onetimetoken: StoreCustom requires CustomHash")
		}
	default:
		return nil, fmt.Errorf("onetimetoken: invalid token store mode %q", options.Storage.Mode)
	}
	if options.Runtime.ResolveSession == nil {
		return nil, fmt.Errorf("onetimetoken: Runtime.ResolveSession is required")
	}
	if options.Runtime.FindSession == nil {
		return nil, fmt.Errorf("onetimetoken: Runtime.FindSession is required")
	}
	if !options.DisableSetSessionCookie && options.Runtime.RefreshSession == nil {
		return nil, fmt.Errorf("onetimetoken: Runtime.RefreshSession is required")
	}
	if options.SetOTTHeaderOnNewSession && options.Runtime.NewSession == nil {
		return nil, fmt.Errorf("onetimetoken: Runtime.NewSession is required")
	}
	if options.Runtime.CreateVerification == nil || options.Runtime.ConsumeVerification == nil {
		if options.Runtime.Adapter == nil {
			return nil, fmt.Errorf("onetimetoken: Runtime.Adapter or verification callbacks are required")
		}
	}
	expires := defaultExpiry
	if options.ExpiresIn != nil {
		expires = *options.ExpiresIn
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	randomSource := options.Runtime.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	if options.Runtime.SerializeSession == nil {
		options.Runtime.SerializeSession = func(record storage.Record) any { return cloneRecord(record) }
	}
	if options.Runtime.SerializeUser == nil {
		options.Runtime.SerializeUser = func(record storage.Record) any { return cloneRecord(record) }
	}
	return &plugin{
		options: options,
		expires: expires,
		clock:   clock,
		random:  &lockedReader{reader: randomSource},
	}, nil
}
