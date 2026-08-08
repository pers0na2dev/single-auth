package deviceauthorization

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

type plugin struct {
	options Options
	schema  storage.Schema
	clock   func() time.Time
	random  io.Reader
}

// NormalizeOptions applies the frozen upstream defaults and validates values
// representable by Go's typed option surface.
func NormalizeOptions(input Options) (Options, error) {
	options := input
	options.Schema = input.Schema.Clone()
	if options.ExpiresIn == 0 {
		options.ExpiresIn = defaultExpiresIn
	}
	if options.Interval == 0 {
		options.Interval = defaultPollingInterval
	}
	if options.DeviceCodeLength == 0 {
		options.DeviceCodeLength = defaultDeviceCodeLength
	}
	if options.UserCodeLength == 0 {
		options.UserCodeLength = defaultUserCodeLength
	}
	if options.DeviceCodeLength < 0 {
		return Options{}, fmt.Errorf("deviceauthorization: DeviceCodeLength must be positive")
	}
	if options.UserCodeLength < 0 {
		return Options{}, fmt.Errorf("deviceauthorization: UserCodeLength must be positive")
	}
	return options, nil
}

// New constructs a transport-neutral plugin descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID:      PluginID,
		Version: Version,
		Schema:  implementation.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "deviceCode", Path: DeviceCodePath, Methods: []string{"POST"}, OperationID: "deviceCode", Handler: implementation.deviceCode},
			{Name: "deviceToken", Path: DeviceTokenPath, Methods: []string{"POST"}, OperationID: "deviceToken", Handler: implementation.deviceToken},
			{Name: "deviceVerify", Path: DeviceVerifyPath, Methods: []string{"GET"}, OperationID: "deviceVerify", Handler: implementation.deviceVerify},
			{Name: "deviceApprove", Path: DeviceApprovePath, Methods: []string{"POST"}, OperationID: "deviceApprove", Handler: implementation.deviceApprove},
			{Name: "deviceDeny", Path: DeviceDenyPath, Methods: []string{"POST"}, OperationID: "deviceDeny", Handler: implementation.deviceDeny},
		},
		ErrorCodes: errorDefinitions(),
	}, nil
}

func MustNew(options Options) engine.Plugin {
	descriptor, err := New(options)
	if err != nil {
		panic(err)
	}
	return descriptor
}

// NewFactory binds device authorization to the final root storage, session,
// secondary-storage, and dynamic base-URL semantics.
func NewFactory(options ...Options) singleauth.PluginFactory {
	var selected Options
	if len(options) > 0 {
		selected = options[0]
	}
	return &rootFactory{options: selected}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return PluginID }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return resolveSchema(factory.options.Schema)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.AdapterForContext = host.AdapterForContext
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.BaseURL = host.Options.BaseURL
	options.Runtime.ResolveBaseURL = func(ctx *engine.Context) (string, error) {
		return host.ResolveBaseURL(ctx.Request())
	}
	options.Runtime.ResolveSession = func(ctx *engine.Context, required bool) (*SessionState, error) {
		mode := singleauth.PluginSessionOptional
		if required {
			mode = singleauth.PluginSessionRequired
		}
		state, err := host.ResolveSession(ctx, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.CreateSession = func(ctx *engine.Context, userID string, dontRemember bool) (*SessionState, error) {
		state, err := host.CreateSession(ctx, userID, dontRemember)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.SetNewSession = func(ctx *engine.Context, state *SessionState) {
		if state == nil {
			host.SetNewSession(ctx, nil)
			return
		}
		host.SetNewSession(ctx, &singleauth.PluginSessionState{
			Session: state.Session, User: state.User,
		})
	}
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	options, err := NormalizeOptions(input)
	if err != nil {
		return nil, err
	}
	schema, err := resolveSchema(options.Schema)
	if err != nil {
		return nil, fmt.Errorf("deviceauthorization: schema: %w", err)
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	randomSource := options.Runtime.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &plugin{
		options: options,
		schema:  schema,
		clock:   clock,
		random:  &lockedReader{r: randomSource},
	}, nil
}

func (p *plugin) adapter(ctx context.Context) storage.TransactionAdapter {
	if p.options.Runtime.AdapterForContext != nil {
		if adapter := p.options.Runtime.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return p.options.Runtime.Adapter
}
