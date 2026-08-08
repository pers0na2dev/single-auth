package haveibeenpwned

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type compiledPlugin struct {
	enabled bool
	paths   map[string]struct{}
	checker *checker
	runtime Runtime
}

// New constructs the single-auth-compatible descriptor and installs its
// password hash wrapper. The wrapper runs at the actual hash point so each
// endpoint keeps its own validation, verification-token, and session order.
func New(options Options) (engine.Plugin, error) {
	implementation, err := compile(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	if err := implementation.runtime.WrapPasswordHash(implementation.wrapHash); err != nil {
		return engine.Plugin{}, fmt.Errorf("haveibeenpwned: install password hash wrapper: %w", err)
	}
	return implementation.descriptor(), nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

// NewFactory binds the plugin to the root request-aware password hash chain
// after singleauth.New has finalized its password and HTTP client options.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return PluginID }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	if host.WrapPasswordHash == nil {
		return engine.Plugin{}, fmt.Errorf("haveibeenpwned: host password hash wrapper is required")
	}
	if options.HTTPClient == nil {
		options.HTTPClient = host.Options.HTTPClient
	}
	options.Runtime.WrapPasswordHash = func(wrapper PasswordHashWrapper) error {
		return host.WrapPasswordHash(func(next singleauth.PluginPasswordHash) singleauth.PluginPasswordHash {
			wrapped := wrapper(func(ctx *engine.Context, password string) (string, error) {
				return next(ctx, password)
			})
			if wrapped == nil {
				return nil
			}
			return func(ctx *engine.Context, password string) (string, error) {
				return wrapped(ctx, password)
			}
		})
	}
	return New(options)
}

func compile(input Options) (*compiledPlugin, error) {
	options := snapshotOptions(input)
	if options.Runtime.WrapPasswordHash == nil {
		return nil, fmt.Errorf("haveibeenpwned: Runtime.WrapPasswordHash is required")
	}
	enabled := options.Enabled == nil || *options.Enabled
	paths := options.Paths
	if paths == nil {
		paths = DefaultPaths()
	}
	pathSet := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		pathSet[path] = struct{}{}
	}
	return &compiledPlugin{
		enabled: enabled,
		paths:   pathSet,
		checker: newChecker(options),
		runtime: options.Runtime,
	}, nil
}

func snapshotOptions(source Options) Options {
	result := source
	if source.Paths != nil {
		result.Paths = make([]string, len(source.Paths))
		copy(result.Paths, source.Paths)
	}
	if source.Enabled != nil {
		value := *source.Enabled
		result.Enabled = &value
	}
	return result
}

func (plugin *compiledPlugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID:         PluginID,
		Version:    Version,
		ErrorCodes: pluginErrorCodes(),
	}
}

func (plugin *compiledPlugin) wrapHash(next PasswordHashFunc) PasswordHashFunc {
	return func(ctx *engine.Context, password string) (string, error) {
		if !plugin.enabled || ctx == nil {
			return next(ctx, password)
		}
		path := ctx.Path()
		if path == "" {
			return next(ctx, password)
		}
		if _, applies := plugin.paths[path]; !applies {
			return next(ctx, password)
		}
		if err := plugin.checker.check(ctx.GoContext(), password); err != nil {
			return "", err
		}
		return next(ctx, password)
	}
}
