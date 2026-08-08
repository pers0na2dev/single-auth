package username

import (
	"context"
	"fmt"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type compiledPlugin struct {
	options           Options
	schema            storage.Schema
	usernameNormal    Normalizer
	displayNormal     Normalizer
	usernameValidator Validator
	minLength         int
	maxLength         int
}

type rootFactory struct{ options Options }

// NewFactory contributes the username fields before adapter construction and
// binds persistence, password, session, cookie, and verification services to
// the final root runtime.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

func (*rootFactory) PluginID() string { return "username" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return Schema(factory.options)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Logger = host.Logger
	options.Runtime.Clock = host.Clock
	options.Runtime.Secret = host.Secret
	options.Runtime.HashPassword = host.Options.EmailAndPassword.Password.Hash
	options.Runtime.HashPasswordContext = func(ctx *engine.Context, password string) (string, error) {
		return host.HashPassword(ctx, password)
	}
	options.Runtime.VerifyPassword = host.Options.EmailAndPassword.Password.Verify
	options.Runtime.RequireEmailVerification = host.Options.EmailAndPassword.RequireEmailVerification
	options.Runtime.SendOnSignIn = host.Options.EmailVerification.SendOnSignIn
	options.Runtime.VerificationExpiresIn = host.Options.EmailVerification.ExpiresIn
	options.Runtime.RegisterDatabaseHooks = host.RegisterDatabaseHooks
	options.Runtime.IssueSession = func(ctx *engine.Context, userID string, dontRemember bool) (*SessionState, error) {
		state, err := host.IssueSession(ctx, userID, dontRemember)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.ResolveSession = func(ctx *engine.Context) (*SessionState, error) {
		state, err := host.ResolveSession(ctx, singleauth.PluginSessionRequired)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.ResolveBaseURL = host.ResolveBaseURL
	options.Runtime.ValidateRedirect = host.ValidateRedirect
	options.Runtime.RunBackground = host.RunBackground
	if sender := host.Options.EmailVerification.SendVerificationEmail; sender != nil {
		options.Runtime.SendVerificationEmail = func(ctx context.Context, message VerificationMessage) error {
			return sender(ctx, singleauth.EmailVerificationMessage{
				User: message.User, URL: message.URL, Token: message.Token,
			})
		}
	}
	return New(options)
}

// New validates and snapshots a standalone username plugin.
func New(options Options) (engine.Plugin, error) {
	compiled, err := compileOptions(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	if err := compiled.options.Runtime.RegisterDatabaseHooks(compiled.databaseHooks()); err != nil {
		return engine.Plugin{}, fmt.Errorf("username: register database hooks: %w", err)
	}
	return compiled.descriptor(), nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

func compileOptions(input Options) (*compiledPlugin, error) {
	compiled, err := compileDefinition(input)
	if err != nil {
		return nil, err
	}
	options := compiled.options
	if options.Runtime.Adapter == nil {
		return nil, fmt.Errorf("username: Runtime.Adapter is required")
	}
	if options.Runtime.IssueSession == nil {
		return nil, fmt.Errorf("username: Runtime.IssueSession is required")
	}
	if options.Runtime.ResolveSession == nil {
		return nil, fmt.Errorf("username: Runtime.ResolveSession is required")
	}
	if options.Runtime.RegisterDatabaseHooks == nil {
		return nil, fmt.Errorf("username: Runtime.RegisterDatabaseHooks is required")
	}
	if options.Runtime.HashPassword == nil {
		options.Runtime.HashPassword = baCrypto.HashPassword
	}
	if options.Runtime.HashPasswordContext == nil {
		hash := options.Runtime.HashPassword
		options.Runtime.HashPasswordContext = func(_ *engine.Context, password string) (string, error) {
			return hash(password)
		}
	}
	if options.Runtime.VerifyPassword == nil {
		options.Runtime.VerifyPassword = baCrypto.VerifyPassword
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Secret == "" {
		options.Runtime.Secret = defaultSecret
	}
	if options.Runtime.VerificationExpiresIn == 0 {
		options.Runtime.VerificationExpiresIn = time.Hour
	}
	if options.Runtime.SerializeUser == nil {
		options.Runtime.SerializeUser = func(user storage.Record) any { return cloneRecord(user) }
	}
	if options.Runtime.RunBackground == nil {
		options.Runtime.RunBackground = func(ctx context.Context, work func(context.Context) error) error {
			return work(ctx)
		}
	}
	compiled.options = options
	return compiled, nil
}

func compileDefinition(input Options) (*compiledPlugin, error) {
	options := snapshotOptions(input)

	minLength := options.MinUsernameLength
	if minLength == 0 {
		minLength = defaultMinUsernameLength
	}
	maxLength := options.MaxUsernameLength
	if maxLength == 0 {
		maxLength = defaultMaxUsernameLength
	}
	usernameNormalizer := Normalizer(strings.ToLower)
	if options.DisableUsernameNormalization {
		usernameNormalizer = func(value string) string { return value }
	} else if options.UsernameNormalization != nil {
		usernameNormalizer = options.UsernameNormalization
	}
	displayNormalizer := options.DisplayUsernameNormalization
	if displayNormalizer == nil {
		displayNormalizer = func(value string) string { return value }
	}
	validator := options.UsernameValidator
	if validator == nil {
		validator = defaultUsernameValidator
	}
	schema, err := schemaFor(options, usernameNormalizer, displayNormalizer)
	if err != nil {
		return nil, err
	}
	return &compiledPlugin{
		options: options, schema: schema, usernameNormal: usernameNormalizer,
		displayNormal: displayNormalizer, usernameValidator: validator,
		minLength: minLength, maxLength: maxLength,
	}, nil
}

func snapshotOptions(source Options) Options {
	result := source
	result.Runtime = snapshotRuntime(source.Runtime)
	return result
}

func snapshotRuntime(source Runtime) Runtime { return source }

func (plugin *compiledPlugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID:      "username",
		Version: Version,
		Schema:  plugin.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "signInUsername", Path: "/sign-in/username", Methods: []string{"POST"}, OperationID: "signInWithUsername", Handler: plugin.signInUsername},
			{Name: "isUsernameAvailable", Path: "/is-username-available", Methods: []string{"POST"}, OperationID: "isUsernameAvailable", Handler: plugin.isUsernameAvailable},
		},
		Hooks: engine.Hooks{Before: []engine.BeforeHook{
			{Name: "username-display-fallback", Matcher: plugin.matchesSignUp, Handler: plugin.applyDisplayFallback},
			{Name: "username-validate-input", Matcher: plugin.matchesUserInput, Handler: plugin.validateHTTPInput},
			{Name: "username-display-default", Matcher: plugin.matchesSignUp, Handler: plugin.applyDisplayDefault},
		}},
		ErrorCodes: pluginErrorCodes(),
	}
}
