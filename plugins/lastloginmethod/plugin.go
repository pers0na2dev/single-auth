package lastloginmethod

import (
	"fmt"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type compiledPlugin struct {
	cookieName      string
	maxAge          int
	customResolve   ResolveMethodFunc
	storeInDatabase bool
	beforeStore     BeforeStoreCookieFunc
	schema          storage.Schema
	runtime         Runtime
}

type rootFactory struct{ options Options }

// NewFactory contributes the optional user field before adapter construction
// and installs database hooks during the root plugin initialization phase.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

func (*rootFactory) PluginID() string { return "last-login-method" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return schemaFor(factory.options)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	options.Runtime = Runtime{
		Adapter:               host.Adapter,
		Logger:                host.Logger,
		SessionCookie:         host.SessionCookie,
		RegisterDatabaseHooks: host.RegisterDatabaseHooks,
	}
	return New(options)
}

// New constructs a standalone engine descriptor. StoreInDatabase requires
// Runtime.Adapter and Runtime.RegisterDatabaseHooks; NewFactory supplies both.
func New(options Options) (engine.Plugin, error) {
	plugin, err := compile(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	if plugin.storeInDatabase {
		if plugin.runtime.Adapter == nil {
			return engine.Plugin{}, fmt.Errorf("lastloginmethod: database adapter is required")
		}
		if plugin.runtime.RegisterDatabaseHooks == nil {
			return engine.Plugin{}, fmt.Errorf("lastloginmethod: database hook registrar is required")
		}
		if err := plugin.registerDatabaseHooks(); err != nil {
			return engine.Plugin{}, fmt.Errorf("lastloginmethod: register database hooks: %w", err)
		}
	}
	return plugin.descriptor(), nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

func compile(input Options) (*compiledPlugin, error) {
	options := snapshotOptions(input)
	schema, err := schemaFor(options)
	if err != nil {
		return nil, err
	}
	cookieName := options.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}
	maxAge := DefaultMaxAge
	if options.MaxAge != nil {
		maxAge = *options.MaxAge
	}
	runtime := options.Runtime
	if runtime.SessionCookie == nil {
		runtime.SessionCookie = func(contract.Request) (string, cookies.Options) {
			return "single-auth.session_token", cookies.Options{
				Path: "/", HTTPOnly: true, SameSite: "lax",
			}
		}
	}
	return &compiledPlugin{
		cookieName:      cookieName,
		maxAge:          maxAge,
		customResolve:   options.CustomResolveMethod,
		storeInDatabase: options.StoreInDatabase,
		beforeStore:     options.BeforeStoreCookie,
		schema:          schema,
		runtime:         runtime,
	}, nil
}

func snapshotOptions(source Options) Options {
	result := source
	if source.MaxAge != nil {
		value := *source.MaxAge
		result.MaxAge = &value
	}
	return result
}

func (plugin *compiledPlugin) descriptor() engine.Plugin {
	schema := storage.Schema{}
	if len(plugin.schema.Models) != 0 || plugin.schema.UsePlural {
		schema = plugin.schema.Clone()
	}
	return engine.Plugin{
		ID:      "last-login-method",
		Version: Version,
		Schema:  schema,
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    "last-login-method",
			Matcher: func(*engine.Context) (bool, error) { return true, nil },
			Handler: plugin.after,
		}}},
	}
}

func (plugin *compiledPlugin) after(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	method, err := plugin.resolve(ctx)
	if err != nil || method == "" {
		return nil, err
	}
	sessionName, attributes := plugin.runtime.SessionCookie(ctx.Request())
	hasSessionToken := false
	for _, setCookie := range response.Headers().Values("Set-Cookie") {
		if strings.Contains(setCookie, sessionName) {
			hasSessionToken = true
			break
		}
	}
	if !hasSessionToken {
		return nil, nil
	}

	hookCtx := normalizeHookContext(ctx)
	if plugin.beforeStore != nil {
		permitted, hookErr := plugin.beforeStore(cloneHookContext(hookCtx), method)
		if hookErr != nil {
			if plugin.runtime.Logger != nil {
				plugin.runtime.Logger.Error(
					"[LastLoginMethod] Error in beforeStoreCookie hook", hookErr,
				)
			}
			return nil, nil
		}
		if !permitted {
			return nil, nil
		}
	}

	attributes.MaxAge = Int(plugin.maxAge)
	attributes.HTTPOnly = false
	serialized := cookies.Serialize(plugin.cookieName, method, attributes)
	if serialized != "" {
		ctx.AddSetCookie(serialized)
	}
	return nil, nil
}

func (plugin *compiledPlugin) registerDatabaseHooks() error {
	return plugin.runtime.RegisterDatabaseHooks(singleauth.DatabaseHooks{
		"user": {
			Create: singleauth.DatabaseOperationHooks{Before: plugin.beforeUserCreate},
		},
		"session": {
			Create: singleauth.DatabaseOperationHooks{After: plugin.afterSessionCreate},
		},
	})
}

func (plugin *compiledPlugin) beforeUserCreate(
	user storage.Record,
	ctx singleauth.DatabaseHookContext,
) (singleauth.DatabaseHookResult, error) {
	if ctx.Endpoint == nil {
		return singleauth.DatabaseHookResult{}, nil
	}
	method, err := plugin.resolve(ctx.Endpoint)
	if err != nil || method == "" {
		return singleauth.DatabaseHookResult{}, err
	}
	data := cloneRecord(user)
	data["lastLoginMethod"] = method
	return singleauth.DatabaseHookResult{Data: data}, nil
}

func (plugin *compiledPlugin) afterSessionCreate(
	value any,
	ctx singleauth.DatabaseHookContext,
) error {
	if ctx.Endpoint == nil {
		return nil
	}
	method, err := plugin.resolve(ctx.Endpoint)
	if err != nil || method == "" {
		return err
	}
	session, ok := value.(storage.Record)
	if !ok || session == nil {
		return nil
	}
	userID, _ := session["userId"].(string)
	if userID == "" {
		return nil
	}
	_, updateErr := plugin.runtime.Adapter.Update(ctx.Context, storage.UpdateParams{
		Model:  "user",
		Where:  []storage.Where{{Field: "id", Value: userID}},
		Update: storage.Record{"lastLoginMethod": method},
	})
	if updateErr != nil && plugin.runtime.Logger != nil {
		plugin.runtime.Logger.Error("Failed to update lastLoginMethod", updateErr)
	}
	return nil
}

func cloneRecord(source storage.Record) storage.Record {
	result := make(storage.Record, len(source)+1)
	for key, value := range source {
		result[key] = value
	}
	return result
}
