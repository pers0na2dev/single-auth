package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type plugin struct {
	options Options
	schema  storage.Schema
	clock   func() time.Time
}

// NewFactory contributes the admin fields before adapter creation and binds
// every endpoint to the root session, secondary-storage, cookie, and password
// services.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return PluginID }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return Schema(factory.options.Schema)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	options.Runtime.Adapter = host.Adapter
	options.Runtime.AdapterForContext = host.AdapterForContext
	options.Runtime.Clock = host.Clock
	options.Runtime.Secret = host.Secret
	options.Runtime.ResolveSession = func(ctx *engine.Context, authoritative bool) (*SessionState, error) {
		mode := singleauth.PluginSessionRequired
		if authoritative {
			mode = singleauth.PluginSessionAuthoritative
		}
		state, err := host.ResolveSession(ctx, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.CreateUser = host.CreateUser
	options.Runtime.ParseUserInput = host.ParseUserInput
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.SerializeSession = host.SerializeSession
	options.Runtime.UpdateUser = host.UpdateUser
	options.Runtime.DeleteUser = host.DeleteUser
	options.Runtime.ListUserSessions = host.ListUserSessions
	options.Runtime.CreateSession = func(ctx *engine.Context, userID string, dontRemember bool, data storage.Record) (*SessionState, error) {
		state, err := host.CreateSessionWithData(ctx, userID, dontRemember, data)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.RefreshSession = func(ctx *engine.Context, state SessionState, dontRemember bool) error {
		return host.RefreshSession(ctx, singleauth.PluginSessionState{Session: state.Session, User: state.User}, dontRemember)
	}
	options.Runtime.FindSession = func(ctx context.Context, token string) (*SessionState, error) {
		state, err := host.FindSession(ctx, token)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.DeleteSession = host.DeleteSession
	options.Runtime.RevokeSessions = host.RevokeSessions
	options.Runtime.SetCredentialPassword = host.SetCredentialPassword
	options.Runtime.HashPassword = host.HashPassword
	options.Runtime.MinPasswordLength = host.Options.EmailAndPassword.MinPasswordLength
	options.Runtime.MaxPasswordLength = host.Options.EmailAndPassword.MaxPasswordLength
	options.Runtime.SessionCookie = host.SessionCookie
	options.Runtime.Cookie = host.Cookie
	options.Runtime.RegisterDatabaseHooks = host.RegisterDatabaseHooks
	return New(options)
}

// New validates and snapshots an admin plugin descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	if implementation.options.Runtime.RegisterDatabaseHooks != nil {
		if err := implementation.options.Runtime.RegisterDatabaseHooks(implementation.databaseHooks()); err != nil {
			return engine.Plugin{}, fmt.Errorf("admin: register database hooks: %w", err)
		}
	}
	return implementation.descriptor(), nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	descriptor, err := New(options)
	if err != nil {
		panic(err)
	}
	return descriptor
}

func normalize(input Options) (*plugin, error) {
	adminRolesConfigured := input.AdminRoles != nil
	options := snapshotOptions(input)
	if options.DefaultRole == "" {
		options.DefaultRole = "user"
	}
	if options.AdminRoles == nil {
		options.AdminRoles = []string{"admin"}
	}
	if options.BannedUserMessage == "" {
		options.BannedUserMessage = DefaultBannedUserMessage
	}
	if options.ImpersonationSessionDuration == 0 {
		options.ImpersonationSessionDuration = time.Hour
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Secret == "" {
		options.Runtime.Secret = "single-auth-secret-123456789"
	}
	if adminRolesConfigured && options.Roles != nil {
		known := make(map[string]struct{}, len(options.Roles))
		for name := range options.Roles {
			known[strings.ToLower(name)] = struct{}{}
		}
		invalid := make([]string, 0)
		for _, role := range options.AdminRoles {
			if _, ok := known[strings.ToLower(role)]; !ok {
				invalid = append(invalid, role)
			}
		}
		if len(invalid) != 0 {
			return nil, fmt.Errorf("Invalid admin roles: %s. Admin roles must be defined in the 'roles' configuration.", strings.Join(invalid, ", "))
		}
	} else if adminRolesConfigured {
		_, defaults := DefaultAccessControl()
		for _, role := range options.AdminRoles {
			found := false
			for name := range defaults {
				if strings.EqualFold(name, role) {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("Invalid admin roles: %s. Admin roles must be defined in the 'roles' configuration.", role)
			}
		}
	}
	schema, err := Schema(options.Schema)
	if err != nil {
		return nil, err
	}
	installRuntimeFallbacks(&options)
	return &plugin{options: options, schema: schema, clock: options.Runtime.Clock}, nil
}

func snapshotOptions(source Options) Options {
	result := source
	if source.AdminRoles != nil {
		result.AdminRoles = append([]string{}, source.AdminRoles...)
	}
	if source.AdminUserIDs != nil {
		result.AdminUserIDs = append([]string{}, source.AdminUserIDs...)
	}
	result.Roles = cloneRoles(source.Roles)
	result.Schema = source.Schema.Clone()
	return result
}

func installRuntimeFallbacks(options *Options) {
	runtime := &options.Runtime
	if runtime.AdapterForContext == nil {
		runtime.AdapterForContext = func(context.Context) storage.TransactionAdapter { return runtime.Adapter }
	}
	if runtime.ParseUserInput == nil {
		runtime.ParseUserInput = func(_ *engine.Context, input map[string]any) (storage.Record, error) {
			return cloneRecord(storage.Record(input)), nil
		}
	}
	if runtime.SerializeUser == nil {
		runtime.SerializeUser = func(record storage.Record) any { return cloneRecord(record) }
	}
	if runtime.SerializeSession == nil {
		runtime.SerializeSession = func(record storage.Record) any { return cloneRecord(record) }
	}
	if runtime.Adapter != nil {
		if runtime.CreateUser == nil {
			runtime.CreateUser = func(ctx *engine.Context, data storage.Record) (storage.Record, error) {
				return runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "user", Data: data})
			}
		}
		if runtime.UpdateUser == nil {
			runtime.UpdateUser = func(ctx *engine.Context, id string, update storage.Record) (storage.Record, error) {
				return runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
					Model: "user", Where: []storage.Where{{Field: "id", Value: id}}, Update: update,
				})
			}
		}
		if runtime.DeleteUser == nil {
			runtime.DeleteUser = func(ctx *engine.Context, id string) error {
				return runtime.Adapter.Delete(ctx.GoContext(), storage.DeleteParams{
					Model: "user", Where: []storage.Where{{Field: "id", Value: id}},
				})
			}
		}
		if runtime.ListUserSessions == nil {
			runtime.ListUserSessions = func(ctx context.Context, id string, active bool) ([]storage.Record, error) {
				where := []storage.Where{{Field: "userId", Value: id}}
				if active {
					where = append(where, storage.Where{Field: "expiresAt", Value: runtime.Clock(), Operator: storage.OpGt})
				}
				return runtime.Adapter.FindMany(ctx, storage.FindManyParams{Model: "session", Where: where})
			}
		}
		if runtime.FindSession == nil {
			runtime.FindSession = func(ctx context.Context, token string) (*SessionState, error) {
				session, err := runtime.Adapter.FindOne(ctx, storage.FindOneParams{Model: "session", Where: []storage.Where{{Field: "token", Value: token}}})
				if err != nil || session == nil {
					return nil, err
				}
				userID, _ := recordString(session, "userId")
				user, err := runtime.Adapter.FindOne(ctx, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}})
				if err != nil || user == nil {
					return nil, err
				}
				return &SessionState{Session: session, User: user}, nil
			}
		}
		if runtime.DeleteSession == nil {
			runtime.DeleteSession = func(ctx context.Context, token string) error {
				return runtime.Adapter.Delete(ctx, storage.DeleteParams{Model: "session", Where: []storage.Where{{Field: "token", Value: token}}})
			}
		}
		if runtime.RevokeSessions == nil {
			runtime.RevokeSessions = func(ctx *engine.Context, userID string) error {
				_, err := runtime.Adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{Model: "session", Where: []storage.Where{{Field: "userId", Value: userID}}})
				return err
			}
		}
	}
}

func (p *plugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: p.schema.Clone(),
		Endpoints: []engine.Endpoint{
			endpoint("setRole", "/admin/set-role", "POST", "setUserRole", p.setRole),
			endpoint("getUser", "/admin/get-user", "GET", "getUser", p.getUser),
			endpoint("createUser", "/admin/create-user", "POST", "createUser", p.createUser),
			endpoint("adminUpdateUser", "/admin/update-user", "POST", "adminUpdateUser", p.updateUser),
			endpoint("listUsers", "/admin/list-users", "GET", "listUsers", p.listUsers),
			endpoint("listUserSessions", "/admin/list-user-sessions", "POST", "adminListUserSessions", p.listUserSessions),
			endpoint("unbanUser", "/admin/unban-user", "POST", "unbanUser", p.unbanUser),
			endpoint("banUser", "/admin/ban-user", "POST", "banUser", p.banUser),
			endpoint("impersonateUser", "/admin/impersonate-user", "POST", "impersonateUser", p.impersonateUser),
			endpoint("stopImpersonating", "/admin/stop-impersonating", "POST", "stopImpersonating", p.stopImpersonating),
			endpoint("revokeUserSession", "/admin/revoke-user-session", "POST", "revokeUserSession", p.revokeUserSession),
			endpoint("revokeUserSessions", "/admin/revoke-user-sessions", "POST", "revokeUserSessions", p.revokeUserSessions),
			endpoint("removeUser", "/admin/remove-user", "POST", "removeUser", p.removeUser),
			endpoint("setUserPassword", "/admin/set-user-password", "POST", "setUserPassword", p.setUserPassword),
			endpoint("userHasPermission", "/admin/has-permission", "POST", "userHasPermission", p.userHasPermission),
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    "admin-filter-impersonated-sessions",
			Matcher: func(ctx *engine.Context) (bool, error) { return ctx != nil && ctx.Path() == "/list-sessions", nil },
			Handler: p.filterImpersonatedSessions,
		}}},
		ErrorCodes: pluginErrorCodes(),
	}
}

func endpoint(name, path, method, operationID string, handler engine.HandlerFunc) engine.Endpoint {
	return engine.Endpoint{
		Name: name, Path: path, Methods: []string{method}, OperationID: operationID, Handler: handler,
		Metadata: map[string]any{"openapi": map[string]any{"operationId": operationID}},
	}
}

func (p *plugin) databaseHooks() singleauth.DatabaseHooks {
	return singleauth.DatabaseHooks{
		"user":    {Create: singleauth.DatabaseOperationHooks{Before: p.beforeUserCreate}},
		"session": {Create: singleauth.DatabaseOperationHooks{Before: p.beforeSessionCreate}},
	}
}

func (p *plugin) beforeUserCreate(data storage.Record, _ singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
	if _, exists := data["role"]; exists {
		return singleauth.DatabaseHookResult{}, nil
	}
	return singleauth.DatabaseHookResult{Data: storage.Record{"role": p.options.DefaultRole}}, nil
}

func (p *plugin) beforeSessionCreate(data storage.Record, hook singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
	userID, ok := recordString(data, "userId")
	if !ok || userID == "" || p.options.Runtime.AdapterForContext == nil {
		return singleauth.DatabaseHookResult{}, nil
	}
	adapter := p.options.Runtime.AdapterForContext(hook.Context)
	if adapter == nil {
		return singleauth.DatabaseHookResult{}, nil
	}
	user, err := adapter.FindOne(hook.Context, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}})
	if err != nil || user == nil || !recordBool(user, "banned") {
		return singleauth.DatabaseHookResult{}, err
	}
	if expiresAt, exists := recordTime(user, "banExpires"); exists && expiresAt.Before(p.clock()) {
		_, err = adapter.Update(hook.Context, storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
			Update: storage.Record{"banned": false, "banReason": nil, "banExpires": nil},
		})
		return singleauth.DatabaseHookResult{}, err
	}
	return singleauth.DatabaseHookResult{}, contract.NewAPIError(
		contract.StatusForbidden, ErrorBannedUser, p.options.BannedUserMessage,
	)
}

func (p *plugin) filterImpersonatedSessions(_ *engine.Context, response contract.Response) (*contract.Response, error) {
	if response.Status() != contract.StatusOK {
		return nil, nil
	}
	var sessions []map[string]any
	if err := json.Unmarshal(response.Body(), &sessions); err != nil {
		return nil, nil
	}
	filtered := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		value, exists := session["impersonatedBy"]
		if exists && value != nil && value != "" {
			continue
		}
		filtered = append(filtered, session)
	}
	rewritten, err := contract.JSONResponse(response.Status(), filtered)
	if err != nil {
		return nil, err
	}
	rewritten = rewritten.WithHeaders(response.Headers())
	return &rewritten, nil
}
