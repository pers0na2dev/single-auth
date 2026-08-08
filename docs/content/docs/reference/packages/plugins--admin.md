---
title: "github.com/pers0na2dev/single-auth/plugins/admin"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/admin.

- Import path: `github.com/pers0na2dev/single-auth/plugins/admin`
- Package name: `admin`

Package admin implements the single-auth 1.6.26 administration plugin.

## Constants

```go
const (
	ErrorFailedToCreateUser                   = "FAILED_TO_CREATE_USER"
	ErrorUserAlreadyExists                    = "USER_ALREADY_EXISTS"
	ErrorUserAlreadyExistsUseAnotherEmail     = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
	ErrorYouCannotBanYourself                 = "YOU_CANNOT_BAN_YOURSELF"
	ErrorNotAllowedToChangeUsersRole          = "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
	ErrorNotAllowedToCreateUsers              = "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS"
	ErrorNotAllowedToListUsers                = "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS"
	ErrorNotAllowedToListUsersSessions        = "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS"
	ErrorNotAllowedToBanUsers                 = "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"
	ErrorNotAllowedToImpersonateUsers         = "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS"
	ErrorNotAllowedToRevokeUsersSessions      = "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"
	ErrorNotAllowedToDeleteUsers              = "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS"
	ErrorNotAllowedToSetUsersPassword         = "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD"
	ErrorBannedUser                           = "BANNED_USER"
	ErrorNotAllowedToGetUser                  = "YOU_ARE_NOT_ALLOWED_TO_GET_USER"
	ErrorNoDataToUpdate                       = "NO_DATA_TO_UPDATE"
	ErrorNotAllowedToUpdateUsers              = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS"
	ErrorYouCannotRemoveYourself              = "YOU_CANNOT_REMOVE_YOURSELF"
	ErrorNotAllowedToSetNonExistentValue      = "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"
	ErrorYouCannotImpersonateAdmins           = "YOU_CANNOT_IMPERSONATE_ADMINS"
	ErrorInvalidRoleType                      = "INVALID_ROLE_TYPE"
	ErrorNotAllowedToSetUsersEmail            = "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL"
	ErrorPasswordCannotBeUpdatedViaUpdateUser = "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER"
)
```

```go
const (
	PluginID = "admin"
	Version  = "1.6.26"
)
```

```go
const DefaultBannedUserMessage = "You have been banned from this application. Please contact support if you believe this is an error."
```

## Variables

DefaultStatements is the frozen single-auth 1.6.26 admin vocabulary.

```go
var DefaultStatements = authorization.Statements{
	"user": {
		"create", "list", "set-role", "ban", "impersonate",
		"impersonate-admins", "delete", "set-password", "set-email",
		"get", "update",
	},
	"session": {"list", "revoke", "delete"},
}
```

## Functions

### `DefaultAccessControl`

DefaultAccessControl creates independent role values on every call.

```go
func DefaultAccessControl() (*authorization.AccessControl, map[string]*authorization.Role)
```

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots an admin plugin descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory contributes the admin fields before adapter creation and binds
every endpoint to the root session, secondary-storage, cookie, and password
services.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns the administration schema merged with custom overrides.

```go
func Schema(custom storage.Schema) (storage.Schema, error)
```

## Types

### `CreateUserInput`

CreateUserInput is the typed server-side admin create-user contract.

```go
type CreateUserInput struct {
	Name     string
	Email    string
	Password string
	Role     any
	Data     map[string]any
}
```

### `ErrorCodes`

ErrorCodes is the concrete admin contribution to auth.$ERROR_CODES.

```go
type ErrorCodes struct {
	UserAlreadyExists singleauth.ErrorCode
}
```

### `ListUsersInput`

ListUsersInput retains single-auth's search, filter, sort, limit, and offset
query fields.

```go
type ListUsersInput struct {
	SearchValue    string
	SearchField    string
	SearchOperator string
	FilterValue    []string
	FilterField    string
	FilterOperator string
	SortBy         string
	SortDirection  string
	Limit          *int
	Offset         *int
}
```

### `ListUsersResult`

```go
type ListUsersResult[Output any] struct {
	Users  []Output
	Total  int
	Limit  *int
	Offset *int
}
```

### `Options`

Options configures the single-auth administration plugin.

```go
type Options struct {
	DefaultRole                  string
	AdminRoles                   []string
	DefaultBanReason             string
	DefaultBanExpiresIn          time.Duration
	ImpersonationSessionDuration time.Duration
	Schema                       storage.Schema
	Roles                        map[string]*authorization.Role
	AdminUserIDs                 []string
	BannedUserMessage            string
	AllowImpersonatingAdmins     bool
	Runtime                      Runtime
}
```

### `Runtime`

Runtime contains the root services used by the plugin. NewFactory fills
this structure from singleauth.PluginHost. It remains public for focused
adapter and descriptor tests.

```go
type Runtime struct {
	Adapter           storage.Adapter
	AdapterForContext func(context.Context) storage.TransactionAdapter
	Clock             func() time.Time
	Secret            string

	ResolveSession   func(*engine.Context, bool) (*SessionState, error)
	CreateUser       func(*engine.Context, storage.Record) (storage.Record, error)
	ParseUserInput   func(*engine.Context, map[string]any) (storage.Record, error)
	SerializeUser    func(storage.Record) any
	SerializeSession func(storage.Record) any

	UpdateUser       func(*engine.Context, string, storage.Record) (storage.Record, error)
	DeleteUser       func(*engine.Context, string) error
	ListUserSessions func(context.Context, string, bool) ([]storage.Record, error)

	CreateSession  func(*engine.Context, string, bool, storage.Record) (*SessionState, error)
	RefreshSession func(*engine.Context, SessionState, bool) error
	FindSession    func(context.Context, string) (*SessionState, error)
	DeleteSession  func(context.Context, string) error
	RevokeSessions func(*engine.Context, string) error

	SetCredentialPassword func(*engine.Context, string, string) error
	HashPassword          func(*engine.Context, string) (string, error)
	MinPasswordLength     int
	MaxPasswordLength     int

	SessionCookie func(contract.Request) (string, cookies.Options)
	Cookie        func(contract.Request, string, string) (string, cookies.Options)

	RegisterDatabaseHooks func(singleauth.DatabaseHooks) error
}
```

### `SessionState`

SessionState is the transport-neutral session and user pair used by the
administration runtime.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `TypedAuth`

TypedAuth binds an initialized runtime to the factory's concrete output.

```go
type TypedAuth[Output any] struct {
	*singleauth.Auth
	// contains filtered or unexported fields
}
```

## Methods on `TypedAuth`

### `API`

```go
func (auth *TypedAuth[Output]) API() TypedDirectAPI[Output]
```

### `TypedDirectAPI`

TypedDirectAPI promotes the complete base API and adds concrete admin
endpoint methods.

```go
type TypedDirectAPI[Output any] struct {
	singleauth.DirectAPI
	// contains filtered or unexported fields
}
```

## Methods on `TypedDirectAPI`

### `CreateUser`

```go
func (api TypedDirectAPI[Output]) CreateUser(
	ctx context.Context,
	input CreateUserInput,
) (Output, error)
```

### `ListUsers`

```go
func (api TypedDirectAPI[Output]) ListUsers(
	ctx context.Context,
	input ListUsersInput,
) (ListUsersResult[Output], error)
```

### `TypedFactory`

TypedFactory preserves the configured admin user result type through factory
functions and options indirection while delegating runtime setup to NewFactory.

```go
type TypedFactory[Output any] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedFactory`

### `NewTypedFactory`

```go
func NewTypedFactory[Output any](options Options, decode ValueDecoder[Output]) *TypedFactory[Output]
```

## Methods on `TypedFactory`

### `BindAuth`

```go
func (factory *TypedFactory[Output]) BindAuth(auth *singleauth.Auth) (*TypedAuth[Output], error)
```

### `Build`

```go
func (factory *TypedFactory[Output]) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `ErrorCodes`

```go
func (factory *TypedFactory[Output]) ErrorCodes() singleauth.TypedErrorCodes[ErrorCodes]
```

### `PluginID`

```go
func (*TypedFactory[Output]) PluginID() string
```

### `Schema`

```go
func (factory *TypedFactory[Output]) Schema() (storage.Schema, error)
```

### `ValueDecoder`

ValueDecoder converts the lossless decoded direct-endpoint value into a
caller-defined user type.

```go
type ValueDecoder[Output any] func(any) (Output, error)
```

