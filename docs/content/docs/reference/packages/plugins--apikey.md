---
title: "github.com/pers0na2dev/single-auth/plugins/apikey"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/apikey.

- Import path: `github.com/pers0na2dev/single-auth/plugins/apikey`
- Package name: `apikey`

Package apikey implements the single-auth API-key plugin contract.

## Constants

```go
const (
	ErrorInvalidMetadataType               = "INVALID_METADATA_TYPE"
	ErrorMetadataDisabled                  = "METADATA_DISABLED"
	ErrorRefillAmountAndIntervalRequired   = "REFILL_AMOUNT_AND_INTERVAL_REQUIRED"
	ErrorRefillIntervalAndAmountRequired   = "REFILL_INTERVAL_AND_AMOUNT_REQUIRED"
	ErrorUnauthorizedSession               = "UNAUTHORIZED_SESSION"
	ErrorKeyNotFound                       = "KEY_NOT_FOUND"
	ErrorKeyDisabled                       = "KEY_DISABLED"
	ErrorKeyExpired                        = "KEY_EXPIRED"
	ErrorInvalidPrefixLength               = "INVALID_PREFIX_LENGTH"
	ErrorInvalidNameLength                 = "INVALID_NAME_LENGTH"
	ErrorInvalidAPIKey                     = "INVALID_API_KEY"
	ErrorServerOnlyProperty                = "SERVER_ONLY_PROPERTY"
	ErrorNameRequired                      = "NAME_REQUIRED"
	ErrorKeyDisabledExpiration             = "KEY_DISABLED_EXPIRATION"
	ErrorExpiresInTooSmall                 = "EXPIRES_IN_IS_TOO_SMALL"
	ErrorExpiresInTooLarge                 = "EXPIRES_IN_IS_TOO_LARGE"
	ErrorNoValuesToUpdate                  = "NO_VALUES_TO_UPDATE"
	ErrorUsageExceeded                     = "USAGE_EXCEEDED"
	ErrorRateLimited                       = "RATE_LIMITED"
	ErrorInvalidReferenceID                = "INVALID_REFERENCE_ID_FROM_API_KEY"
	ErrorOrganizationIDRequired            = "ORGANIZATION_ID_REQUIRED"
	ErrorUserNotMemberOfOrganization       = "USER_NOT_MEMBER_OF_ORGANIZATION"
	ErrorInsufficientAPIKeyPermissions     = "INSUFFICIENT_API_KEY_PERMISSIONS"
	ErrorNoDefaultAPIKeyConfigurationFound = "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND"
	ErrorOrganizationPluginRequired        = "ORGANIZATION_PLUGIN_REQUIRED"
)
```

```go
const Version = "1.6.26"
```

## Functions

### `Bool`

Bool returns a pointer suitable for tri-state configuration fields where nil
means to use single-auth's default.

```go
func Bool(value bool) *bool
```

### `HashKey`

HashKey returns single-auth's SHA-256 base64url-without-padding key hash.

```go
func HashKey(key string) string
```

### `MustNew`

MustNew is New for static standalone setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs a standalone engine plugin from explicit runtime services.

```go
func New(options Options) (engine.Plugin, error)
```

### `Schema`

Schema returns the canonical single-auth API-key storage extension.

```go
func Schema(options Options) (storage.Schema, error)
```

## Types

### `APIKey`

APIKey is the complete persisted API-key record. Key contains the plaintext
credential only in Create's return value and is omitted from read/list/verify
responses.

```go
type APIKey struct {
	ID                  string              `json:"id"`
	ConfigID            string              `json:"configId"`
	Name                *string             `json:"name"`
	Start               *string             `json:"start"`
	Prefix              *string             `json:"prefix"`
	Key                 string              `json:"key,omitempty"`
	ReferenceID         string              `json:"referenceId"`
	RefillInterval      *int64              `json:"refillInterval"`
	RefillAmount        *int64              `json:"refillAmount"`
	LastRefillAt        *time.Time          `json:"lastRefillAt"`
	Enabled             bool                `json:"enabled"`
	RateLimitEnabled    bool                `json:"rateLimitEnabled"`
	RateLimitTimeWindow *int64              `json:"rateLimitTimeWindow"`
	RateLimitMax        *int64              `json:"rateLimitMax"`
	RequestCount        int64               `json:"requestCount"`
	Remaining           *int64              `json:"remaining"`
	LastRequest         *time.Time          `json:"lastRequest"`
	ExpiresAt           *time.Time          `json:"expiresAt"`
	CreatedAt           time.Time           `json:"createdAt"`
	UpdatedAt           time.Time           `json:"updatedAt"`
	Metadata            any                 `json:"metadata"`
	Permissions         map[string][]string `json:"permissions"`
}
```

### `Configuration`

Configuration is one named API-key configuration. ConfigID is required
when more than one configuration is installed.

```go
type Configuration struct {
	ConfigID                 string
	References               ReferenceType
	DefaultPrefix            string
	DefaultKeyLength         int
	MinimumPrefixLength      int
	MaximumPrefixLength      int
	MinimumNameLength        int
	MaximumNameLength        int
	RequireName              bool
	EnableMetadata           bool
	DisableKeyHashing        bool
	StoreStartingCharacters  *bool
	StartingCharactersLength int
	RateLimitEnabled         *bool
	RateLimitTimeWindow      time.Duration
	RateLimitMax             int64
	DefaultExpiresIn         time.Duration
	DisableCustomExpiresTime bool
	MinimumExpiresIn         time.Duration
	MaximumExpiresIn         time.Duration
	DefaultPermissions       map[string][]string
	EnableSessionForAPIKeys  bool
	APIKeyHeaders            []string
}
```

### `CreateInput`

CreateInput contains both trusted server ownership and request actor fields.
ActorUserID represents the authenticated session user; UserID is accepted by
direct server calls.

```go
type CreateInput struct {
	ConfigID            string
	Name                *string
	Prefix              string
	ExpiresIn           *time.Duration
	Remaining           *int64
	RefillAmount        *int64
	RefillInterval      *time.Duration
	Metadata            any
	Permissions         map[string][]string
	RateLimitMax        *int64
	RateLimitTimeWindow *time.Duration
	RateLimitEnabled    *bool
	UserID              string
	OrganizationID      string
	ActorUserID         string
}
```

### `DeleteInput`

```go
type DeleteInput struct {
	KeyID       string
	ConfigID    string
	ActorUserID string
}
```

### `ErrorBody`

ErrorBody is the stable client-facing API-key error representation.

```go
type ErrorBody struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}
```

### `GetInput`

```go
type GetInput struct {
	ID          string
	ConfigID    string
	ActorUserID string
}
```

### `ListInput`

```go
type ListInput struct {
	ConfigID       string
	OrganizationID string
	ActorUserID    string
	Limit          *int
	Offset         *int
}
```

### `ListResult`

```go
type ListResult struct {
	APIKeys []APIKey `json:"apiKeys"`
	Total   int      `json:"total"`
	Limit   *int     `json:"limit,omitempty"`
	Offset  *int     `json:"offset,omitempty"`
}
```

### `Options`

Options configures the API-key service and root plugin factory.

```go
type Options struct {
	Configurations       []Configuration
	Organization         OrganizationAuthorization
	Schema               storage.Schema
	Runtime              Runtime
	DeleteExpiredOnWrite bool
}
```

### `OrganizationAuthorization`

OrganizationAuthorization configures the organization role vocabulary used
by this plugin. The creator role always receives all API-key permissions,
matching single-auth's allowCreatorAllPermissions behavioral compatibility.

```go
type OrganizationAuthorization struct {
	CreatorRole string
	Roles       map[string]authorization.Statements
}
```

### `PermissionAction`

PermissionAction is the organization permission checked for an API-key
operation.

```go
type PermissionAction string
```

## Constants associated with `PermissionAction`

```go
const (
	PermissionCreate PermissionAction = "create"
	PermissionRead   PermissionAction = "read"
	PermissionUpdate PermissionAction = "update"
	PermissionDelete PermissionAction = "delete"
)
```

### `Plugin`

Plugin is a reusable factory plus the bound direct API. A Plugin instance
belongs to one single-auth runtime.

```go
type Plugin struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Plugin`

### `MustNewFactory`

MustNewFactory is NewFactory for declarative application setup.

```go
func MustNewFactory(options Options) *Plugin
```

### `NewFactory`

NewFactory returns a reusable API-key plugin factory.

```go
func NewFactory(options Options) *Plugin
```

## Methods on `Plugin`

### `Build`

```go
func (plugin *Plugin) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `Create`

```go
func (plugin *Plugin) Create(ctx context.Context, input CreateInput) (APIKey, error)
```

### `Delete`

```go
func (plugin *Plugin) Delete(ctx context.Context, input DeleteInput) error
```

### `Get`

```go
func (plugin *Plugin) Get(ctx context.Context, input GetInput) (APIKey, error)
```

### `List`

```go
func (plugin *Plugin) List(ctx context.Context, input ListInput) (ListResult, error)
```

### `PluginID`

```go
func (*Plugin) PluginID() string
```

### `Schema`

```go
func (plugin *Plugin) Schema() (storage.Schema, error)
```

### `Update`

```go
func (plugin *Plugin) Update(ctx context.Context, input UpdateInput) (APIKey, error)
```

### `Verify`

```go
func (plugin *Plugin) Verify(ctx context.Context, input VerifyInput) (VerifyResult, error)
```

### `ReferenceType`

ReferenceType determines whether a configuration's keys belong to a user
or to an organization.

```go
type ReferenceType string
```

## Constants associated with `ReferenceType`

```go
const (
	ReferenceUser         ReferenceType = "user"
	ReferenceOrganization ReferenceType = "organization"
)
```

### `ResolveSessionFunc`

ResolveSessionFunc resolves a session for a plugin endpoint. A nil state is
treated as an unauthorized request.

```go
type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
```

### `Runtime`

Runtime contains host-provided services. It is public so applications can
construct the production service without the root plugin registry.

```go
type Runtime struct {
	Adapter                     storage.Adapter
	Clock                       func() time.Time
	Random                      io.Reader
	KeyGenerator                func(context.Context, int, string) (string, error)
	ResolveSession              ResolveSessionFunc
	ResolveAuthoritativeSession ResolveSessionFunc
	HasPlugin                   func(string) bool
	SerializeUser               func(storage.Record) any
	SerializeSession            func(storage.Record) any
}
```

### `Service`

Service implements the database-backed API-key operations shared by direct
calls and transport endpoints.

```go
type Service struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Service`

### `NewService`

NewService validates options and constructs the production API-key service.

```go
func NewService(options Options) (*Service, error)
```

## Methods on `Service`

### `Create`

Create mints and persists a user- or organization-owned API key.

```go
func (service *Service) Create(ctx context.Context, input CreateInput) (APIKey, error)
```

### `Delete`

Delete removes an API key after ownership and delete-permission checks.

```go
func (service *Service) Delete(ctx context.Context, input DeleteInput) error
```

### `Get`

Get returns one key after configuration, ownership, and organization ACL checks.

```go
func (service *Service) Get(ctx context.Context, input GetInput) (APIKey, error)
```

### `List`

List returns only user keys or only organization keys depending on whether
OrganizationID is present, matching single-auth's ownership separation.

```go
func (service *Service) List(ctx context.Context, input ListInput) (ListResult, error)
```

### `Update`

Update changes an API key after ownership and update-permission checks.

```go
func (service *Service) Update(ctx context.Context, input UpdateInput) (APIKey, error)
```

### `Verify`

Verify validates a plaintext credential and returns its owner/configuration
metadata without disclosing the stored hash.

```go
func (service *Service) Verify(ctx context.Context, input VerifyInput) VerifyResult
```

### `SessionState`

SessionState is the request's authoritative user/session pair.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `UpdateInput`

```go
type UpdateInput struct {
	KeyID               string
	ConfigID            string
	ActorUserID         string
	Name                *string
	Enabled             *bool
	ExpiresIn           *time.Duration
	ExpiresInSet        bool
	Remaining           *int64
	RefillAmount        *int64
	RefillInterval      *time.Duration
	Metadata            any
	MetadataSet         bool
	RateLimitEnabled    *bool
	RateLimitTimeWindow *time.Duration
	RateLimitMax        *int64
	Permissions         map[string][]string
	PermissionsSet      bool
}
```

### `VerifyInput`

```go
type VerifyInput struct {
	Key         string
	ConfigID    string
	Permissions map[string][]string
}
```

### `VerifyResult`

```go
type VerifyResult struct {
	Valid bool       `json:"valid"`
	Error *ErrorBody `json:"error"`
	Key   *APIKey    `json:"key"`
}
```

