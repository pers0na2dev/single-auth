---
title: "github.com/pers0na2dev/single-auth/plugins/scim"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/scim.

- Import path: `github.com/pers0na2dev/single-auth/plugins/scim`
- Package name: `scim`

Package scim implements the transport-neutral single-auth SCIM plugin.

The production surface includes single-auth 1.6.26 provider management,
token generation and storage, bearer-token authentication, SCIM user
creation and PATCH semantics, provider scoping, and SCIM error payloads.

## Constants

```go
const (
	Version = "1.6.26"

	EndpointPatchSCIMUser                = "patchSCIMUser"
	EndpointGenerateSCIMToken            = "generateSCIMToken"
	EndpointListSCIMProviderConnections  = "listSCIMProviderConnections"
	EndpointGetSCIMProviderConnection    = "getSCIMProviderConnection"
	EndpointDeleteSCIMProviderConnection = "deleteSCIMProviderConnection"
	EndpointCreateSCIMUser               = "createSCIMUser"
	EndpointListSCIMUsers                = "listSCIMUsers"
	EndpointGetSCIMUser                  = "getSCIMUser"
	EndpointUpdateSCIMUser               = "updateSCIMUser"
	EndpointDeleteSCIMUser               = "deleteSCIMUser"
	PatchOpSchema                        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	UserSchema                           = "urn:ietf:params:scim:schemas:core:2.0:User"
	ErrorSchema                          = "urn:ietf:params:scim:api:messages:2.0:Error"
)
```

## Functions

### `EncodeBearerToken`

EncodeBearerToken returns the RFC 4648 base64url token accepted by the SCIM
middleware. Organization IDs may contain colons.

```go
func EncodeBearerToken(secret, providerID, organizationID string) string
```

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs the transport-neutral SCIM plugin descriptor.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds SCIM persistence and user lifecycle operations to the root
single-auth runtime.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns the storage contribution used by the SCIM token middleware.

```go
func Schema(options Options) storage.Schema
```

## Types

### `CanGenerateTokenFunc`

CanGenerateTokenFunc applies an application-specific authorization gate
after the built-in organization and role checks.

```go
type CanGenerateTokenFunc func(context.Context, TokenGenerationPayload) (bool, error)
```

### `ErrorBody`

ErrorBody is the RFC 7644 error representation emitted by SCIM endpoints.

```go
type ErrorBody struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	SCIMType string   `json:"scimType,omitempty"`
}
```

### `ExistingUserLinkInput`

ExistingUserLinkInput describes an existing identity considered for an
explicit SCIM account link.

```go
type ExistingUserLinkInput struct {
	User           storage.Record
	Email          string
	ProviderID     string
	OrganizationID string
}
```

### `LinkExistingUsersOptions`

LinkExistingUsersOptions opts into linking a SCIM account to a user found by
email. The zero value rejects linking. When Enabled is true without further
constraints every matching existing user may be linked, matching the
provider boolean true option.

```go
type LinkExistingUsersOptions struct {
	Enabled                      bool
	TrustedDomains               []string
	RequireExistingOrgMembership bool
	ShouldLinkUser               func(context.Context, ExistingUserLinkInput) (bool, error)
}
```

### `Operation`

Operation is one SCIM PatchOp operation. Value retains JSON scalar/object
types, and Path accepts leading-slash and dot notation.

```go
type Operation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value"`
}
```

### `Options`

Options configures the SCIM production surface.

```go
type Options struct {
	ProviderOwnership        ProviderOwnership
	DefaultSCIM              []Provider
	RequiredRoles            []string
	CreatorRole              string
	ReservedProviderIDs      []string
	StoreSCIMToken           TokenStorage
	CanGenerateToken         CanGenerateTokenFunc
	BeforeSCIMTokenGenerated TokenGenerationHook
	AfterSCIMTokenGenerated  TokenGenerationHook
	LinkExistingUsers        LinkExistingUsersOptions
	VerifyToken              TokenVerifier
	Runtime                  Runtime
}
```

### `PatchRequest`

PatchRequest is the RFC 7644 PATCH User request body.

```go
type PatchRequest struct {
	Schemas    []string    `json:"schemas"`
	Operations []Operation `json:"Operations"`
}
```

### `PatchResources`

PatchResources contains the canonical single-auth user and account updates.

```go
type PatchResources struct {
	User    storage.Record
	Account storage.Record
}
```

## Constructors and functions for `PatchResources`

### `BuildUserPatch`

BuildUserPatch implements single-auth's SCIM user/account PatchOp mapping.
Unknown paths and remove operations produce no update, matching 1.6.26.

```go
func BuildUserPatch(user storage.Record, operations []Operation) (PatchResources, error)
```

### `Provider`

Provider is the token-bearing SCIM provider scope selected by middleware.

```go
type Provider struct {
	ID             string `json:"id"`
	ProviderID     string `json:"providerId"`
	SCIMToken      string `json:"scimToken,omitempty"`
	OrganizationID string `json:"organizationId,omitempty"`
	UserID         string `json:"userId,omitempty"`
}
```

### `ProviderOwnership`

ProviderOwnership controls the optional scimProvider.userId schema field.

```go
type ProviderOwnership struct {
	Enabled bool
}
```

### `Runtime`

Runtime contains the root services used by SCIM endpoints. NewFactory binds
these fields to single-auth automatically.

```go
type Runtime struct {
	Adapter                  storage.TransactionAdapter
	AdapterForContext        func(context.Context) storage.TransactionAdapter
	Random                   io.Reader
	EncryptSecret            func([]byte) (string, error)
	DecryptSecret            func(string) ([]byte, error)
	ReservedProviderID       func(string) bool
	UpdateUser               func(*engine.Context, string, storage.Record) (storage.Record, error)
	CreateUser               func(*engine.Context, storage.Record) (storage.Record, error)
	CreateAccount            func(context.Context, storage.Record) (storage.Record, error)
	DeleteUser               func(*engine.Context, string) error
	RevokeSessions           func(*engine.Context, string) error
	RemoveOrganizationMember func(
		context.Context,
		string,
		string,
		func(context.Context, storage.TransactionAdapter) error,
	) error
	HasPlugin func(string) bool
	Clock     func() time.Time
}
```

### `TokenGenerationHook`

TokenGenerationHook observes or rejects token generation. The after hook
receives SCIMProvider; the before hook receives nil in that field.

```go
type TokenGenerationHook func(context.Context, TokenGenerationPayload) error
```

### `TokenGenerationPayload`

TokenGenerationPayload is passed to authorization and lifecycle hooks.

```go
type TokenGenerationPayload struct {
	User           storage.Record
	Member         storage.Record
	ProviderID     string
	OrganizationID string
	SCIMToken      string
	SCIMProvider   *Provider
}
```

### `TokenStorage`

TokenStorage configures the persisted representation of generated tokens.
Hash is selected when non-nil. Encrypt and Decrypt must be supplied together.

```go
type TokenStorage struct {
	Mode    TokenStorageMode
	Hash    TokenTransform
	Encrypt TokenTransform
	Decrypt TokenTransform
}
```

### `TokenStorageMode`

TokenStorageMode selects how newly generated SCIM secrets are persisted.
The zero value is the single-auth default, plain-text storage.

```go
type TokenStorageMode string
```

## Constants associated with `TokenStorageMode`

```go
const (
	TokenStoragePlain     TokenStorageMode = "plain"
	TokenStorageHashed    TokenStorageMode = "hashed"
	TokenStorageEncrypted TokenStorageMode = "encrypted"
)
```

### `TokenTransform`

TokenTransform mirrors single-auth's custom hash/encrypt/decrypt callbacks.

```go
type TokenTransform func(context.Context, string) (string, error)
```

### `TokenVerifier`

TokenVerifier compares a persisted SCIM token with the presented secret.
Applications using hashed or encrypted persistence can supply their own
verifier; nil uses a constant-time plain-text comparison.

```go
type TokenVerifier func(context.Context, string, string) (bool, error)
```

