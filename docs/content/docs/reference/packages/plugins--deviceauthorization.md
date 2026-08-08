---
title: "github.com/pers0na2dev/single-auth/plugins/deviceauthorization"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/deviceauthorization.

- Import path: `github.com/pers0na2dev/single-auth/plugins/deviceauthorization`
- Package name: `deviceauthorization`

Package deviceauthorization implements single-auth 1.6.26's RFC 8628
device-authorization plugin for direct calls, net/http, fasthttp, and Fiber.

## Constants

```go
const (
	MessageInvalidDeviceCode       = "Invalid device code"
	MessageExpiredDeviceCode       = "Device code has expired"
	MessageExpiredUserCode         = "User code has expired"
	MessageAuthorizationPending    = "Authorization pending"
	MessageAccessDenied            = "Access denied"
	MessageInvalidUserCode         = "Invalid user code"
	MessageAlreadyProcessed        = "Device code already processed"
	MessageDeviceCodeNotClaimed    = "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying"
	MessagePollingTooFrequently    = "Polling too frequently"
	MessageUserNotFound            = "User not found"
	MessageFailedToCreateSession   = "Failed to create session"
	MessageInvalidDeviceCodeStatus = "Invalid device code status"
	MessageAuthenticationRequired  = "Authentication required"
)
```

```go
const (
	PluginID = "device-authorization"
	Version  = "1.6.26"

	DeviceCodePath    = "/device/code"
	DeviceTokenPath   = "/device/token"
	DeviceVerifyPath  = "/device"
	DeviceApprovePath = "/device/approve"
	DeviceDenyPath    = "/device/deny"

	DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)
```

## Functions

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs a transport-neutral plugin descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds device authorization to the final root storage, session,
secondary-storage, and dynamic base-URL semantics.

```go
func NewFactory(options ...Options) singleauth.PluginFactory
```

### `Schema`

Schema returns an independent copy of single-auth 1.6.26's deviceCode
model. The model deliberately has no user relation in the frozen upstream.

```go
func Schema() storage.Schema
```

## Types

### `BaseURLResolver`

```go
type BaseURLResolver func(*engine.Context) (string, error)
```

### `ContextAdapterResolver`

```go
type ContextAdapterResolver func(context.Context) storage.TransactionAdapter
```

### `CreateSessionFunc`

```go
type CreateSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
```

### `DeviceAuthRequestFunc`

```go
type DeviceAuthRequestFunc func(context.Context, string, *string) error
```

### `DeviceCode`

DeviceCode is the persisted RFC 8628 authorization state.

```go
type DeviceCode struct {
	ID              string
	DeviceCode      string
	UserCode        string
	UserID          *string
	ExpiresAt       time.Time
	Status          string
	LastPolledAt    *time.Time
	PollingInterval int64
	ClientID        string
	Scope           *string
}
```

### `DeviceCodeResponse`

DeviceCodeResponse is returned from POST /device/code.

```go
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}
```

### `GenerateCodeFunc`

```go
type GenerateCodeFunc func(context.Context) (string, error)
```

### `OAuthErrorBody`

OAuthErrorBody is the RFC-compatible error representation.

```go
type OAuthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
```

### `Options`

Options configures single-auth's device-authorization plugin. Zero duration
and length values select the upstream defaults.

```go
type Options struct {
	ExpiresIn        time.Duration
	Interval         time.Duration
	DeviceCodeLength int
	UserCodeLength   int

	GenerateDeviceCode  GenerateCodeFunc
	GenerateUserCode    GenerateCodeFunc
	ValidateClient      ValidateClientFunc
	OnDeviceAuthRequest DeviceAuthRequestFunc
	VerificationURI     string

	Schema  storage.Schema
	Runtime Runtime
}
```

## Constructors and functions for `Options`

### `NormalizeOptions`

NormalizeOptions applies the frozen upstream defaults and validates values
representable by Go's typed option surface.

```go
func NormalizeOptions(input Options) (Options, error)
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context, bool) (*SessionState, error)
```

### `Runtime`

Runtime contains dependencies that single-auth injects into endpoint
context. NewFactory supplies the root session, secondary-storage, dynamic
URL, and transaction-aware adapter behavioral compatibility.

```go
type Runtime struct {
	Adapter           storage.Adapter
	AdapterForContext ContextAdapterResolver
	Clock             func() time.Time
	Random            io.Reader
	BaseURL           string
	ResolveBaseURL    BaseURLResolver
	ResolveSession    ResolveSessionFunc
	CreateSession     CreateSessionFunc
	SetNewSession     SetNewSessionFunc
}
```

### `SessionState`

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `SetNewSessionFunc`

```go
type SetNewSessionFunc func(*engine.Context, *SessionState)
```

### `TokenResponse`

TokenResponse is the OAuth 2.0 token response for an approved code.

```go
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}
```

### `ValidateClientFunc`

```go
type ValidateClientFunc func(context.Context, string) (bool, error)
```

### `VerifyResponse`

VerifyResponse is returned while displaying device authorization state.

```go
type VerifyResponse struct {
	UserCode string `json:"user_code"`
	Status   string `json:"status"`
}
```

