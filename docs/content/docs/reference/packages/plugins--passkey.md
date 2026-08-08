---
title: "github.com/pers0na2dev/single-auth/plugins/passkey"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/passkey.

- Import path: `github.com/pers0na2dev/single-auth/plugins/passkey`
- Package name: `passkey`

Package passkey implements the single-auth 1.6.26 passkey server plugin.

The package is transport neutral. Its endpoints are engine endpoints, so the
same plugin works through single-auth's net/http, fasthttp, and Fiber
adapters. Browser calls to navigator.credentials remain client concerns.

## Constants

```go
const (
	ErrorChallengeNotFound          = "CHALLENGE_NOT_FOUND"
	ErrorRegistrationNotAllowed     = "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
	ErrorFailedToVerifyRegistration = "FAILED_TO_VERIFY_REGISTRATION"
	ErrorPasskeyNotFound            = "PASSKEY_NOT_FOUND"
	ErrorAuthenticationFailed       = "AUTHENTICATION_FAILED"
	ErrorUnableToCreateSession      = "UNABLE_TO_CREATE_SESSION"
	ErrorFailedToUpdatePasskey      = "FAILED_TO_UPDATE_PASSKEY"
	ErrorPreviouslyRegistered       = "PREVIOUSLY_REGISTERED"
	ErrorRegistrationCancelled      = "REGISTRATION_CANCELLED"
	ErrorAuthenticationCancelled    = "AUTH_CANCELLED"
	ErrorUnknown                    = "UNKNOWN_ERROR"
	ErrorSessionRequired            = "SESSION_REQUIRED"
	ErrorResolveUserRequired        = "RESOLVE_USER_REQUIRED"
	ErrorResolvedUserInvalid        = "RESOLVED_USER_INVALID"
)
```

```go
const (
	Version = "1.6.26"
)
```

## Variables

CommonAuthenticatorNames is single-auth's intentionally small best-effort
AAGUID map. Callers may copy or extend it for UI labeling.

```go
var CommonAuthenticatorNames = map[string]string{
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
	"b78a0a55-6ef8-d246-a042-ba0f6d55050c": "LastPass",
	"b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
	"50726f74-6f6e-5061-7373-50726f746f6e": "Proton Pass",
	"0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Keeper",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
}
```

## Functions

### `Bool`

Bool returns a pointer for options whose omitted and false states differ.

```go
func Bool(value bool) *bool
```

### `GetAuthenticatorName`

GetAuthenticatorName resolves a normalized non-anonymous AAGUID.

```go
func GetAuthenticatorName(aaguid string) (string, bool)
```

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a single-auth passkey plugin.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds passkey persistence, sessions, cryptographic material, and
cookie policy to the final single-auth runtime during New.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns an independent copy of the upstream passkey model schema.

```go
func Schema() storage.Schema
```

## Types

### `AdvancedOptions`

```go
type AdvancedOptions struct {
	// WebAuthnChallengeCookie is the createAuthCookie key. It defaults to
	// "single-auth-passkey" and is prefixed by CookiePrefix.
	WebAuthnChallengeCookie string
	CookiePrefix            string
	ChallengeCookie         *ChallengeCookie
}
```

### `AfterAuthenticationVerificationArgs`

```go
type AfterAuthenticationVerificationArgs struct {
	Context      *engine.Context
	Verification webauthn.VerifiedAuthenticationResponse
	ClientData   webauthn.AuthenticationResponseJSON
}
```

### `AfterAuthenticationVerificationFunc`

```go
type AfterAuthenticationVerificationFunc func(AfterAuthenticationVerificationArgs) error
```

### `AfterRegistrationVerificationArgs`

```go
type AfterRegistrationVerificationArgs struct {
	Context      *engine.Context
	Verification webauthn.VerifiedRegistrationResponse
	User         RegistrationUser
	ClientData   webauthn.RegistrationResponseJSON
	FlowContext  *string
}
```

### `AfterRegistrationVerificationFunc`

```go
type AfterRegistrationVerificationFunc func(AfterRegistrationVerificationArgs) (AfterRegistrationVerificationResult, error)
```

### `AfterRegistrationVerificationResult`

AfterRegistrationVerificationResult optionally reassigns the credential and
supplies a label. Empty values mean no override, matching upstream truthiness.

```go
type AfterRegistrationVerificationResult struct {
	UserID string
	Name   string
}
```

### `AuthenticationOptions`

```go
type AuthenticationOptions struct {
	Extensions        map[string]any
	ResolveExtensions ExtensionsResolver
	AfterVerification AfterAuthenticationVerificationFunc
}
```

### `AuthenticationVerifier`

```go
type AuthenticationVerifier func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error)
```

### `ChallengeCookie`

ChallengeCookie is the fully resolved cookie dependency. When omitted, New
derives single-auth's default cookie from BaseURL and Advanced options.

```go
type ChallengeCookie struct {
	Name       string
	Attributes cookies.Options
}
```

### `ChallengeCookieResolver`

```go
type ChallengeCookieResolver func(contract.Request) (ChallengeCookie, error)
```

### `ConsumeChallengeFunc`

```go
type ConsumeChallengeFunc func(context.Context, string) (storage.Record, error)
```

### `CreateChallengeFunc`

```go
type CreateChallengeFunc func(context.Context, string, string, time.Time) (storage.Record, error)
```

### `ExtensionsResolver`

ExtensionsResolver computes WebAuthn extensions for one endpoint request.

```go
type ExtensionsResolver func(*engine.Context) (map[string]any, error)
```

### `IssueSessionFunc`

IssueSessionFunc creates a session for userID, resolves its user, and writes
the host's session cookies to ctx. A nil result means creation failed.

```go
type IssueSessionFunc func(*engine.Context, string) (*SessionState, error)
```

### `Options`

Options configures the single-auth-compatible passkey plugin.

```go
type Options struct {
	RPID                   string
	RPName                 string
	Origin                 string
	Origins                []string
	BaseURL                string
	AppName                string
	Secret                 string
	AuthenticatorSelection *webauthn.AuthenticatorSelectionCriteria
	Advanced               AdvancedOptions
	Registration           RegistrationOptions
	Authentication         AuthenticationOptions
	Schema                 storage.Schema
	Runtime                Runtime
}
```

### `Passkey`

Passkey is the public passkey model returned by the plugin endpoints.

```go
type Passkey struct {
	ID           string                        `json:"id"`
	Name         string                        `json:"name,omitempty"`
	PublicKey    string                        `json:"publicKey"`
	UserID       string                        `json:"userId"`
	CredentialID string                        `json:"credentialID"`
	Counter      uint32                        `json:"counter"`
	DeviceType   webauthn.CredentialDeviceType `json:"deviceType"`
	BackedUp     bool                          `json:"backedUp"`
	Transports   string                        `json:"transports,omitempty"`
	CreatedAt    time.Time                     `json:"createdAt"`
	AAGUID       string                        `json:"aaguid,omitempty"`
}
```

### `RegistrationOptions`

```go
type RegistrationOptions struct {
	// RequireSession defaults to true. Use Bool(false) for passkey-first flows.
	RequireSession    *bool
	ResolveUser       ResolveRegistrationUserFunc
	Extensions        map[string]any
	ResolveExtensions ExtensionsResolver
	AfterVerification AfterRegistrationVerificationFunc
}
```

### `RegistrationUser`

RegistrationUser is the account identity bound into a registration
challenge. DisplayName falls back to Name and then ID.

```go
type RegistrationUser struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}
```

### `RegistrationVerifier`

```go
type RegistrationVerifier func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error)
```

### `ResolveRegistrationUserArgs`

ResolveRegistrationUserArgs is passed to passkey-first identity resolution.

```go
type ResolveRegistrationUserArgs struct {
	Context *string
	Request *engine.Context
}
```

### `ResolveRegistrationUserFunc`

```go
type ResolveRegistrationUserFunc func(ResolveRegistrationUserArgs) (RegistrationUser, error)
```

### `ResolveSessionFunc`

ResolveSessionFunc resolves the request's session. It returns nil, nil for an
unauthenticated optional lookup. For SessionFresh, the host must apply its
configured freshness policy and may return SESSION_NOT_FRESH.

```go
type ResolveSessionFunc func(*engine.Context, SessionResolution) (*SessionState, error)
```

### `Runtime`

Runtime contains dependencies that single-auth normally injects through its
internal endpoint context. They are explicit until the Go root runtime
exposes an equivalent public plugin dependency surface.

```go
type Runtime struct {
	Adapter                storage.Adapter
	ResolveSession         ResolveSessionFunc
	IssueSession           IssueSessionFunc
	Clock                  func() time.Time
	Random                 io.Reader
	ResolveChallengeCookie ChallengeCookieResolver
	CreateChallenge        CreateChallengeFunc
	ConsumeChallenge       ConsumeChallengeFunc
	VerifyRegistration     RegistrationVerifier
	VerifyAuthentication   AuthenticationVerifier
}
```

### `SessionResolution`

SessionResolution tells the host how strongly an endpoint needs a session.

```go
type SessionResolution uint8
```

## Constants associated with `SessionResolution`

```go
const (
	SessionOptional SessionResolution = iota
	SessionRequired
	SessionFresh
)
```

### `SessionState`

SessionState is the session/user pair resolved by the host runtime.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

