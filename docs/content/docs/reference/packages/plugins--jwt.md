---
title: "github.com/pers0na2dev/single-auth/plugins/jwt"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/jwt.

- Import path: `github.com/pers0na2dev/single-auth/plugins/jwt`
- Package name: `jwt`

Package jwt implements single-auth 1.6.26's asymmetric JWT and JWKS plugin.

## Constants

```go
const (
	PluginID = "jwt"
	Version  = "1.6.26"
)
```

## Functions

### `Duration`

```go
func Duration(value time.Duration) *time.Duration
```

### `GetJWTToken`

GetJWTToken builds the session-derived payload and signs it. It is the Go
equivalent of the upstream getJwtToken export.

```go
func GetJWTToken(ctx *engine.Context, options Options, state SessionState) (string, error)
```

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a single-auth JWT plugin descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Schema`

Schema returns an independent copy of single-auth 1.6.26's jwks model.

```go
func Schema() storage.Schema
```

### `SignJWT`

SignJWT signs an arbitrary claim set using the plugin's configured key.

```go
func SignJWT(ctx *engine.Context, options Options, payload map[string]any) (string, error)
```

### `String`

```go
func String(value string) *string
```

### `ToExpJWT`

ToExpJWT implements single-auth's number | Date | TimeString conversion.

```go
func ToExpJWT(expiration any, issuedAt float64) (float64, error)
```

### `VerifyJWT`

VerifyJWT verifies a token with the configured stored public keys. Invalid,
expired, or mismatched tokens return nil exactly like the upstream helper.

```go
func VerifyJWT(ctx *engine.Context, token string, options Options) map[string]any
```

## Types

### `AccessTokenVerification`

AccessTokenVerification preserves the distinctions required by the OAuth
provider's RFC 7009 endpoint after cryptographic JWS verification.

```go
type AccessTokenVerification uint8
```

## Constants associated with `AccessTokenVerification`

```go
const (
	AccessTokenNotJWT AccessTokenVerification = iota
	AccessTokenInvalidSignature
	AccessTokenInvalidClaims
	AccessTokenInactive
	AccessTokenValid
)
```

## Constructors and functions for `AccessTokenVerification`

### `VerifyAccessToken`

VerifyAccessToken performs the same stored-JWK verification as VerifyJWT,
but retains the JOSE failure class used by OAuth revocation. single-auth
1.6.26 falls back to opaque lookup only for TypeError/JWSInvalid failures,
accepts JWTExpired/JWTInvalid as inactive, and surfaces signature or claim
validation failures as internal errors.

```go
func VerifyAccessToken(
	ctx *engine.Context,
	token string,
	options Options,
) (map[string]any, AccessTokenVerification, error)
```

### `AdapterForContextFunc`

```go
type AdapterForContextFunc func(context.Context) storage.TransactionAdapter
```

### `AdapterOptions`

```go
type AdapterOptions struct {
	GetJWKs   GetJWKsFunc
	CreateJWK CreateJWKFunc
}
```

### `Algorithm`

```go
type Algorithm string
```

## Constants associated with `Algorithm`

```go
const (
	EdDSA Algorithm = "EdDSA"
	ES256 Algorithm = "ES256"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	RS256 Algorithm = "RS256"
)
```

### `CreateJWKFunc`

```go
type CreateJWKFunc func(*engine.Context, JWK) (JWK, error)
```

### `DecryptPrivateKeyFunc`

```go
type DecryptPrivateKeyFunc func(context.Context, string) ([]byte, error)
```

### `DefinePayloadFunc`

```go
type DefinePayloadFunc func(*engine.Context, SessionState) (map[string]any, error)
```

### `EncryptPrivateKeyFunc`

```go
type EncryptPrivateKeyFunc func(context.Context, []byte) (string, error)
```

### `ExportedKeyPair`

ExportedKeyPair is the JWK representation returned by
GenerateExportedKeyPair.

```go
type ExportedKeyPair struct {
	PublicKey  map[string]any
	PrivateKey map[string]any
	Algorithm  Algorithm
	Curve      string
}
```

## Constructors and functions for `ExportedKeyPair`

### `GenerateExportedKeyPair`

GenerateExportedKeyPair generates an extractable public/private JWK pair.
It snapshots options and uses Runtime.Random, defaulting to crypto/rand.

```go
func GenerateExportedKeyPair(options Options) (ExportedKeyPair, error)
```

### `GetJWKsFunc`

```go
type GetJWKsFunc func(*engine.Context) ([]JWK, error)
```

### `GetSubjectFunc`

```go
type GetSubjectFunc func(*engine.Context, SessionState) (*string, error)
```

### `JWK`

JWK is the persisted single-auth jwks model. Algorithm and Curve are kept
for custom-adapter compatibility; the upstream database schema intentionally does
not persist either field.

```go
type JWK struct {
	ID         string
	PublicKey  string
	PrivateKey string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	Algorithm  Algorithm
	Curve      string
}
```

## Constructors and functions for `JWK`

### `CreateJWK`

CreateJWK generates and persists one signing key using single-auth's
private-key encryption representation.

```go
func CreateJWK(ctx *engine.Context, options Options) (JWK, error)
```

### `JWKSOptions`

```go
type JWKSOptions struct {
	RemoteURL                   string
	KeyPair                     *KeyPairConfig
	DisablePrivateKeyEncryption bool
	RotationInterval            *time.Duration
	GracePeriod                 *time.Duration
	// Path is a pointer because omitted defaults to /jwks while an explicit
	// empty string is rejected by the upstream nullish-coalescing semantics.
	Path *string
}
```

### `KeyPairConfig`

KeyPairConfig is the Go representation of single-auth's JWKOptions union.
Curve is only meaningful for EdDSA and defaults to Ed25519. ModulusLength
is only meaningful for RSA algorithms and defaults to 2048 bits.

```go
type KeyPairConfig struct {
	Algorithm     Algorithm
	Curve         string
	ModulusLength int
}
```

### `Options`

```go
type Options struct {
	JWKS                    JWKSOptions
	Token                   TokenOptions
	DisableSettingJWTHeader bool
	Schema                  storage.Schema
	Adapter                 AdapterOptions
	Runtime                 Runtime
}
```

### `RemoteSignFunc`

```go
type RemoteSignFunc func(context.Context, map[string]any) (string, error)
```

### `ResolveBaseURLFunc`

```go
type ResolveBaseURLFunc func(*engine.Context) (string, error)
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context, bool) (*SessionState, error)
```

### `Runtime`

Runtime holds services which single-auth gets from its auth context. A root
PluginFactory fills these fields; explicit values make the plugin usable in
an isolated engine registry and in deterministic tests.

```go
type Runtime struct {
	Adapter           storage.Adapter
	AdapterForContext AdapterForContextFunc
	Clock             func() time.Time
	Random            io.Reader
	Secret            string
	BaseURL           string
	ResolveBaseURL    ResolveBaseURLFunc
	ResolveSession    ResolveSessionFunc
	SerializeUser     SerializeUserFunc
	EncryptPrivateKey EncryptPrivateKeyFunc
	DecryptPrivateKey DecryptPrivateKeyFunc
}
```

### `SerializeUserFunc`

```go
type SerializeUserFunc func(storage.Record) any
```

### `SessionState`

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `TokenOptions`

```go
type TokenOptions struct {
	// Issuer is a pointer because an explicitly empty issuer differs from an
	// omitted issuer in single-auth.
	Issuer *string
	// Audience accepts a string or []string, preserving the upstream JSON
	// representation. Other values are rejected during plugin construction.
	Audience any
	// ExpirationTime accepts integer seconds, time.Time, or a single-auth time
	// string such as "15m". Nil selects the upstream 15-minute default.
	ExpirationTime any
	DefinePayload  DefinePayloadFunc
	GetSubject     GetSubjectFunc
	Sign           RemoteSignFunc
}
```

