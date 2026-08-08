---
title: "github.com/pers0na2dev/single-auth/security/crypto"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/security/crypto.

- Import path: `github.com/pers0na2dev/single-auth/security/crypto`
- Package name: `crypto`

Package crypto implements the wire-compatible cryptographic formats used by
the reference implementation. Production helpers always use cryptographically secure entropy.

## Constants

```go
const (
	DefaultSecret = "single-auth-secret-12345678901234567890"
)
```

## Variables

```go
var (
	ErrInvalidJWT = errors.New("invalid the reference implementation JWT")
	ErrExpiredJWT = errors.New("expired the reference implementation JWT")
)
```

```go
var (
	ErrInvalidCiphertext = errors.New("invalid the reference implementation ciphertext")
	ErrUnknownSecret     = errors.New("unknown the reference implementation secret version")
)
```

```go
var ErrInvalidPasswordHash = errors.New("invalid the reference implementation password hash")
```

## Functions

### `DecodeJWE`

DecodeJWE decrypts a token produced from one secret.

```go
func DecodeJWE(token, secret, salt string) (map[string]any, error)
```

### `DecodeJWEAt`

DecodeJWEAt decrypts at a deterministic time.

```go
func DecodeJWEAt(token, secret, salt string, now time.Time) (map[string]any, error)
```

### `DecodeJWEWithConfig`

DecodeJWEWithConfig selects a rotation key using kid and falls back for
legacy kid-less tokens in the reference implementation order.

```go
func DecodeJWEWithConfig(token string, config SecretConfig, salt string) (map[string]any, error)
```

### `DecodeJWEWithConfigAt`

DecodeJWEWithConfigAt is the deterministic, rotation-aware JWE decoder.

```go
func DecodeJWEWithConfigAt(token string, config SecretConfig, salt string, now time.Time) (map[string]any, error)
```

### `Decrypt`

Decrypt decrypts the legacy bare-hex XChaCha20-Poly1305 format.

```go
func Decrypt(secret, value string) ([]byte, error)
```

### `DecryptWithConfig`

DecryptWithConfig decrypts versioned data and explicitly configured legacy
bare-hex data.

```go
func DecryptWithConfig(config SecretConfig, value string) ([]byte, error)
```

### `EncodeJWE`

EncodeJWE encrypts claims using the reference implementation's dir+A256CBC-HS512 compact JWE.

```go
func EncodeJWE(payload map[string]any, secret, salt string, expiresIn time.Duration) (string, error)
```

### `EncodeJWEAt`

EncodeJWEAt creates deterministic compatibility vectors.

```go
func EncodeJWEAt(payload map[string]any, secret, salt string, expiresIn time.Duration, now time.Time, random io.Reader) (string, error)
```

### `EncodeJWEWithConfig`

EncodeJWEWithConfig encrypts using the current secret in a rotation config.

```go
func EncodeJWEWithConfig(payload map[string]any, config SecretConfig, salt string, expiresIn time.Duration) (string, error)
```

### `EncodeJWEWithConfigAt`

EncodeJWEWithConfigAt is the deterministic, rotation-aware JWE encoder.

```go
func EncodeJWEWithConfigAt(
	payload map[string]any,
	config SecretConfig,
	salt string,
	expiresIn time.Duration,
	now time.Time,
	random io.Reader,
) (string, error)
```

### `Encrypt`

Encrypt encrypts data in the legacy bare-hex XChaCha20-Poly1305 format.

```go
func Encrypt(secret string, data []byte) (string, error)
```

### `EncryptWithConfig`

EncryptWithConfig encrypts data with the current version and adds an envelope.

```go
func EncryptWithConfig(config SecretConfig, data []byte) (string, error)
```

### `EncryptWithConfigAndReader`

EncryptWithConfigAndReader is EncryptWithConfig with an injectable random
source. It is used by the auth runtime so OAuth-state vectors can be
deterministic without weakening the production default.

```go
func EncryptWithConfigAndReader(config SecretConfig, data []byte, random io.Reader) (string, error)
```

### `EncryptWithReader`

EncryptWithReader creates deterministic vectors while retaining the legacy
unversioned format.

```go
func EncryptWithReader(secret string, data []byte, random io.Reader) (string, error)
```

### `FormatEnvelope`

FormatEnvelope builds the reference implementation's versioned encrypted value format.

```go
func FormatEnvelope(version int, ciphertext string) string
```

### `HashPassword`

HashPassword creates a the reference implementation compatible scrypt password hash.

```go
func HashPassword(password string) (string, error)
```

### `HashPasswordWithReader`

HashPasswordWithReader is HashPassword with injectable entropy for tests.

```go
func HashPasswordWithReader(password string, random io.Reader) (string, error)
```

### `MakeSignature`

MakeSignature returns the reference implementation's padded base64 HMAC-SHA256 signature.

```go
func MakeSignature(value, secret string) string
```

### `MakeURLSignature`

MakeURLSignature returns the unpadded base64url HMAC-SHA256 format used by
the reference implementation's compact session cache.

```go
func MakeURLSignature(value, secret string) string
```

### `SignJWT`

SignJWT creates the HS256 JWT format used by the reference implementation cookie caches.

```go
func SignJWT(payload map[string]any, secret string, expiresIn time.Duration) (string, error)
```

### `SignJWTAt`

SignJWTAt is SignJWT with an injectable timestamp for deterministic vectors.

```go
func SignJWTAt(payload map[string]any, secret string, expiresIn time.Duration, now time.Time) (string, error)
```

### `ValidateSecretEntries`

ValidateSecretEntries applies the reference implementation's structural secret checks.

```go
func ValidateSecretEntries(entries []SecretEntry) error
```

### `ValidateSecretInputs`

ValidateSecretInputs validates dynamically decoded secret entries.

```go
func ValidateSecretInputs(entries []SecretInputEntry) error
```

### `VerifyJWT`

VerifyJWT verifies an HS256 token and its time-based claims.

```go
func VerifyJWT(token, secret string) (map[string]any, error)
```

### `VerifyJWTAt`

VerifyJWTAt verifies a token at a deterministic time with clock tolerance.

```go
func VerifyJWTAt(token, secret string, now time.Time, tolerance time.Duration) (map[string]any, error)
```

### `VerifyPassword`

VerifyPassword verifies both current and legacy @noble/hashes the reference implementation
hashes. Malformed hashes are rejected without panicking.

```go
func VerifyPassword(hash, password string) bool
```

### `VerifySignature`

VerifySignature verifies MakeSignature in constant time.

```go
func VerifySignature(value, signature, secret string) bool
```

### `VerifyURLSignature`

VerifyURLSignature verifies MakeURLSignature in constant time.

```go
func VerifyURLSignature(value, signature, secret string) bool
```

## Types

### `Envelope`

Envelope is the parsed $ba$&lt;version&gt;$&lt;ciphertext&gt; representation.

```go
type Envelope struct {
	Version    int
	Ciphertext string
}
```

## Constructors and functions for `Envelope`

### `ParseEnvelope`

ParseEnvelope parses a versioned the reference implementation encrypted value.

```go
func ParseEnvelope(value string) (Envelope, bool)
```

### `SecretConfig`

SecretConfig preserves the reference implementation's ordered secret rotation configuration.

```go
type SecretConfig struct {
	Keys           map[int]string `json:"keys"`
	Order          []int          `json:"order"`
	CurrentVersion int            `json:"currentVersion"`
	LegacySecret   string         `json:"legacySecret,omitempty"`
}
```

## Constructors and functions for `SecretConfig`

### `BuildSecretConfig`

BuildSecretConfig normalizes dynamic entries and constructs the same key map
used by the reference implementation. Its built-in default is never retained as a legacy key.

```go
func BuildSecretConfig(entries []SecretInputEntry, legacySecret string) (SecretConfig, error)
```

### `NewSecretConfig`

NewSecretConfig validates and builds an ordered rotation configuration.

```go
func NewSecretConfig(entries []SecretEntry, legacySecret string) (SecretConfig, error)
```

### `SecretEntry`

SecretEntry is one versioned the reference implementation secret.

```go
type SecretEntry struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}
```

## Constructors and functions for `SecretEntry`

### `NormalizeSecretEntries`

NormalizeSecretEntries applies the reference implementation's strict validation after its
parseInt(String(version), 10) coercion. Canonical decimal strings such as
"1" are accepted, while "0x10", "1e2", fractional values, and duplicate
versions after coercion are rejected.

```go
func NormalizeSecretEntries(entries []SecretInputEntry) ([]SecretEntry, error)
```

### `ParseSecretsEnv`

ParseSecretsEnv parses SINGLE_AUTH_SECRETS using JavaScript parseInt-like
leading-decimal behavioral compatibility, matching the reference implementation 1.6.26.

```go
func ParseSecretsEnv(value string) ([]SecretEntry, error)
```

### `SecretInputEntry`

SecretInputEntry accepts configuration decoded from dynamic formats where
the reference implementation permits canonical decimal strings as well as numeric versions.
NormalizeSecretEntries converts it to the strongly typed Go form.

```go
type SecretInputEntry struct {
	Version any    `json:"version"`
	Value   string `json:"value"`
}
```

