---
title: "github.com/pers0na2dev/single-auth/plugins/siwe"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/siwe.

- Import path: `github.com/pers0na2dev/single-auth/plugins/siwe`
- Package name: `siwe`

Package siwe implements the single-auth 1.6.26 Sign-In with Ethereum
server plugin for single-auth.

## Constants

```go
const Version = "1.6.26"
```

## Functions

### `ChecksumAddress`

ChecksumAddress implements EIP-55 with legacy Keccak-256, matching
single-auth's @noble/hashes implementation byte-for-byte.

```go
func ChecksumAddress(address string) string
```

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a transport-neutral SIWE plugin.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds persistence, base URL resolution, user hooks, session
cookies, secondary verification storage, and the root clock.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `NormalizeDomain`

NormalizeDomain strips scheme and path and lowercases the RFC 3986
authority, exactly like the frozen plugin.

```go
func NormalizeDomain(domain string) string
```

### `Schema`

Schema returns an independent copy of the frozen walletAddress schema.

```go
func Schema() storage.Schema
```

## Types

### `Cacao`

Cacao is the CAIP-74 capability object supplied to the application's
signature verifier. It mirrors the object emitted by single-auth 1.6.26.

```go
type Cacao struct {
	Header    CacaoHeader    `json:"h"`
	Payload   CacaoPayload   `json:"p"`
	Signature CacaoSignature `json:"s"`
}
```

### `CacaoHeader`

```go
type CacaoHeader struct {
	Type string `json:"t"`
}
```

### `CacaoPayload`

```go
type CacaoPayload struct {
	Domain     string   `json:"domain"`
	Audience   string   `json:"aud"`
	Nonce      string   `json:"nonce"`
	Issuer     string   `json:"iss"`
	Version    string   `json:"version,omitempty"`
	IssuedAt   string   `json:"iat,omitempty"`
	NotBefore  string   `json:"nbf,omitempty"`
	Expiration string   `json:"exp,omitempty"`
	Statement  string   `json:"statement,omitempty"`
	RequestID  string   `json:"requestId,omitempty"`
	Resources  []string `json:"resources,omitempty"`
	Type       string   `json:"type,omitempty"`
}
```

### `CacaoSignature`

```go
type CacaoSignature struct {
	Type    string `json:"t"`
	Value   string `json:"s"`
	Message string `json:"m,omitempty"`
}
```

### `ConsumeVerificationFunc`

```go
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)
```

### `CreateUserFunc`

```go
type CreateUserFunc func(*engine.Context, storage.Record) (storage.Record, error)
```

### `CreateVerificationFunc`

```go
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
```

### `ENSLookupArgs`

```go
type ENSLookupArgs struct {
	WalletAddress string
}
```

### `ENSLookupFunc`

```go
type ENSLookupFunc func(context.Context, ENSLookupArgs) (ENSLookupResult, error)
```

### `ENSLookupResult`

```go
type ENSLookupResult struct {
	Name   string
	Avatar string
}
```

### `GetNonceFunc`

```go
type GetNonceFunc func(context.Context) (string, error)
```

### `IssueSessionFunc`

```go
type IssueSessionFunc func(*engine.Context, string) (*SessionState, error)
```

### `Options`

Options configures the single-auth-compatible SIWE plugin. Anonymous is a
pointer because omission means true while an explicit false requires email.

```go
type Options struct {
	Domain          string
	EmailDomainName string
	Anonymous       *bool
	GetNonce        GetNonceFunc
	VerifyMessage   VerifyMessageFunc
	ENSLookup       ENSLookupFunc
	Schema          storage.Schema
	Runtime         Runtime
}
```

### `ParsedMessage`

ParsedMessage contains the ERC-4361 fields that the server independently
validates before calling the application verifier.

```go
type ParsedMessage struct {
	Scheme         string `json:"scheme,omitempty"`
	Domain         string `json:"domain,omitempty"`
	Address        string `json:"address,omitempty"`
	URI            string `json:"uri,omitempty"`
	Version        string `json:"version,omitempty"`
	ChainID        int64  `json:"chainId,omitempty"`
	HasChainID     bool   `json:"-"`
	Nonce          string `json:"nonce,omitempty"`
	IssuedAt       string `json:"issuedAt,omitempty"`
	ExpirationTime string `json:"expirationTime,omitempty"`
	NotBefore      string `json:"notBefore,omitempty"`
	RequestID      string `json:"requestId,omitempty"`
}
```

## Constructors and functions for `ParsedMessage`

### `ParseMessage`

ParseMessage is the tolerant parser used by single-auth 1.6.26. Missing or
malformed fields are left empty and are rejected by the binding step.

```go
func ParseMessage(message string) ParsedMessage
```

### `ResolveBaseURLFunc`

```go
type ResolveBaseURLFunc func(contract.Request) (string, error)
```

### `Runtime`

Runtime contains the services single-auth normally injects into endpoint
context. NewFactory binds these to the root runtime.

```go
type Runtime struct {
	Adapter             storage.Adapter
	Clock               func() time.Time
	ResolveBaseURL      ResolveBaseURLFunc
	CreateVerification  CreateVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	CreateUser          CreateUserFunc
	IssueSession        IssueSessionFunc
}
```

### `SessionState`

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `VerifyMessageArgs`

VerifyMessageArgs is passed only after the nonce has been atomically
consumed and the signed ERC-4361 fields have been bound to server state.

```go
type VerifyMessageArgs struct {
	Message   string
	Signature string
	Address   string
	ChainID   int64
	Cacao     Cacao
}
```

### `VerifyMessageFunc`

```go
type VerifyMessageFunc func(context.Context, VerifyMessageArgs) (bool, error)
```

### `WalletAddress`

WalletAddress is the canonical SIWE persistence model.

```go
type WalletAddress struct {
	ID        string
	UserID    string
	Address   string
	ChainID   int64
	IsPrimary bool
	CreatedAt time.Time
}
```

