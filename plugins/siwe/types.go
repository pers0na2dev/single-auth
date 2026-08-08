package siwe

import (
	"context"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// Cacao is the CAIP-74 capability object supplied to the application's
// signature verifier. It mirrors the object emitted by single-auth 1.6.26.
type Cacao struct {
	Header    CacaoHeader    `json:"h"`
	Payload   CacaoPayload   `json:"p"`
	Signature CacaoSignature `json:"s"`
}

type CacaoHeader struct {
	Type string `json:"t"`
}

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

type CacaoSignature struct {
	Type    string `json:"t"`
	Value   string `json:"s"`
	Message string `json:"m,omitempty"`
}

// VerifyMessageArgs is passed only after the nonce has been atomically
// consumed and the signed ERC-4361 fields have been bound to server state.
type VerifyMessageArgs struct {
	Message   string
	Signature string
	Address   string
	ChainID   int64
	Cacao     Cacao
}

type VerifyMessageFunc func(context.Context, VerifyMessageArgs) (bool, error)
type GetNonceFunc func(context.Context) (string, error)

type ENSLookupArgs struct {
	WalletAddress string
}

type ENSLookupResult struct {
	Name   string
	Avatar string
}

type ENSLookupFunc func(context.Context, ENSLookupArgs) (ENSLookupResult, error)

type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type IssueSessionFunc func(*engine.Context, string) (*SessionState, error)
type CreateUserFunc func(*engine.Context, storage.Record) (storage.Record, error)
type ResolveBaseURLFunc func(contract.Request) (string, error)
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)

// Runtime contains the services single-auth normally injects into endpoint
// context. NewFactory binds these to the root runtime.
type Runtime struct {
	Adapter             storage.Adapter
	Clock               func() time.Time
	ResolveBaseURL      ResolveBaseURLFunc
	CreateVerification  CreateVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
	CreateUser          CreateUserFunc
	IssueSession        IssueSessionFunc
}

// Options configures the single-auth-compatible SIWE plugin. Anonymous is a
// pointer because omission means true while an explicit false requires email.
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

// WalletAddress is the canonical SIWE persistence model.
type WalletAddress struct {
	ID        string
	UserID    string
	Address   string
	ChainID   int64
	IsPrimary bool
	CreatedAt time.Time
}
