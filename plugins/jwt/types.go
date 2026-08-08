package jwt

import (
	"context"
	"io"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	PluginID = "jwt"
	Version  = "1.6.26"
)

type Algorithm string

const (
	EdDSA Algorithm = "EdDSA"
	ES256 Algorithm = "ES256"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	RS256 Algorithm = "RS256"
)

// KeyPairConfig is the Go representation of single-auth's JWKOptions union.
// Curve is only meaningful for EdDSA and defaults to Ed25519. ModulusLength
// is only meaningful for RSA algorithms and defaults to 2048 bits.
type KeyPairConfig struct {
	Algorithm     Algorithm
	Curve         string
	ModulusLength int
}

// JWK is the persisted single-auth jwks model. Algorithm and Curve are kept
// for custom-adapter compatibility; the upstream database schema intentionally does
// not persist either field.
type JWK struct {
	ID         string
	PublicKey  string
	PrivateKey string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	Algorithm  Algorithm
	Curve      string
}

type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type GetJWKsFunc func(*engine.Context) ([]JWK, error)
type CreateJWKFunc func(*engine.Context, JWK) (JWK, error)

type AdapterOptions struct {
	GetJWKs   GetJWKsFunc
	CreateJWK CreateJWKFunc
}

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

type DefinePayloadFunc func(*engine.Context, SessionState) (map[string]any, error)
type GetSubjectFunc func(*engine.Context, SessionState) (*string, error)
type RemoteSignFunc func(context.Context, map[string]any) (string, error)

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

type ResolveSessionFunc func(*engine.Context, bool) (*SessionState, error)
type ResolveBaseURLFunc func(*engine.Context) (string, error)
type SerializeUserFunc func(storage.Record) any
type AdapterForContextFunc func(context.Context) storage.TransactionAdapter
type EncryptPrivateKeyFunc func(context.Context, []byte) (string, error)
type DecryptPrivateKeyFunc func(context.Context, string) ([]byte, error)

// Runtime holds services which single-auth gets from its auth context. A root
// PluginFactory fills these fields; explicit values make the plugin usable in
// an isolated engine registry and in deterministic tests.
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

type Options struct {
	JWKS                    JWKSOptions
	Token                   TokenOptions
	DisableSettingJWTHeader bool
	Schema                  storage.Schema
	Adapter                 AdapterOptions
	Runtime                 Runtime
}

func Duration(value time.Duration) *time.Duration { return &value }
func String(value string) *string                 { return &value }

// ExportedKeyPair is the JWK representation returned by
// GenerateExportedKeyPair.
type ExportedKeyPair struct {
	PublicKey  map[string]any
	PrivateKey map[string]any
	Algorithm  Algorithm
	Curve      string
}
