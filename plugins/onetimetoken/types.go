package onetimetoken

import (
	"context"
	"io"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

type TokenStoreMode string

const (
	StorePlain  TokenStoreMode = "plain"
	StoreHashed TokenStoreMode = "hashed"
	StoreCustom TokenStoreMode = "custom-hasher"
)

type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type ResolveSessionFunc func(*engine.Context) (*SessionState, error)
type FindSessionFunc func(context.Context, string) (*SessionState, error)
type RefreshSessionFunc func(*engine.Context, SessionState) error
type NewSessionFunc func(*engine.Context) *SessionState
type GenerateTokenFunc func(*engine.Context, SessionState) (string, error)
type TokenHashFunc func(context.Context, string) (string, error)
type SerializeRecordFunc func(storage.Record) any
type CreateVerificationFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type ConsumeVerificationFunc func(context.Context, string) (storage.Record, error)

type TokenStorage struct {
	Mode       TokenStoreMode
	CustomHash TokenHashFunc
}

// Runtime contains the request and persistence services supplied by
// singleauth.PluginHost. Adapter is only used by standalone plugin instances
// when explicit verification callbacks are omitted.
type Runtime struct {
	Adapter storage.Adapter
	Clock   func() time.Time
	Random  io.Reader

	ResolveSession ResolveSessionFunc
	FindSession    FindSessionFunc
	RefreshSession RefreshSessionFunc
	NewSession     NewSessionFunc

	SerializeSession SerializeRecordFunc
	SerializeUser    SerializeRecordFunc

	CreateVerification  CreateVerificationFunc
	ConsumeVerification ConsumeVerificationFunc
}

type Options struct {
	// ExpiresIn distinguishes omission from an explicit zero duration, matching
	// JavaScript's nullish default. Nil selects three minutes.
	ExpiresIn *time.Duration

	DisableClientRequest     bool
	GenerateToken            GenerateTokenFunc
	DisableSetSessionCookie  bool
	Storage                  TokenStorage
	SetOTTHeaderOnNewSession bool

	Runtime Runtime
}

func Duration(value time.Duration) *time.Duration { return &value }
