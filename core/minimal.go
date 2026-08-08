package core

import (
	"errors"

	"github.com/pers0na2dev/single-auth/storage"
)

const (
	minimalMigrationsErrorMessage     = "Migrations are not supported in 'single-auth/minimal'. Please use 'single-auth' for migration support."
	minimalDirectDatabaseErrorMessage = "direct database connections are unsupported; provide a storage.Adapter"
)

var (
	// ErrMinimalMigrationsUnsupported is returned by the minimal runtime because
	// schema migrations require the database-specific full runtime upstream.
	ErrMinimalMigrationsUnsupported = &UpstreamError{message: minimalMigrationsErrorMessage}
	// ErrMinimalDirectDatabaseUnsupported is returned when a raw database
	// connection is passed to the minimal runtime instead of a storage adapter.
	ErrMinimalDirectDatabaseUnsupported = &UpstreamError{message: minimalDirectDatabaseErrorMessage}
)

// UpstreamError is an initialization or capability error exposed verbatim
// by upstream implementation. The concrete type preserves the upstream error identity for
// callers that need to distinguish configuration errors from transport errors.
type UpstreamError struct {
	message string
}

// Error returns the unmodified upstream implementation diagnostic.
func (e *UpstreamError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

// MinimalAuth is the upstream implementation-compatible minimal runtime. It embeds the
// regular Go runtime while keeping the minimal entry point's migration and
// raw-connection constraints explicit.
type MinimalAuth struct {
	*Auth
}

// MinimalContext exposes the adapter selected by the minimal initializer.
// DatabaseType is always "unknown" because minimal mode accepts an already
// configured storage adapter and does not perform database detection.
type MinimalContext struct {
	Adapter      storage.Adapter
	DatabaseType string
}

// NewMinimal constructs upstream implementation's adapter-only minimal runtime.
func NewMinimal(options Options) (*MinimalAuth, error) {
	auth, err := New(options)
	if err != nil {
		return nil, err
	}
	return &MinimalAuth{Auth: auth}, nil
}

// NewMinimalWithDatabase accepts the dynamic database shape exposed by the
// JavaScript initializer. Go storage.Adapter values are supported; raw
// connections are rejected with upstream implementation's exact minimal-mode diagnostic.
func NewMinimalWithDatabase(options Options, database any) (*MinimalAuth, error) {
	if database == nil {
		return NewMinimal(options)
	}
	adapter, ok := database.(storage.Adapter)
	if !ok {
		return nil, ErrMinimalDirectDatabaseUnsupported
	}
	options.Database = adapter
	return NewMinimal(options)
}

// Context returns the initialized adapter-only minimal context.
func (a *MinimalAuth) Context() (*MinimalContext, error) {
	if a == nil || a.Auth == nil || a.Adapter() == nil {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return &MinimalContext{Adapter: a.Adapter(), DatabaseType: "unknown"}, nil
}

// RunMigrations always rejects in minimal mode.
func (a *MinimalAuth) RunMigrations() error {
	return ErrMinimalMigrationsUnsupported
}

// RunMigrations always rejects in minimal mode.
func (c *MinimalContext) RunMigrations() error {
	return ErrMinimalMigrationsUnsupported
}
