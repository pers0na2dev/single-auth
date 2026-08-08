package core

import (
	"context"
	"database/sql"
	"errors"

	"github.com/pers0na2dev/single-auth/storage"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"
)

const fullMigrationAdapterErrorMessage = "Database is not provided or it's an adapter. Migrations are only supported with a database instance."

var (
	// ErrFullMigrationsRequireDatabase is returned when full-mode migrations are
	// requested without a raw database connection.
	ErrFullMigrationsRequireDatabase = &UpstreamError{message: fullMigrationAdapterErrorMessage}
)

// AuthContextAdapterConfig is the Go counterpart of upstream implementation's adapter
// factory metadata.
type AuthContextAdapterConfig struct {
	AdapterID   string
	AdapterName string
}

// AuthContextAdapterOptions describes the detected database dialect and the
// adapter factory that was selected for it.
type AuthContextAdapterOptions struct {
	Type          string
	AdapterConfig *AuthContextAdapterConfig
}

// AuthContext exposes the initialized full-mode adapter and migration
// capability. It is an immutable snapshot.
type AuthContext struct {
	Adapter        storage.Adapter
	AdapterOptions AuthContextAdapterOptions
	DatabaseType   string
	runMigrations  func(context.Context) error
}

type authContextMetadata struct {
	adapterID      string
	adapterOptions AuthContextAdapterOptions
	databaseType   string
}

type contextDatabaseInitialization struct {
	adapter       storage.Adapter
	metadata      authContextMetadata
	runMigrations func(context.Context) error
}

type contextDatabaseInitializer func(
	runtimeOptions,
	storage.Schema,
) (contextDatabaseInitialization, error)

// NewWithSQLiteDatabase initializes the full runtime from a raw database/sql
// SQLite handle and exposes the native SQLite adapter.
func NewWithSQLiteDatabase(options Options, database *sql.DB) (*Auth, error) {
	if database == nil {
		return nil, errors.New("single-auth: SQLite database is nil")
	}
	if options.Database != nil {
		return nil, errors.New("single-auth: database adapter and raw database are mutually exclusive")
	}
	options.databaseInitializer = func(
		normalized runtimeOptions,
		schema storage.Schema,
	) (contextDatabaseInitialization, error) {
		adapter, err := sqliteadapter.New(database, sqliteadapter.Options{
			Schema: schema,
			Clock:  normalized.Clock,
			IDGenerator: func(model string) (any, error) {
				value, generated, generateErr := generateIdentifier(normalized, model, 32)
				if generateErr != nil {
					return nil, generateErr
				}
				if !generated {
					return nil, errors.New("single-auth: SQLite adapter requires generated IDs")
				}
				return value, nil
			},
		})
		if err != nil {
			return contextDatabaseInitialization{}, err
		}
		return contextDatabaseInitialization{
			adapter: adapter,
			metadata: authContextMetadata{
				adapterID: "sqlite",
				adapterOptions: AuthContextAdapterOptions{
					Type: "sqlite",
					AdapterConfig: &AuthContextAdapterConfig{
						AdapterID: "sqlite", AdapterName: "SQLite Adapter",
					},
				},
				databaseType: "sqlite",
			},
			runMigrations: adapter.EnsureSchema,
		}, nil
	}
	return New(options)
}

// Context returns the initialized full-mode context.
func (a *Auth) Context() (*AuthContext, error) {
	if a == nil || a.adapter == nil {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return &AuthContext{
		Adapter:        a.adapter,
		AdapterOptions: cloneAuthContextAdapterOptions(a.contextMeta.adapterOptions),
		DatabaseType:   a.contextMeta.databaseType,
		runMigrations:  a.runMigrations,
	}, nil
}

// RunMigrations executes full-mode schema migrations using a background
// context, matching upstream implementation's zero-argument runtime callback.
func (a *Auth) RunMigrations() error {
	return a.RunMigrationsContext(context.Background())
}

// RunMigrationsContext executes full-mode schema migrations with cancellation.
func (a *Auth) RunMigrationsContext(ctx context.Context) error {
	if a == nil || a.runMigrations == nil {
		return errors.New("single-auth: auth is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return a.runMigrations(ctx)
}

// RunMigrations executes this context's full-mode schema migrations.
func (c *AuthContext) RunMigrations() error {
	return c.RunMigrationsContext(context.Background())
}

// RunMigrationsContext executes this context's migrations with cancellation.
func (c *AuthContext) RunMigrationsContext(ctx context.Context) error {
	if c == nil || c.runMigrations == nil {
		return errors.New("single-auth: auth context is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.runMigrations(ctx)
}

func unsupportedFullMigration(context.Context) error {
	return ErrFullMigrationsRequireDatabase
}

func authContextMetadataForAdapter(adapter storage.Adapter) authContextMetadata {
	if adapter == nil {
		return authContextMetadata{}
	}
	return authContextMetadata{adapterID: adapter.ID()}
}

func cloneAuthContextAdapterOptions(options AuthContextAdapterOptions) AuthContextAdapterOptions {
	clone := options
	if options.AdapterConfig != nil {
		config := *options.AdapterConfig
		clone.AdapterConfig = &config
	}
	return clone
}
