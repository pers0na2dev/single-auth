// Package sqlite contains a compile-checked full-runtime SQLite example.
package sqlite

import (
	"context"
	"database/sql"

	_ "modernc.org/sqlite"

	singleauth "github.com/pers0na2dev/single-auth"
)

// Open constructs the complete plugin-aware schema, initializes the native
// SQLite adapter, and applies additive migrations before returning.
func Open(ctx context.Context, dataSourceName, secret string) (*sql.DB, *singleauth.Auth, error) {
	database, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, nil, err
	}

	auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
		BaseURL: "https://auth.example.com",
		Secret:  secret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
		},
		TrustedOrigins: []string{"https://app.example.com"},
	}, database)
	if err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	if err := auth.RunMigrationsContext(ctx); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	return database, auth, nil
}
