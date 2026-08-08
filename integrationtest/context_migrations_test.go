package singleauth_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type migrationContextKey struct{}

type ensuringAdapter struct {
	storage.Adapter

	mu        sync.Mutex
	calls     int
	seen      any
	ensureErr error
}

func (adapter *ensuringAdapter) EnsureSchema(ctx context.Context) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.calls++
	adapter.seen = ctx.Value(migrationContextKey{})
	return adapter.ensureErr
}

func (adapter *ensuringAdapter) snapshot() (int, any) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.calls, adapter.seen
}

func TestRunMigrationsUsesNativeAdapterCapability(t *testing.T) {
	adapter := &ensuringAdapter{Adapter: memory.MustNew()}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:  "http://localhost:3000",
		Database: adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), migrationContextKey{}, "request-context")
	if err := auth.RunMigrationsContext(ctx); err != nil {
		t.Fatal(err)
	}
	if calls, seen := adapter.snapshot(); calls != 1 || seen != "request-context" {
		t.Fatalf("ensure calls = %d, context value = %#v", calls, seen)
	}

	authContext, err := auth.Context()
	if err != nil {
		t.Fatal(err)
	}
	if err := authContext.RunMigrationsContext(ctx); err != nil {
		t.Fatal(err)
	}
	if calls, _ := adapter.snapshot(); calls != 2 {
		t.Fatalf("ensure calls through AuthContext = %d, want 2", calls)
	}
}

func TestRunMigrationsPropagatesNativeAdapterError(t *testing.T) {
	want := errors.New("schema failed")
	adapter := &ensuringAdapter{Adapter: memory.MustNew(), ensureErr: want}
	auth, err := singleauth.New(singleauth.Options{Database: adapter})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RunMigrations(); !errors.Is(err, want) {
		t.Fatalf("RunMigrations error = %v, want %v", err, want)
	}
}

func TestRunMigrationsRejectsAdapterWithoutCapability(t *testing.T) {
	auth, err := singleauth.New(singleauth.Options{Database: memory.MustNew()})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RunMigrations(); !errors.Is(err, singleauth.ErrFullMigrationsRequireDatabase) {
		t.Fatalf("RunMigrations error = %v", err)
	}
}

var _ storage.SchemaEnsurer = (*ensuringAdapter)(nil)
