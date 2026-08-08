package onetimetoken

import (
	"context"
	"testing"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestDefaultConfigurationAndTokenHash(t *testing.T) {
	if Version != "1.6.26" || defaultExpiry.Milliseconds() != 180000 || StorePlain != "plain" {
		t.Fatalf("defaults: version=%q expiry=%s store=%q", Version, defaultExpiry, StorePlain)
	}
	if got, want := defaultTokenHash("123456"), "jZae727K08KaOmKSgOaGzww_XVqGr_PKEgIMkjrcbJI"; got != want {
		t.Fatalf("token hash = %q, want %q", got, want)
	}

	adapter := memory.MustNew()
	plugin, err := New(Options{Runtime: Runtime{
		Adapter: adapter,
		ResolveSession: func(*engine.Context) (*SessionState, error) {
			return &SessionState{}, nil
		},
		FindSession:    func(_ context.Context, _ string) (*SessionState, error) { return nil, nil },
		RefreshSession: func(*engine.Context, SessionState) error { return nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	if plugin.ID != "one-time-token" || plugin.Version != Version || len(plugin.Endpoints) != 2 {
		t.Fatalf("plugin descriptor=%#v", plugin)
	}
}
