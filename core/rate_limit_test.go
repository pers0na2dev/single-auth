package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

func rateRequest(t *testing.T, auth *Auth, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://auth.test"+path, nil)
	request.Header.Set("X-Forwarded-For", "192.0.2.10")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	return recorder
}

func TestRootRateLimitHTTPResponseAndDirectAPIBypass(t *testing.T) {
	auth := MustNew(Options{
		RateLimit: RateLimitOptions{
			Enabled: securityBool(true), Window: 30, Max: 2,
		},
	})
	for attempt := 1; attempt <= 3; attempt++ {
		response := rateRequest(t, auth, "/api/auth/ok")
		if attempt <= 2 {
			if response.Code != contract.StatusOK {
				t.Fatalf("attempt %d = %d %s", attempt, response.Code, response.Body.String())
			}
			continue
		}
		if response.Code != contract.StatusTooManyRequests {
			t.Fatalf("limited status = %d, body = %s", response.Code, response.Body.String())
		}
		if response.Body.String() != rateLimitResponseBody {
			t.Fatalf("limited body = %q", response.Body.String())
		}
		if response.Header().Get("X-Retry-After") != "30" {
			t.Fatalf("retry header = %q", response.Header().Get("X-Retry-After"))
		}
		if response.Header().Get("Content-Type") != "text/plain;charset=UTF-8" {
			t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
		}
	}

	for attempt := 0; attempt < 3; attempt++ {
		response, err := auth.Invoke("ok", engine.DirectInput{})
		if err != nil || response.Status() != contract.StatusOK {
			t.Fatalf("direct attempt %d = %d, %v", attempt, response.Status(), err)
		}
	}
}

func TestRootRateLimitProductionDefault(t *testing.T) {
	development := MustNew(Options{
		Environment: "development",
		RateLimit:   RateLimitOptions{Window: 30, Max: 1},
	})
	if first, second := rateRequest(t, development, "/api/auth/ok"), rateRequest(t, development, "/api/auth/ok"); first.Code != contract.StatusOK || second.Code != contract.StatusOK {
		t.Fatalf("development default statuses = %d, %d", first.Code, second.Code)
	}

	production := MustNew(Options{
		Environment: "production",
		Secret:      "0123456789abcdef0123456789abcdef",
		RateLimit:   RateLimitOptions{Window: 30, Max: 1},
	})
	first := rateRequest(t, production, "/api/auth/ok")
	second := rateRequest(t, production, "/api/auth/ok")
	if first.Code != contract.StatusOK || second.Code != contract.StatusTooManyRequests {
		t.Fatalf("production default statuses = %d, %d", first.Code, second.Code)
	}
}

func TestRootRateLimitRunsBeforePluginOnRequestAndUsesPluginRules(t *testing.T) {
	var lock sync.Mutex
	pluginCalls := 0
	plugin := engine.Plugin{
		ID: "rate-plugin",
		Endpoints: []engine.Endpoint{{
			Name: "ratePluginProbe", Path: "/plugin-rate", Methods: []string{http.MethodGet},
			Handler: func(*engine.Context) (contract.Response, error) {
				return jsonResponse(contract.StatusOK, map[string]any{"ok": true})
			},
		}},
		RateLimit: []ratelimit.MatcherRule{{
			Match: func(path string) bool { return path == "/plugin-rate" },
			Rule:  ratelimit.Rule{Window: 60, Max: 1},
		}},
		OnRequest: func(*engine.Context) (engine.OnRequestResult, error) {
			lock.Lock()
			pluginCalls++
			lock.Unlock()
			return engine.OnRequestResult{}, nil
		},
	}
	auth := MustNew(Options{
		RateLimit: RateLimitOptions{Enabled: securityBool(true)},
		Plugins:   []engine.Plugin{plugin},
	})
	first := rateRequest(t, auth, "/api/auth/plugin-rate")
	second := rateRequest(t, auth, "/api/auth/plugin-rate")
	if first.Code != contract.StatusOK || second.Code != contract.StatusTooManyRequests {
		t.Fatalf("plugin rule statuses = %d, %d", first.Code, second.Code)
	}
	lock.Lock()
	calls := pluginCalls
	lock.Unlock()
	if calls != 1 {
		t.Fatalf("plugin onRequest calls = %d, want 1", calls)
	}
}

func TestRootDatabaseRateLimitSchemaAliasesAndEnforcement(t *testing.T) {
	auth := MustNew(Options{
		RateLimit: RateLimitOptions{
			Enabled:   securityBool(true),
			Window:    60,
			Max:       1,
			Storage:   "database",
			ModelName: "auth_rate_limits",
			Fields: map[string]string{
				"key": "bucket_key", "count": "hit_count", "lastRequest": "last_hit_ms",
			},
		},
	})
	schema := auth.Options().Schema
	model, ok := schema.Models["rateLimit"]
	if !ok || model.ModelName != "auth_rate_limits" || model.Fields["key"].FieldName != "bucket_key" ||
		model.Fields["count"].FieldName != "hit_count" || model.Fields["lastRequest"].FieldName != "last_hit_ms" {
		t.Fatalf("rate-limit schema = %#v", model)
	}
	first := rateRequest(t, auth, "/api/auth/ok")
	second := rateRequest(t, auth, "/api/auth/ok")
	if first.Code != contract.StatusOK || second.Code != contract.StatusTooManyRequests {
		t.Fatalf("database statuses = %d, %d", first.Code, second.Code)
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "rateLimit"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("database rows = %#v, %v", rows, err)
	}

	memoryOnly := MustNew(Options{})
	if _, exists := memoryOnly.Options().Schema.Models["rateLimit"]; exists {
		t.Fatal("memory rate limiting unexpectedly materialized rateLimit schema")
	}
}

type rootSecondaryRateStore struct {
	mu     sync.Mutex
	counts map[string]int64
	ttls   []int64
}

func (store *rootSecondaryRateStore) Get(context.Context, string) (string, error) { return "", nil }

func (store *rootSecondaryRateStore) Set(context.Context, string, string, int64) error { return nil }

func (store *rootSecondaryRateStore) Delete(context.Context, string) error { return nil }

func (store *rootSecondaryRateStore) Increment(_ context.Context, key string, ttl int64) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.counts == nil {
		store.counts = make(map[string]int64)
	}
	store.counts[key]++
	store.ttls = append(store.ttls, ttl)
	return store.counts[key], nil
}

func TestRootRateLimitDefaultsToSecondaryStorage(t *testing.T) {
	secondary := &rootSecondaryRateStore{}
	auth := MustNew(Options{
		SecondaryStorage: secondary,
		RateLimit: RateLimitOptions{
			Enabled: securityBool(true), Window: 17, Max: 1,
		},
	})
	first := rateRequest(t, auth, "/api/auth/ok")
	second := rateRequest(t, auth, "/api/auth/ok")
	if first.Code != contract.StatusOK || second.Code != contract.StatusTooManyRequests {
		t.Fatalf("secondary statuses = %d, %d", first.Code, second.Code)
	}
	secondary.mu.Lock()
	ttls := append([]int64(nil), secondary.ttls...)
	secondary.mu.Unlock()
	if len(ttls) != 2 || ttls[0] != 17 || ttls[1] != 17 {
		t.Fatalf("secondary TTLs = %#v", ttls)
	}
}

type rootSecondaryValueRateStore struct {
	rootSecondaryRateStore
}

func (store *rootSecondaryValueRateStore) GetValue(context.Context, string) (any, error) {
	return nil, nil
}

func TestRootRateLimitDefaultsToSecondaryValueStorage(t *testing.T) {
	secondary := &rootSecondaryValueRateStore{}
	auth := MustNew(Options{
		SecondaryValueStorage: secondary,
		RateLimit: RateLimitOptions{
			Enabled: securityBool(true), Window: 19, Max: 1,
		},
	})
	first := rateRequest(t, auth, "/api/auth/ok")
	second := rateRequest(t, auth, "/api/auth/ok")
	if first.Code != contract.StatusOK || second.Code != contract.StatusTooManyRequests {
		t.Fatalf("secondary value statuses = %d, %d", first.Code, second.Code)
	}
	secondary.mu.Lock()
	ttls := append([]int64(nil), secondary.ttls...)
	secondary.mu.Unlock()
	if len(ttls) != 2 || ttls[0] != 19 || ttls[1] != 19 {
		t.Fatalf("secondary value TTLs = %#v", ttls)
	}
}

type failingRateStore struct{}

func (failingRateStore) Get(context.Context, string) (*ratelimit.Record, error) {
	return nil, errors.New("rate store unavailable")
}

func (failingRateStore) Set(context.Context, string, ratelimit.Record, bool, int64) error {
	return errors.New("rate store unavailable")
}

func TestRootRateLimitStorageFailureIsRedacted(t *testing.T) {
	auth := MustNew(Options{
		RateLimit: RateLimitOptions{
			Enabled: securityBool(true), CustomStorage: failingRateStore{},
		},
	})
	response := rateRequest(t, auth, "/api/auth/ok")
	if response.Code != contract.StatusInternalServerError {
		t.Fatalf("failure status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Body.String() != `{"code":"INTERNAL_SERVER_ERROR","message":"Internal Server Error"}` {
		t.Fatalf("failure body = %q", response.Body.String())
	}
}

func TestRootRateLimitRejectsInvalidConfiguration(t *testing.T) {
	if _, err := New(Options{RateLimit: RateLimitOptions{Storage: "redis"}}); err == nil {
		t.Fatal("invalid storage accepted")
	}
	if _, err := New(Options{RateLimit: RateLimitOptions{
		Storage: "secondary-storage", Enabled: securityBool(true),
	}}); err == nil {
		t.Fatal("missing secondary storage accepted")
	}
	if _, err := New(Options{RateLimit: RateLimitOptions{
		Fields: map[string]string{"unknown": "x"},
	}}); err == nil {
		t.Fatal("unknown field accepted")
	}
}
