package ratelimit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }
func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}
func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func boolPointer(value bool) *bool { return &value }

type testHeaders map[string][]string

func (headers testHeaders) Get(name string) string {
	for candidate, values := range headers {
		if strings.EqualFold(candidate, name) {
			return strings.Join(values, ", ")
		}
	}
	return ""
}

func requestFor(t *testing.T, target string) RequestInfo {
	t.Helper()
	return RequestInfo{
		URL: target,
		Headers: testHeaders{
			"X-Forwarded-For": {"198.51.100.10"},
		},
	}
}

func TestLimiterBuiltInRulesRetryAndPathKeying(t *testing.T) {
	clock := newFakeClock()
	store := NewMemoryStore(MemoryOptions{Now: clock.Now})
	limiter := New(Config{
		Enabled:     boolPointer(true),
		Production:  true,
		BasePath:    "/api/auth",
		DefaultRule: Rule{Window: 10, Max: 20},
		Now:         clock.Now,
	}, store)

	for index := 0; index < 3; index++ {
		result, err := limiter.Check(t.Context(), requestFor(t, "https://example.com/api/auth/sign-in/email?nonce=one"))
		if err != nil || !result.Allowed || result.Rule != (Rule{Window: 10, Max: 3}) {
			t.Fatalf("request %d = %#v, %v", index, result, err)
		}
	}
	blocked, err := limiter.Check(t.Context(), requestFor(t, "https://example.com/api/auth/sign-in/email?nonce=two"))
	if err != nil || blocked.Allowed || blocked.RetryAfter != 10 {
		t.Fatalf("blocked = %#v, %v", blocked, err)
	}
	if blocked.Key != "198.51.100.10|/sign-in/email" {
		t.Fatalf("key = %q", blocked.Key)
	}
	clock.Advance(3 * time.Second)
	blocked, err = limiter.Check(t.Context(), requestFor(t, "https://example.com/api/auth/sign-in/email?nonce=three"))
	if err != nil || blocked.RetryAfter != 7 {
		t.Fatalf("retry after 3 seconds = %#v, %v", blocked, err)
	}
	clock.Advance(8 * time.Second)
	allowed, err := limiter.Check(t.Context(), requestFor(t, "https://example.com/api/auth/sign-in/email"))
	if err != nil || !allowed.Allowed {
		t.Fatalf("window did not reset: %#v, %v", allowed, err)
	}
}

func TestLimiterCustomAndPluginRuleOrder(t *testing.T) {
	clock := newFakeClock()
	limiter := New(Config{
		Enabled:     boolPointer(true),
		Production:  true,
		DefaultRule: Rule{Window: 30, Max: 30},
		Now:         clock.Now,
		PluginRules: [][]MatcherRule{
			{{Match: func(path string) bool { return path == "/plugin" }, Rule: Rule{Window: 8, Max: 8}}},
			{{Match: func(string) bool { return true }, Rule: Rule{Window: 9, Max: 9}}},
		},
		CustomRules: []CustomRule{
			{Pattern: "/sign-in/*", Rule: Rule{Window: 10, Max: 2}},
			{Pattern: "/sign-up/email", Rule: Rule{Window: 10, Max: 3}},
			{Pattern: "/get-session", Disabled: true},
			{Pattern: "/plugin", Resolve: func(_ context.Context, _ RequestInfo, current Rule) (Rule, bool, error) {
				if current != (Rule{Window: 8, Max: 8}) {
					t.Fatalf("dynamic rule saw %#v", current)
				}
				return Rule{Window: 5, Max: 1}, true, nil
			}},
		},
	}, NewMemoryStore(MemoryOptions{Now: clock.Now}))

	for index := 0; index < 3; index++ {
		result, err := limiter.Check(t.Context(), requestFor(t, "https://example.com/sign-in/email"))
		if err != nil {
			t.Fatal(err)
		}
		if result.Allowed != (index < 2) {
			t.Fatalf("custom wildcard request %d allowed=%v", index, result.Allowed)
		}
	}
	disabled, err := limiter.Check(t.Context(), requestFor(t, "https://example.com/get-session"))
	if err != nil || disabled.Applied || !disabled.Allowed {
		t.Fatalf("disabled rule = %#v, %v", disabled, err)
	}
	first, err := limiter.Check(t.Context(), requestFor(t, "https://example.com/plugin"))
	if err != nil || !first.Allowed || first.Rule != (Rule{Window: 5, Max: 1}) {
		t.Fatalf("plugin/custom first = %#v, %v", first, err)
	}
	second, err := limiter.Check(t.Context(), requestFor(t, "https://example.com/plugin"))
	if err != nil || second.Allowed {
		t.Fatalf("plugin/custom second = %#v, %v", second, err)
	}
}

func TestLimiterMissingIPFailsClosedAndWarnsOnce(t *testing.T) {
	clock := newFakeClock()
	var warnings []string
	limiter := New(Config{
		Enabled:     boolPointer(true),
		Production:  true,
		DefaultRule: Rule{Window: 10, Max: 3},
		Now:         clock.Now,
		Warn:        func(message string) { warnings = append(warnings, message) },
	}, NewMemoryStore(MemoryOptions{Now: clock.Now}))
	request := RequestInfo{URL: "https://example.com/get-session"}
	var last Result
	for index := 0; index < 4; index++ {
		result, err := limiter.Check(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		last = result
	}
	if last.Allowed || last.Key != NoTrustedIPKey+"|/get-session" {
		t.Fatalf("fail-closed result = %#v", last)
	}
	if len(warnings) != 1 || warnings[0] != missingIPWarning {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestLimiterTrustedProxyAndDisabledTracking(t *testing.T) {
	clock := newFakeClock()
	config := Config{
		Enabled:     boolPointer(true),
		Production:  true,
		DefaultRule: Rule{Window: 10, Max: 3},
		IP:          IPOptions{TrustedProxies: []string{"10.0.0.0/8"}},
		Now:         clock.Now,
	}
	limiter := New(config, NewMemoryStore(MemoryOptions{Now: clock.Now}))
	request := RequestInfo{
		URL: "https://example.com/get-session",
		Headers: testHeaders{
			"X-Forwarded-For": {"203.0.113.7, 198.51.100.10, 10.0.0.5"},
		},
	}
	result, err := limiter.Check(t.Context(), request)
	if err != nil || result.Key != "198.51.100.10|/get-session" {
		t.Fatalf("trusted result = %#v, %v", result, err)
	}
	duplicateHeaders := RequestInfo{
		URL: "https://example.com/other",
		Headers: testHeaders{
			"X-Forwarded-For": {"198.51.100.11", "10.0.0.6"},
		},
	}
	result, err = limiter.Check(t.Context(), duplicateHeaders)
	if err != nil || result.Key != "198.51.100.11|/other" {
		t.Fatalf("duplicate forwarded headers = %#v, %v", result, err)
	}
	config.IP.DisableTracking = true
	disabled := New(config, NewMemoryStore(MemoryOptions{Now: clock.Now}))
	result, err = disabled.Check(t.Context(), request)
	if err != nil || result.Applied || !result.Allowed {
		t.Fatalf("disabled tracking = %#v, %v", result, err)
	}
}

func TestLimiterEnabledDefaultFollowsProduction(t *testing.T) {
	request := requestFor(t, "https://example.com/sign-in/email")
	development := New(Config{}, nil)
	result, err := development.Check(t.Context(), request)
	if err != nil || result.Applied || !result.Allowed {
		t.Fatalf("development default = %#v, %v", result, err)
	}
	production := New(Config{Production: true}, nil)
	result, err = production.Check(t.Context(), request)
	if err != nil || !result.Applied || !result.Allowed {
		t.Fatalf("production default = %#v, %v", result, err)
	}
}

func TestMemoryStoreAtomicConcurrency(t *testing.T) {
	clock := newFakeClock()
	store := NewMemoryStore(MemoryOptions{Now: clock.Now})
	const requests = 100
	const maximum = 10
	start := make(chan struct{})
	allowed := make(chan bool, requests)
	var group sync.WaitGroup
	for index := 0; index < requests; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := store.Consume(context.Background(), "client|/path", Rule{Window: 10, Max: maximum})
			if err != nil {
				t.Errorf("consume: %v", err)
				return
			}
			allowed <- result.Allowed
		}()
	}
	close(start)
	group.Wait()
	close(allowed)
	count := 0
	for value := range allowed {
		if value {
			count++
		}
	}
	if count != maximum {
		t.Fatalf("allowed %d, want %d", count, maximum)
	}
	record, err := store.Get(t.Context(), "client|/path")
	if err != nil || record == nil || record.Count != maximum {
		t.Fatalf("record = %#v, %v", record, err)
	}
}

func TestMemoryStoreExpiresAtExactTTLBoundary(t *testing.T) {
	clock := newFakeClock()
	store := NewMemoryStore(MemoryOptions{Now: clock.Now})
	first, err := store.Consume(t.Context(), "key", Rule{Window: 10, Max: 1})
	if err != nil || !first.Allowed {
		t.Fatalf("first = %#v, %v", first, err)
	}
	clock.Advance(10 * time.Second)
	boundary, err := store.Consume(t.Context(), "key", Rule{Window: 10, Max: 1})
	if err != nil || !boundary.Allowed {
		t.Fatalf("memory must expire at exact TTL boundary: %#v, %v", boundary, err)
	}
	if store.Len() != 1 {
		t.Fatalf("entries = %d", store.Len())
	}
}
