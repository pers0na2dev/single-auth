package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	authlogger "github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
	storagememory "github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type rateLimiterHTTPCase struct {
	suite           string
	title           string
	storageBackends []string
	run             func(*testing.T, rateLimiterTransport)
}

func (test rateLimiterHTTPCase) key() string {
	return test.suite + "\x00" + test.title
}

type rateLimiterRequest struct {
	method  string
	target  string
	headers http.Header
	body    []byte
}

type rateLimiterResponse struct {
	status  int
	headers http.Header
	body    []byte
}

type rateLimiterTransport struct {
	name string
	bind func(*testing.T, *Auth) func(context.Context, rateLimiterRequest) (rateLimiterResponse, error)
}

func TestRateLimiterHTTPScenarios(t *testing.T) {
	cases := rateLimiterHTTPCases()
	seen := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		if test.suite == "" || test.title == "" || test.run == nil {
			t.Fatalf("invalid rate-limiter scenario %#v", test)
		}
		if _, exists := seen[test.key()]; exists {
			t.Fatalf("duplicate rate-limiter case %q / %q", test.suite, test.title)
		}
		seen[test.key()] = struct{}{}
		for _, transport := range rateLimiterTransports() {
			t.Run(test.suite+"/"+test.title+"/"+transport.name, func(t *testing.T) {
				test.run(t, transport)
			})
		}
	}
	if len(seen) != 28 {
		t.Fatalf("rate-limiter scenarios=%d, want 28", len(seen))
	}
}

func rateLimiterTransports() []rateLimiterTransport {
	return []rateLimiterTransport{
		{name: "net/http", bind: bindRateLimiterNetHTTP},
		{name: "fasthttp", bind: bindRateLimiterFastHTTP},
		{name: "fiber", bind: bindRateLimiterFiber},
	}
}

func bindRateLimiterNetHTTP(t *testing.T, auth *Auth) func(context.Context, rateLimiterRequest) (rateLimiterResponse, error) {
	t.Helper()
	handler := nethttptransport.NewHandler(auth.Dispatcher())
	return func(ctx context.Context, input rateLimiterRequest) (rateLimiterResponse, error) {
		request := httptest.NewRequest(input.method, "http://localhost:3000"+input.target, bytes.NewReader(input.body)).WithContext(ctx)
		request.Header = input.headers.Clone()
		request.RemoteAddr = "127.0.0.1:43123"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return rateLimiterResponse{status: recorder.Code, headers: recorder.Header().Clone(), body: append([]byte(nil), recorder.Body.Bytes()...)}, nil
	}
}

func bindRateLimiterFastHTTP(t *testing.T, auth *Auth) func(context.Context, rateLimiterRequest) (rateLimiterResponse, error) {
	t.Helper()
	adapter := fasthttptransport.New(auth.Dispatcher(), fasthttptransport.WithContextProvider(func(*fasthttpserver.RequestCtx) context.Context {
		return context.Background()
	}))
	return func(_ context.Context, input rateLimiterRequest) (rateLimiterResponse, error) {
		var request fasthttpserver.Request
		request.Header.SetMethod(input.method)
		request.SetRequestURI("http://localhost:3000" + input.target)
		request.Header.SetHost("localhost:3000")
		for name, values := range input.headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		request.SetBody(input.body)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123}, nil)
		adapter.Serve(&requestContext)
		headers := make(http.Header)
		requestContext.Response.Header.VisitAll(func(name, value []byte) { headers.Add(string(name), string(value)) })
		return rateLimiterResponse{status: requestContext.Response.StatusCode(), headers: headers, body: append([]byte(nil), requestContext.Response.Body()...)}, nil
	}
}

func bindRateLimiterFiber(t *testing.T, auth *Auth) func(context.Context, rateLimiterRequest) (rateLimiterResponse, error) {
	t.Helper()
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(auth.Dispatcher()))
	return func(ctx context.Context, input rateLimiterRequest) (rateLimiterResponse, error) {
		request, err := http.NewRequestWithContext(ctx, input.method, "http://localhost:3000"+input.target, bytes.NewReader(input.body))
		if err != nil {
			return rateLimiterResponse{}, err
		}
		request.Header = input.headers.Clone()
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			return rateLimiterResponse{}, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return rateLimiterResponse{status: response.StatusCode, headers: response.Header.Clone(), body: body}, err
	}
}

func rateLimiterHTTPCases() []rateLimiterHTTPCase {
	return []rateLimiterHTTPCase{
		{suite: "rate-limiter", title: "should return 429 after 3 request for sign-in", storageBackends: []string{"memory"}, run: replayRateLimiterSignInLimit},
		{suite: "rate-limiter", title: "should reset the limit after the window period", storageBackends: []string{"memory"}, run: replayRateLimiterReset},
		{suite: "rate-limiter", title: "should respond the correct retry-after header", storageBackends: []string{"memory"}, run: replayRateLimiterRetryAfter},
		{suite: "rate-limiter", title: "should rate limit based on the path", storageBackends: []string{"memory"}, run: replayRateLimiterPathBuckets},
		{suite: "rate-limiter", title: "non-special-rules limits", storageBackends: []string{"memory"}, run: replayRateLimiterDefaultLimit},
		{suite: "rate-limiter", title: "query params should be ignored", storageBackends: []string{"memory"}, run: replayRateLimiterIgnoresQuery},
		{suite: "atomic concurrent enforcement > memory storage", title: "lets exactly one of two simultaneous requests through", storageBackends: []string{"memory"}, run: replayRateLimiterConcurrent("memory")},
		{suite: "atomic concurrent enforcement > memory storage", title: "resets the count once the window elapses", storageBackends: []string{"memory"}, run: replayRateLimiterAtomicReset("memory")},
		{suite: "atomic concurrent enforcement > database storage", title: "lets exactly one of two simultaneous requests through", storageBackends: []string{"database"}, run: replayRateLimiterConcurrent("database")},
		{suite: "atomic concurrent enforcement > database storage", title: "resets the count once the window elapses", storageBackends: []string{"database"}, run: replayRateLimiterAtomicReset("database")},
		{suite: "database cleanup", title: "awaits expired row cleanup when no background handler is configured", storageBackends: []string{"database"}, run: replayRateLimiterDatabaseCleanup},
		{suite: "custom rate limiting storage", title: "should use custom storage", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterSecondaryStorage},
		{suite: "should work with custom rules", title: "should use custom rules", storageBackends: []string{"database"}, run: replayRateLimiterCustomRules},
		{suite: "should work with custom rules", title: "should use default rules if custom rules are not defined", storageBackends: []string{"database"}, run: replayRateLimiterCustomDefault},
		{suite: "should work with custom rules", title: "should not rate limit if custom rule is false", storageBackends: []string{"database"}, run: replayRateLimiterCustomDisabled},
		{suite: "should work in development/test environment", title: "should work in development environment", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterEnvironment("development")},
		{suite: "should work in development/test environment", title: "should work in test environment", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterEnvironment("test")},
		{suite: "missing client IP warning", title: "should point users to ipAddressHeaders and trustedProxies when no client IP is available outside dev/test", storageBackends: []string{"memory"}, run: replayRateLimiterMissingIPWarning},
		{suite: "missing client IP warning", title: "should fail closed and still enforce the limit when no client IP is available", storageBackends: []string{"memory"}, run: replayRateLimiterMissingIPClosed},
		{suite: "forwarded IP chains", title: "should not key limits by untrusted forwarded chain entries", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterUntrustedChain},
		{suite: "forwarded IP chains", title: "should key the real client when trusted proxies are configured", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterTrustedChain},
		{suite: "IPv6 address normalization and rate limiting", title: "should normalize IPv6 addresses to canonical form", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterIPv6Canonical},
		{suite: "IPv6 address normalization and rate limiting", title: "should convert IPv4-mapped IPv6 to IPv4", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterIPv4Mapped},
		{suite: "IPv6 address normalization and rate limiting", title: "should support IPv6 subnet rate limiting", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterIPv6Subnet},
		{suite: "IPv6 address normalization and rate limiting", title: "should rate limit different IPv6 subnets separately", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterIPv6SeparateSubnets},
		{suite: "IPv6 address normalization and rate limiting", title: "should handle localhost IPv6 addresses", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterIPv6Localhost},
		{suite: "IPv6 address normalization and rate limiting", title: "should handle link-local IPv6 addresses", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterIPv6LinkLocal},
		{suite: "IPv6 address normalization and rate limiting", title: "IPv6 subnet should not affect IPv4 addresses", storageBackends: []string{"secondary-storage"}, run: replayRateLimiterIPv4Unaffected},
	}
}

func rateLimiterBool(value bool) *bool { return &value }

func newRateLimiterAuth(t *testing.T, options Options) *Auth {
	t.Helper()
	if options.Secret == "" {
		options.Secret = "0123456789abcdef0123456789abcdef"
	}
	if options.BaseURL == "" {
		options.BaseURL = "http://localhost:3000"
	}
	if !options.Logger.Disabled && options.Logger.Log == nil && options.Logger.Level == "" &&
		options.Logger.Output == nil && options.Logger.ErrorOutput == nil && options.Logger.DisableColors == nil {
		options.Logger.Disabled = true
	}
	options.EmailAndPassword.Enabled = true
	auth, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func seedRateLimiterUser(t *testing.T, auth *Auth) {
	t.Helper()
	if _, err := auth.API().SignUpEmail(t.Context(), SignUpEmailInput{
		Name: "test user", Email: "test@test.com", Password: "test123456",
	}); err != nil {
		t.Fatal(err)
	}
}

func rateLimiterHeaders(ip string) http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	if ip != "" {
		headers.Set("X-Forwarded-For", ip)
	}
	return headers
}

func rateLimiterSignInRequest(ip string) rateLimiterRequest {
	return rateLimiterRequest{
		method: http.MethodPost, target: "/api/auth/sign-in/email", headers: rateLimiterHeaders(ip),
		body: []byte(`{"email":"test@test.com","password":"test123456"}`),
	}
}

func rateLimiterGet(path, ip string) rateLimiterRequest {
	return rateLimiterRequest{method: http.MethodGet, target: path, headers: rateLimiterHeaders(ip)}
}

func rateLimiterCall(t *testing.T, exchange func(context.Context, rateLimiterRequest) (rateLimiterResponse, error), request rateLimiterRequest) rateLimiterResponse {
	t.Helper()
	response, err := exchange(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requireRateLimiterStatuses(t *testing.T, got []int, want ...int) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
}

func requireRateLimitedResponse(t *testing.T, response rateLimiterResponse) {
	t.Helper()
	if response.status != http.StatusTooManyRequests || string(response.body) != `{"message":"Too many requests. Please try again later."}` || response.headers.Get("X-Retry-After") == "" {
		t.Fatalf("limited response = %d headers=%v body=%q", response.status, response.headers, response.body)
	}
}

func replayRateLimiterSignInLimit(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "test", RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	statuses := make([]int, 0, 5)
	for range 5 {
		statuses = append(statuses, rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1")).status)
	}
	requireRateLimiterStatuses(t, statuses, 200, 200, 200, 429, 429)
}

func replayRateLimiterReset(t *testing.T, transport rateLimiterTransport) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	auth := newRateLimiterAuth(t, Options{Environment: "test", Clock: func() time.Time { return now }, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 4; attempt++ {
		response := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1"))
		if (attempt < 3 && response.status != 200) || (attempt == 3 && response.status != 429) {
			t.Fatalf("before reset attempt %d status=%d", attempt, response.status)
		}
	}
	now = now.Add(11 * time.Second)
	statuses := make([]int, 0, 5)
	for range 5 {
		statuses = append(statuses, rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1")).status)
	}
	requireRateLimiterStatuses(t, statuses, 200, 200, 200, 429, 429)
}

func replayRateLimiterRetryAfter(t *testing.T, transport rateLimiterTransport) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	auth := newRateLimiterAuth(t, Options{Environment: "test", Clock: func() time.Time { return now }, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	for range 3 {
		if response := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1")); response.status != 200 {
			t.Fatalf("warmup status=%d", response.status)
		}
	}
	now = now.Add(3 * time.Second)
	response := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1"))
	requireRateLimitedResponse(t, response)
	if got := response.headers.Get("X-Retry-After"); got != "7" {
		t.Fatalf("X-Retry-After=%q, want 7", got)
	}
}

func replayRateLimiterPathBuckets(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "test", RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	for range 3 {
		if status := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1")).status; status != 200 {
			t.Fatalf("sign-in warmup status=%d", status)
		}
	}
	if response := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1")); response.status != 429 {
		t.Fatalf("sign-in status=%d", response.status)
	}
	request := rateLimiterRequest{method: http.MethodPost, target: "/api/auth/sign-up/email", headers: rateLimiterHeaders("127.0.0.1"), body: []byte(`{"name":"new","email":"new-test@email.com","password":"test123456"}`)}
	if response := rateLimiterCall(t, exchange, request); response.status != 200 {
		t.Fatalf("separate sign-up bucket status=%d body=%s", response.status, response.body)
	}
}

func replayRateLimiterDefaultLimit(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "test", RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 25; attempt++ {
		response := rateLimiterCall(t, exchange, rateLimiterGet("/api/auth/get-session", "127.0.0.1"))
		want := 200
		if attempt >= 20 {
			want = 429
		}
		if response.status != want {
			t.Fatalf("attempt %d status=%d want=%d", attempt, response.status, want)
		}
	}
}

func replayRateLimiterIgnoresQuery(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "test", RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 25; attempt++ {
		response := rateLimiterCall(t, exchange, rateLimiterGet(fmt.Sprintf("/api/auth/list-sessions?test-query=%d", attempt), "127.0.0.1"))
		want := 401
		if attempt >= 20 {
			want = 429
		}
		if response.status != want {
			t.Fatalf("attempt %d status=%d want=%d body=%s", attempt, response.status, want, response.body)
		}
	}
}

func replayRateLimiterConcurrent(storageMode string) func(*testing.T, rateLimiterTransport) {
	return func(t *testing.T, transport rateLimiterTransport) {
		auth := newAtomicRateLimiterAuth(t, storageMode, nil)
		seedRateLimiterUser(t, auth)
		exchange := transport.bind(t, auth)
		start := make(chan struct{})
		statuses := make(chan int, 2)
		var group sync.WaitGroup
		for range 2 {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				response, err := exchange(context.Background(), rateLimiterSignInRequest("127.0.0.1"))
				if err != nil {
					t.Errorf("concurrent request: %v", err)
					return
				}
				statuses <- response.status
			}()
		}
		close(start)
		group.Wait()
		close(statuses)
		got := make([]int, 0, 2)
		for status := range statuses {
			got = append(got, status)
		}
		sort.Ints(got)
		requireRateLimiterStatuses(t, got, 200, 429)
	}
}

func replayRateLimiterAtomicReset(storageMode string) func(*testing.T, rateLimiterTransport) {
	return func(t *testing.T, transport rateLimiterTransport) {
		now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
		auth := newAtomicRateLimiterAuth(t, storageMode, func() time.Time { return now })
		seedRateLimiterUser(t, auth)
		exchange := transport.bind(t, auth)
		first := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1"))
		blocked := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1"))
		now = now.Add(11 * time.Second)
		allowed := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1"))
		requireRateLimiterStatuses(t, []int{first.status, blocked.status, allowed.status}, 200, 429, 200)
	}
}

func newAtomicRateLimiterAuth(t *testing.T, storageMode string, clock func() time.Time) *Auth {
	t.Helper()
	return newRateLimiterAuth(t, Options{
		Environment: "test", Clock: clock,
		RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Storage: storageMode, CustomRules: []ratelimit.CustomRule{{Pattern: "/sign-in/email", Rule: ratelimit.Rule{Window: 10, Max: 1}}}},
	})
}

type blockingDeleteAdapter struct {
	storage.Adapter
	called  chan struct{}
	release chan struct{}
	once    sync.Once
}

func (adapter *blockingDeleteAdapter) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
	if params.Model == "rateLimit" {
		adapter.once.Do(func() { close(adapter.called) })
		select {
		case <-adapter.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return adapter.Adapter.DeleteMany(ctx, params)
}

func replayRateLimiterDatabaseCleanup(t *testing.T, transport rateLimiterTransport) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	schema, err := storage.CoreSchema().Merge(configuredRateLimitSchema(RateLimitOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	base := storagememory.MustNew(storagememory.WithSchema(schema), storagememory.WithClock(func() time.Time { return now }))
	adapter := &blockingDeleteAdapter{Adapter: base, called: make(chan struct{}), release: make(chan struct{})}
	auth := newRateLimiterAuth(t, Options{Environment: "test", Clock: func() time.Time { return now }, Database: adapter, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Storage: "database", Window: 10, Max: 20}})
	if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{Model: "rateLimit", Data: storage.Record{"key": "127.0.0.1|/get-session", "count": int64(1), "lastRequest": now.Add(-11 * time.Second).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	exchange := transport.bind(t, auth)
	settled := make(chan rateLimiterResponse, 1)
	go func() {
		response, callErr := exchange(context.Background(), rateLimiterGet("/api/auth/get-session", "127.0.0.1"))
		if callErr != nil {
			t.Errorf("cleanup request: %v", callErr)
		}
		settled <- response
	}()
	select {
	case <-adapter.called:
	case <-time.After(5 * time.Second):
		t.Fatal("database cleanup was not called")
	}
	select {
	case response := <-settled:
		t.Fatalf("request settled before cleanup release: %#v", response)
	default:
	}
	close(adapter.release)
	select {
	case response := <-settled:
		if response.status != 200 {
			t.Fatalf("cleanup response status=%d body=%s", response.status, response.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not settle after cleanup release")
	}
}

type rateLimiterSecondaryStore struct {
	mu     sync.Mutex
	values map[string]string
	ttls   map[string]int64
}

func newRateLimiterSecondaryStore() *rateLimiterSecondaryStore {
	return &rateLimiterSecondaryStore{values: map[string]string{}, ttls: map[string]int64{}}
}

func (store *rateLimiterSecondaryStore) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *rateLimiterSecondaryStore) Set(_ context.Context, key, value string, ttl int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = value
	store.ttls[key] = ttl
	return nil
}

func (store *rateLimiterSecondaryStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.values, key)
	delete(store.ttls, key)
	return nil
}

func (store *rateLimiterSecondaryStore) snapshot() (map[string]string, map[string]int64) {
	store.mu.Lock()
	defer store.mu.Unlock()
	values := make(map[string]string, len(store.values))
	ttls := make(map[string]int64, len(store.ttls))
	for key, value := range store.values {
		values[key] = value
	}
	for key, ttl := range store.ttls {
		ttls[key] = ttl
	}
	return values, ttls
}

func replayRateLimiterSecondaryStorage(t *testing.T, transport rateLimiterTransport) {
	store := newRateLimiterSecondaryStore()
	auth := newRateLimiterAuth(t, Options{Environment: "test", SecondaryStorage: store, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	if status := rateLimiterCall(t, exchange, rateLimiterGet("/api/auth/get-session", "127.0.0.1")).status; status != 200 {
		t.Fatalf("get-session status=%d", status)
	}
	bootstrapValues, _ := store.snapshot()
	if len(bootstrapValues) != 3 || bootstrapValues["127.0.0.1|/get-session"] == "" {
		t.Fatalf("isolated Go bootstrap cardinality=%d keys=%v, want upstream-equivalent three entries including get-session bucket", len(bootstrapValues), sortedRateLimiterKeys(bootstrapValues))
	}
	lastRequest := int64(0)
	for attempt := 0; attempt < 4; attempt++ {
		response := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1"))
		values, ttls := store.snapshot()
		var record ratelimit.Record
		if err := json.Unmarshal([]byte(values["127.0.0.1|/sign-in/email"]), &record); err != nil {
			t.Fatalf("secondary record: %v, values=%v", err, values)
		}
		if record.LastRequest < lastRequest || record.Count != int64(min(attempt+1, 3)) || ttls["127.0.0.1|/sign-in/email"] != 10 {
			t.Fatalf("attempt %d record=%#v ttl=%d", attempt, record, ttls["127.0.0.1|/sign-in/email"])
		}
		lastRequest = record.LastRequest
		want := 200
		if attempt >= 3 {
			want = 429
		}
		if response.status != want {
			t.Fatalf("attempt %d status=%d want=%d", attempt, response.status, want)
		}
	}
}

func customRuleOptions() RateLimitOptions {
	return RateLimitOptions{Enabled: rateLimiterBool(true), Storage: "database", CustomRules: []ratelimit.CustomRule{
		{Pattern: "/sign-in/*", Rule: ratelimit.Rule{Window: 10, Max: 2}},
		{Pattern: "/sign-up/email", Rule: ratelimit.Rule{Window: 10, Max: 3}},
		{Pattern: "/get-session", Disabled: true},
	}}
}

func replayRateLimiterCustomRules(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "test", RateLimit: customRuleOptions()})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 4; attempt++ {
		status := rateLimiterCall(t, exchange, rateLimiterSignInRequest("127.0.0.1")).status
		want := 200
		if attempt >= 2 {
			want = 429
		}
		if status != want {
			t.Fatalf("sign-in attempt %d status=%d want=%d", attempt, status, want)
		}
	}
	for attempt := 0; attempt < 5; attempt++ {
		request := rateLimiterRequest{method: http.MethodPost, target: "/api/auth/sign-up/email", headers: rateLimiterHeaders("127.0.0.1"), body: []byte(fmt.Sprintf(`{"name":"test","email":"custom-%d@test.com","password":"test123456"}`, attempt))}
		status := rateLimiterCall(t, exchange, request).status
		want := 200
		if attempt >= 3 {
			want = 429
		}
		if status != want {
			t.Fatalf("sign-up attempt %d status=%d want=%d", attempt, status, want)
		}
	}
}

func replayRateLimiterCustomDefault(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "test", RateLimit: customRuleOptions()})
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 5; attempt++ {
		if status := rateLimiterCall(t, exchange, rateLimiterGet("/api/auth/get-session", "127.0.0.1")).status; status != 200 {
			t.Fatalf("default rule attempt %d status=%d", attempt, status)
		}
	}
}

func replayRateLimiterCustomDisabled(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "test", RateLimit: customRuleOptions()})
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 110; attempt++ {
		if response := rateLimiterCall(t, exchange, rateLimiterGet("/api/auth/get-session", "127.0.0.1")); response.status != 200 {
			t.Fatalf("disabled attempt %d status=%d", attempt, response.status)
		}
	}
}

func replayRateLimiterEnvironment(environment string) func(*testing.T, rateLimiterTransport) {
	return func(t *testing.T, transport rateLimiterTransport) {
		store := newRateLimiterSecondaryStore()
		auth := newRateLimiterAuth(t, Options{Environment: environment, SecondaryStorage: store, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 3}})
		seedRateLimiterUser(t, auth)
		exchange := transport.bind(t, auth)
		for attempt := 0; attempt < 4; attempt++ {
			status := rateLimiterCall(t, exchange, rateLimiterSignInRequest("")).status
			want := 200
			if attempt >= 3 {
				want = 429
			}
			if status != want {
				t.Fatalf("attempt %d status=%d want=%d", attempt, status, want)
			}
		}
		values, _ := store.snapshot()
		if _, exists := values["127.0.0.1|/sign-in/email"]; !exists {
			t.Fatalf("environment fallback keys=%v", sortedRateLimiterKeys(values))
		}
	}
}

const rateLimiterMissingIPWarning = "Rate limiting could not determine a client IP and is falling back to a single shared per-path bucket. Ensure your runtime forwards a trusted client IP header, then set `advanced.ipAddress.ipAddressHeaders` or `advanced.ipAddress.trustedProxies` so the address can be resolved."

func replayRateLimiterMissingIPWarning(t *testing.T, transport rateLimiterTransport) {
	type warningEntry struct {
		level   authlogger.Level
		message string
	}
	var mu sync.Mutex
	warnings := []warningEntry{}
	auth := newRateLimiterAuth(t, Options{
		Environment: "production",
		Logger: authlogger.Options{Level: authlogger.Warn, Log: func(level authlogger.Level, message string, _ ...any) {
			mu.Lock()
			warnings = append(warnings, warningEntry{level: level, message: message})
			mu.Unlock()
		}},
		RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 3},
	})
	exchange := transport.bind(t, auth)
	if response := rateLimiterCall(t, exchange, rateLimiterGet("/api/auth/get-session", "")); response.status == 429 {
		t.Fatal("first missing-IP request was limited")
	}
	mu.Lock()
	got := append([]warningEntry(nil), warnings...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []warningEntry{{level: authlogger.Warn, message: rateLimiterMissingIPWarning}}) {
		t.Fatalf("warnings=%q", got)
	}
}

func replayRateLimiterMissingIPClosed(t *testing.T, transport rateLimiterTransport) {
	auth := newRateLimiterAuth(t, Options{Environment: "production", RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 3, Warn: func(string) {}}})
	exchange := transport.bind(t, auth)
	limited := false
	for range 6 {
		if response := rateLimiterCall(t, exchange, rateLimiterGet("/api/auth/get-session", "")); response.status == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("missing-IP requests bypassed the limiter")
	}
}

func replayRateLimiterUntrustedChain(t *testing.T, transport rateLimiterTransport) {
	store := newRateLimiterSecondaryStore()
	auth := newRateLimiterAuth(t, Options{Environment: "production", SecondaryStorage: store, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 4; attempt++ {
		status := rateLimiterCall(t, exchange, rateLimiterSignInRequest(fmt.Sprintf("198.51.100.%d, 10.0.0.5", attempt+20))).status
		want := 200
		if attempt >= 3 {
			want = 429
		}
		if status != want {
			t.Fatalf("attempt %d status=%d want=%d", attempt, status, want)
		}
	}
	values, _ := store.snapshot()
	if _, exists := values["no-trusted-ip|/sign-in/email"]; !exists {
		t.Fatalf("untrusted chain keys=%v", sortedRateLimiterKeys(values))
	}
}

func replayRateLimiterTrustedChain(t *testing.T, transport rateLimiterTransport) {
	store := newRateLimiterSecondaryStore()
	auth := newRateLimiterAuth(t, Options{Environment: "production", Advanced: AdvancedOptions{IPAddress: ratelimit.IPOptions{TrustedProxies: []string{"10.0.0.0/8"}}}, SecondaryStorage: store, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 20}})
	seedRateLimiterUser(t, auth)
	exchange := transport.bind(t, auth)
	for attempt := 0; attempt < 4; attempt++ {
		status := rateLimiterCall(t, exchange, rateLimiterSignInRequest(fmt.Sprintf("203.0.113.%d, 198.51.100.10, 10.0.0.5", attempt+20))).status
		want := 200
		if attempt >= 3 {
			want = 429
		}
		if status != want {
			t.Fatalf("attempt %d status=%d want=%d", attempt, status, want)
		}
	}
	values, _ := store.snapshot()
	if _, exists := values["198.51.100.10|/sign-in/email"]; !exists {
		t.Fatalf("trusted chain keys=%v", sortedRateLimiterKeys(values))
	}
	if _, exists := values["no-trusted-ip|/sign-in/email"]; exists {
		t.Fatalf("trusted chain fell back: keys=%v", sortedRateLimiterKeys(values))
	}
}

func newRateLimiterIPHarness(t *testing.T, transport rateLimiterTransport) (*rateLimiterSecondaryStore, func(context.Context, rateLimiterRequest) (rateLimiterResponse, error)) {
	t.Helper()
	store := newRateLimiterSecondaryStore()
	auth := newRateLimiterAuth(t, Options{Environment: "production", SecondaryStorage: store, RateLimit: RateLimitOptions{Enabled: rateLimiterBool(true), Window: 10, Max: 100}})
	return store, transport.bind(t, auth)
}

func sendRateLimiterIPs(t *testing.T, exchange func(context.Context, rateLimiterRequest) (rateLimiterResponse, error), ips ...string) {
	t.Helper()
	for _, ip := range ips {
		if response := rateLimiterCall(t, exchange, rateLimiterGet("/api/auth/get-session", ip)); response.status != 200 {
			t.Fatalf("IP %q status=%d body=%s", ip, response.status, response.body)
		}
	}
}

func requireRateLimiterKeys(t *testing.T, store *rateLimiterSecondaryStore, want ...string) {
	t.Helper()
	values, _ := store.snapshot()
	got := sortedRateLimiterKeys(values)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bucket keys=%v, want %v", got, want)
	}
}

func sortedRateLimiterKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func replayRateLimiterIPv6Canonical(t *testing.T, transport rateLimiterTransport) {
	store, exchange := newRateLimiterIPHarness(t, transport)
	sendRateLimiterIPs(t, exchange, "2001:db8::1", "2001:DB8::1", "2001:0db8::1", "2001:db8:0::1", "2001:0db8:0:0:0:0:0:1")
	requireRateLimiterKeys(t, store, "2001:0db8:0000:0000:0000:0000:0000:0000|/get-session")
}

func replayRateLimiterIPv4Mapped(t *testing.T, transport rateLimiterTransport) {
	store, exchange := newRateLimiterIPHarness(t, transport)
	sendRateLimiterIPs(t, exchange, "::ffff:192.0.2.1", "::FFFF:192.0.2.1", "::ffff:c000:0201")
	requireRateLimiterKeys(t, store, "192.0.2.1|/get-session")
}

func replayRateLimiterIPv6Subnet(t *testing.T, transport rateLimiterTransport) {
	store, exchange := newRateLimiterIPHarness(t, transport)
	sendRateLimiterIPs(t, exchange, "2001:db8:abcd:1234:0000:0000:0000:0001", "2001:db8:abcd:1234:1111:2222:3333:4444", "2001:db8:abcd:1234:ffff:ffff:ffff:ffff")
	requireRateLimiterKeys(t, store, "2001:0db8:abcd:1234:0000:0000:0000:0000|/get-session")
}

func replayRateLimiterIPv6SeparateSubnets(t *testing.T, transport rateLimiterTransport) {
	store, exchange := newRateLimiterIPHarness(t, transport)
	sendRateLimiterIPs(t, exchange, "2001:db8:abcd:1111::1", "2001:db8:abcd:1111::2", "2001:db8:abcd:2222::1", "2001:db8:abcd:2222::2")
	requireRateLimiterKeys(t, store, "2001:0db8:abcd:1111:0000:0000:0000:0000|/get-session", "2001:0db8:abcd:2222:0000:0000:0000:0000|/get-session")
}

func replayRateLimiterIPv6Localhost(t *testing.T, transport rateLimiterTransport) {
	store, exchange := newRateLimiterIPHarness(t, transport)
	sendRateLimiterIPs(t, exchange, "::1")
	requireRateLimiterKeys(t, store, "0000:0000:0000:0000:0000:0000:0000:0000|/get-session")
}

func replayRateLimiterIPv6LinkLocal(t *testing.T, transport rateLimiterTransport) {
	store, exchange := newRateLimiterIPHarness(t, transport)
	sendRateLimiterIPs(t, exchange, "fe80::1")
	requireRateLimiterKeys(t, store, "fe80:0000:0000:0000:0000:0000:0000:0000|/get-session")
}

func replayRateLimiterIPv4Unaffected(t *testing.T, transport rateLimiterTransport) {
	store, exchange := newRateLimiterIPHarness(t, transport)
	sendRateLimiterIPs(t, exchange, "192.168.1.1")
	requireRateLimiterKeys(t, store, "192.168.1.1|/get-session")
}

func TestRateLimiterHTTPScenarioDefinitions(t *testing.T) {
	for _, test := range rateLimiterHTTPCases() {
		if test.suite == "" || test.title == "" || test.run == nil {
			t.Fatalf("invalid case %#v", test)
		}
	}
}
