package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Add(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type keyStore struct {
	mu   sync.Mutex
	keys []JWK
	next int
}

func (store *keyStore) get(*engine.Context) ([]JWK, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneKeys(store.keys), nil
}

func (store *keyStore) create(_ *engine.Context, key JWK) (JWK, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.next++
	key.ID = fmt.Sprintf("key-%d", store.next)
	store.keys = append(store.keys, cloneKey(key))
	return cloneKey(key), nil
}

func (store *keyStore) snapshot() []JWK {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneKeys(store.keys)
}

func baseTestOptions(store *keyStore, clock *testClock) Options {
	state := SessionState{
		Session: storage.Record{
			"id": "session-1", "token": "token-1", "userId": "user-1",
			"expiresAt": clock.Now().Add(time.Hour),
		},
		User: storage.Record{
			"id": "user-1", "name": "Ada Lovelace", "email": "ada@example.com",
			"emailVerified": true,
		},
	}
	return Options{
		Adapter: AdapterOptions{GetJWKs: store.get, CreateJWK: store.create},
		Runtime: Runtime{
			Clock: clock.Now, Secret: testSecret, BaseURL: "http://localhost:3000/api/auth",
			ResolveSession: func(_ *engine.Context, _ bool) (*SessionState, error) {
				clone := cloneSessionState(state)
				return &clone, nil
			},
			SerializeUser: func(record storage.Record) any { return cloneRecord(record) },
		},
	}
}

func newTestDispatcher(t *testing.T, options Options, core ...engine.Endpoint) (*engine.Dispatcher, engine.Plugin) {
	t.Helper()
	descriptor, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry(core, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher, descriptor
}

func request(method, path string, body any) contract.Request {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	return contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "localhost:3000", Body: encoded,
	})
}

func decodeObjectResponse(t *testing.T, response contract.Response) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(response.Body(), &value); err != nil {
		t.Fatalf("decode status=%d body=%q: %v", response.Status(), response.Body(), err)
	}
	return value
}

func tokenParts(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token = %q", token)
	}
	var header, payload map[string]any
	headerBytes, err := rawURL.DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerBytes, &header) != nil {
		t.Fatalf("header = %q err=%v", parts[0], err)
	}
	payloadBytes, err := rawURL.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payloadBytes, &payload) != nil {
		t.Fatalf("payload = %q err=%v", parts[1], err)
	}
	return header, payload
}
