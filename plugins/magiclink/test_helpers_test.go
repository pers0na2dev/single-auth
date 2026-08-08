package magiclink

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *testClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

type magicLinkHarness struct {
	adapter    storage.Adapter
	dispatcher *engine.Dispatcher
	descriptor engine.Plugin
	clock      *testClock

	mu       sync.Mutex
	messages []MagicLinkMessage
	issued   atomic.Int64
	tokens   atomic.Int64
}

func newMagicLinkHarness(t *testing.T, configure func(*Options, *magicLinkHarness)) *magicLinkHarness {
	t.Helper()
	clock := &testClock{now: time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)}
	var identifiers atomic.Int64
	adapter, err := memory.New(
		memory.WithSchema(storage.CoreSchema()),
		memory.WithClock(clock.Now),
		memory.WithIDGenerator(func(model string) (any, error) {
			return fmt.Sprintf("%s-%04d", model, identifiers.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	harness := &magicLinkHarness{adapter: adapter, clock: clock}
	options := Options{
		GenerateToken: func(context.Context, string) (string, error) {
			return fmt.Sprintf("MagicToken%02dABCDEFGHIJKLMNOPQRSTUVWXYZ", harness.tokens.Add(1)), nil
		},
		SendMagicLink: func(_ context.Context, message MagicLinkMessage, _ *engine.Context) error {
			harness.mu.Lock()
			harness.messages = append(harness.messages, message)
			harness.mu.Unlock()
			return nil
		},
		Runtime: Runtime{
			Adapter:  adapter,
			Clock:    clock.Now,
			BaseURL:  "http://localhost:3000",
			BasePath: "/api/auth",
			IssueSession: func(ctx *engine.Context, user storage.Record) (*SessionState, error) {
				sequence := harness.issued.Add(1)
				userID, _ := recordString(user, "id")
				session, createErr := adapter.Create(ctx.GoContext(), storage.CreateParams{
					Model: "session", Data: storage.Record{
						"userId": userID, "token": fmt.Sprintf("session-token-%d", sequence),
						"expiresAt": clock.Now().Add(time.Hour),
					},
				})
				if createErr != nil {
					return nil, createErr
				}
				ctx.AddSetCookie("single-auth.session_token=" + session["token"].(string))
				return &SessionState{Session: session, User: cloneRecord(user)}, nil
			},
		},
	}
	if configure != nil {
		configure(&options, harness)
	}
	descriptor, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry(nil, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	harness.dispatcher = dispatcher
	harness.descriptor = descriptor
	return harness
}

func (h *magicLinkHarness) seedUser(t *testing.T, id, email, name string, verified bool) storage.Record {
	t.Helper()
	user, err := h.adapter.Create(context.Background(), storage.CreateParams{
		Model: "user", ForceAllowID: true,
		Data: storage.Record{
			"id": id, "email": email, "name": name, "emailVerified": verified,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func (h *magicLinkHarness) call(t *testing.T, method, path string, query url.Values, headers contract.Headers, body any) (contract.Response, error) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		headers.Set("Content-Type", "application/json")
	}
	rawQuery := ""
	if query != nil {
		rawQuery = query.Encode()
	}
	request := contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "localhost:3000",
		RawQuery: rawQuery, Headers: headers, Body: encoded,
	})
	return h.dispatcher.Dispatch(request)
}

func (h *magicLinkHarness) latestMessage(t *testing.T) MagicLinkMessage {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.messages) == 0 {
		t.Fatal("no magic link was sent")
	}
	return h.messages[len(h.messages)-1]
}

func (h *magicLinkHarness) messageCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.messages)
}

func responseObject(t *testing.T, response contract.Response) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(response.Body(), &value); err != nil {
		t.Fatalf("decode response %q: %v", response.Body(), err)
	}
	return value
}

func responseCode(t *testing.T, response contract.Response) string {
	t.Helper()
	value := responseObject(t, response)
	code, _ := value["code"].(string)
	return code
}

func location(response contract.Response) string {
	value, _ := response.Headers().Get("Location")
	return value
}

func emptyHeaders() contract.Headers { return contract.NewHeaders() }
