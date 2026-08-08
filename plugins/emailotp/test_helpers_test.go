package emailotp

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

type emailOTPHarness struct {
	adapter    storage.Adapter
	dispatcher *engine.Dispatcher
	clock      *testClock
	descriptor engine.Plugin

	mu             sync.Mutex
	messages       []OTPMessage
	refreshed      []SessionState
	issuedSessions atomic.Int64
	generated      atomic.Int64
}

func newEmailOTPHarness(t *testing.T, configure func(*Options, *emailOTPHarness)) *emailOTPHarness {
	t.Helper()
	clock := &testClock{now: time.Date(2026, time.August, 8, 10, 0, 0, 0, time.UTC)}
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
	harness := &emailOTPHarness{adapter: adapter, clock: clock}
	options := Options{
		GenerateOTP: func(OTPData, *engine.Context) (string, error) {
			return fmt.Sprintf("%06d", harness.generated.Add(1)), nil
		},
		SendVerificationOTP: func(_ context.Context, message OTPMessage, _ *engine.Context) error {
			harness.mu.Lock()
			harness.messages = append(harness.messages, message)
			harness.mu.Unlock()
			return nil
		},
		Runtime: Runtime{
			Adapter: adapter,
			Clock:   clock.Now,
			ResolveSession: func(ctx *engine.Context, _ SessionResolution) (*SessionState, error) {
				userID, ok := ctx.Request().Headers().Get("X-Test-User")
				if !ok || userID == "" {
					return nil, nil
				}
				user, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
					Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
				})
				if findErr != nil || user == nil {
					return nil, findErr
				}
				return &SessionState{
					Session: storage.Record{"id": "current-session", "userId": userID, "token": "current-token"},
					User:    user,
				}, nil
			},
			IssueSession: func(ctx *engine.Context, user storage.Record) (*SessionState, error) {
				userID, _ := recordString(user, "id")
				sequence := harness.issuedSessions.Add(1)
				session, createErr := adapter.Create(ctx.GoContext(), storage.CreateParams{
					Model: "session", Data: storage.Record{
						"userId": userID, "token": fmt.Sprintf("token-%d", sequence),
						"expiresAt": clock.Now().Add(time.Hour),
					},
				})
				if createErr != nil {
					return nil, createErr
				}
				ctx.AddSetCookie("single-auth.session_token=" + session["token"].(string))
				return &SessionState{Session: session, User: cloneRecord(user)}, nil
			},
			RefreshSession: func(_ *engine.Context, state SessionState) error {
				harness.mu.Lock()
				harness.refreshed = append(harness.refreshed, SessionState{
					Session: cloneRecord(state.Session), User: cloneRecord(state.User),
				})
				harness.mu.Unlock()
				return nil
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

func (h *emailOTPHarness) seedUser(t *testing.T, id, email string, verified bool) storage.Record {
	t.Helper()
	user, err := h.adapter.Create(context.Background(), storage.CreateParams{
		Model: "user", ForceAllowID: true,
		Data: storage.Record{
			"id": id, "name": email, "email": email, "emailVerified": verified,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func (h *emailOTPHarness) call(t *testing.T, method, path string, query url.Values, headers contract.Headers, body any) (contract.Response, error) {
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
	return h.dispatcher.Dispatch(contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "localhost:3000",
		RawQuery: rawQuery, Headers: headers, Body: encoded,
	}))
}

func (h *emailOTPHarness) latestMessage(t *testing.T) OTPMessage {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.messages) == 0 {
		t.Fatal("no OTP message was sent")
	}
	return h.messages[len(h.messages)-1]
}

func (h *emailOTPHarness) messageCount() int {
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

func emptyHeaders() contract.Headers { return contract.NewHeaders() }
