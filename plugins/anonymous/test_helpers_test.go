package anonymous

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type sequenceReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *sequenceReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	for index := range target {
		target[index] = reader.next
		reader.next++
	}
	return len(target), nil
}

type anonymousHarness struct {
	adapter      *memory.Adapter
	descriptor   engine.Plugin
	dispatcher   *engine.Dispatcher
	clock        func() time.Time
	tokens       atomic.Int64
	resolutions  []SessionResolution
	resolutionMu sync.Mutex
}

func newAnonymousHarness(
	t *testing.T,
	configure func(*Options, *anonymousHarness),
) *anonymousHarness {
	t.Helper()
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	var identifiers atomic.Int64
	schema, err := storage.CoreSchema().Merge(Schema())
	if err != nil {
		t.Fatal(err)
	}
	adapter := memory.MustNew(
		memory.WithSchema(schema),
		memory.WithClock(func() time.Time { return now }),
		memory.WithIDGenerator(func(model string) (any, error) {
			return fmt.Sprintf("%s-%04d", model, identifiers.Add(1)), nil
		}),
	)
	harness := &anonymousHarness{
		adapter: adapter,
		clock:   func() time.Time { return now },
	}
	options := Options{Runtime: Runtime{
		Adapter: adapter,
		Clock:   harness.clock,
		Random:  &sequenceReader{},
		ResolveSessionCookies: func(contract.Request) SessionCookies {
			return DefaultSessionCookies()
		},
	}}
	options.Runtime.ResolveSession = func(ctx *engine.Context, resolution SessionResolution) (*SessionState, error) {
		harness.resolutionMu.Lock()
		harness.resolutions = append(harness.resolutions, resolution)
		harness.resolutionMu.Unlock()
		header := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
		value, exists := cookies.Parse(header).Get("single-auth.session_token")
		if !exists || value == "" {
			if resolution == SessionOptional {
				return nil, nil
			}
			return nil, unauthorized()
		}
		token, _, _ := strings.Cut(value, ".")
		session, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
		})
		if findErr != nil {
			return nil, findErr
		}
		if session == nil {
			if resolution == SessionOptional {
				return nil, nil
			}
			return nil, unauthorized()
		}
		userID, _ := recordString(session, "userId")
		user, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if findErr != nil {
			return nil, findErr
		}
		if user == nil {
			return nil, unauthorized()
		}
		return &SessionState{Session: session, User: user}, nil
	}
	options.Runtime.IssueSession = func(ctx *engine.Context, userID string) (*SessionState, error) {
		token := fmt.Sprintf("session-%04d", harness.tokens.Add(1))
		session, createErr := adapter.Create(ctx.GoContext(), storage.CreateParams{
			Model: "session", Data: storage.Record{
				"userId": userID, "token": token, "expiresAt": now.Add(time.Hour),
			},
		})
		if createErr != nil {
			return nil, createErr
		}
		user, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if findErr != nil {
			return nil, findErr
		}
		ctx.AddSetCookie("single-auth.session_token=" + token + "; Path=/; HttpOnly; SameSite=Lax")
		return &SessionState{Session: session, User: user}, nil
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
	harness.descriptor = descriptor
	harness.dispatcher = dispatcher
	return harness
}

func (h *anonymousHarness) call(
	t *testing.T,
	method, path string,
	headers contract.Headers,
) (contract.Response, error) {
	t.Helper()
	request := contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "localhost",
		Headers: headers,
	})
	return h.dispatcher.Dispatch(request)
}

func (h *anonymousHarness) seedUser(
	t *testing.T,
	id, email string,
	anonymous bool,
) storage.Record {
	t.Helper()
	user, err := h.adapter.Create(context.Background(), storage.CreateParams{
		Model: "user", ForceAllowID: true,
		Data: storage.Record{
			"id": id, "email": email, "emailVerified": false,
			"name": "Seed", "isAnonymous": anonymous,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func (h *anonymousHarness) seedSession(
	t *testing.T,
	userID, token string,
) storage.Record {
	t.Helper()
	session, err := h.adapter.Create(context.Background(), storage.CreateParams{
		Model: "session", Data: storage.Record{
			"userId": userID, "token": token, "expiresAt": h.clock().Add(time.Hour),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func responseObject(t *testing.T, response contract.Response) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		t.Fatalf("decode response %q: %v", response.Body(), err)
	}
	return result
}

func responseErrorCode(t *testing.T, response contract.Response) string {
	t.Helper()
	code, _ := responseObject(t, response)["code"].(string)
	return code
}

func sessionCookie(response contract.Response) string {
	return cookies.ApplySetCookies("", response.Headers().Values("Set-Cookie"))
}

func requestHeaders(cookie string) contract.Headers {
	headers := contract.NewHeaders()
	if cookie != "" {
		headers.Set("Cookie", cookie)
	}
	return headers
}

type deleteFailingAdapter struct {
	storage.Adapter
	err error
}

func (adapter deleteFailingAdapter) Delete(context.Context, storage.DeleteParams) error {
	return adapter.err
}
