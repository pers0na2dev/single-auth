package passkey

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
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

type sequenceReader struct {
	mu   sync.Mutex
	next byte
}

func (r *sequenceReader) Read(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range buffer {
		buffer[index] = r.next
		r.next++
	}
	return len(buffer), nil
}

type mutableClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *mutableClock) Set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

type testHarness struct {
	adapter    storage.Adapter
	dispatcher *engine.Dispatcher
	clock      *mutableClock

	registrationVerifier   RegistrationVerifier
	authenticationVerifier AuthenticationVerifier
	registrationCalls      atomic.Int64
	authenticationCalls    atomic.Int64
	issuedSessions         atomic.Int64
}

func newHarness(t *testing.T, configure func(*Options, *testHarness)) *testHarness {
	t.Helper()
	clock := &mutableClock{now: time.Date(2026, time.August, 8, 9, 10, 11, 0, time.UTC)}
	schema, err := storage.CoreSchema().Merge(Schema())
	if err != nil {
		t.Fatal(err)
	}
	var identifiers atomic.Int64
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithClock(clock.Now),
		memory.WithIDGenerator(func(model string) (any, error) {
			return fmt.Sprintf("%s-%03d", model, identifiers.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	harness := &testHarness{adapter: adapter, clock: clock}
	harness.registrationVerifier = func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
		return webauthn.VerifiedRegistrationResponse{Verified: false}, nil
	}
	harness.authenticationVerifier = func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
		return webauthn.VerifiedAuthenticationResponse{Verified: false}, nil
	}
	options := Options{
		BaseURL: "http://localhost:3000",
		AppName: "Single Auth Test App",
		Secret:  "test-passkey-secret-which-is-long-enough",
		Runtime: Runtime{
			Adapter: adapter,
			Clock:   clock.Now,
			Random:  &sequenceReader{},
			ResolveSession: func(ctx *engine.Context, resolution SessionResolution) (*SessionState, error) {
				headers := ctx.Request().Headers()
				if resolution == SessionFresh {
					if stale, _ := headers.Get("X-Test-Stale"); stale == "true" {
						return nil, contract.NewAPIError(
							contract.StatusForbidden, "SESSION_NOT_FRESH", "Session is not fresh",
						)
					}
				}
				userID, ok := headers.Get("X-Test-User")
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
					Session: storage.Record{"id": "resolved-session", "userId": userID}, User: user,
				}, nil
			},
			IssueSession: func(ctx *engine.Context, userID string) (*SessionState, error) {
				sequence := harness.issuedSessions.Add(1)
				now := clock.Now()
				session, createErr := adapter.Create(ctx.GoContext(), storage.CreateParams{
					Model: "session",
					Data: storage.Record{
						"userId": userID, "token": fmt.Sprintf("issued-%d", sequence),
						"expiresAt": now.Add(24 * time.Hour), "createdAt": now, "updatedAt": now,
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
				if user != nil {
					ctx.AddSetCookie(cookies.Serialize("single-auth.session_token", "issued", cookies.Options{
						Path: "/", HTTPOnly: true, SameSite: "lax",
					}))
				}
				return &SessionState{Session: session, User: user}, nil
			},
			VerifyRegistration: func(options webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
				harness.registrationCalls.Add(1)
				return harness.registrationVerifier(options)
			},
			VerifyAuthentication: func(options webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
				harness.authenticationCalls.Add(1)
				return harness.authenticationVerifier(options)
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
	return harness
}

func (h *testHarness) seedUser(t *testing.T, id, email string) storage.Record {
	t.Helper()
	now := h.clock.Now()
	user, err := h.adapter.Create(context.Background(), storage.CreateParams{
		Model: "user", ForceAllowID: true,
		Data: storage.Record{
			"id": id, "name": email, "email": email, "emailVerified": true,
			"createdAt": now, "updatedAt": now,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func (h *testHarness) seedPasskey(t *testing.T, userID, credentialID, name string) storage.Record {
	t.Helper()
	data := storage.Record{
		"userId": userID, "credentialID": credentialID, "publicKey": "AQID",
		"counter": uint32(0), "deviceType": "singleDevice", "backedUp": false,
		"transports": "internal,hybrid", "createdAt": h.clock.Now(), "aaguid": "test-aaguid",
	}
	if name != "" {
		data["name"] = name
	}
	record, err := h.adapter.Create(context.Background(), storage.CreateParams{Model: "passkey", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (h *testHarness) call(
	t *testing.T,
	method, path string,
	query url.Values,
	headers contract.Headers,
	body any,
) (contract.Response, error) {
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

func applyResponseCookies(headers *contract.Headers, response contract.Response) {
	current, _ := headers.Get("Cookie")
	updated := cookies.ApplySetCookies(current, response.Headers().Values("Set-Cookie"))
	headers.Set("Cookie", updated)
}

func decodeResponse[T any](t *testing.T, response contract.Response) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(response.Body(), &value); err != nil {
		t.Fatalf("decode response %s: %v", response.Body(), err)
	}
	return value
}

func assertAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	apiError, ok := contract.AsAPIError(err)
	if !ok {
		t.Fatalf("error = %T %v, want APIError", err, err)
	}
	if apiError.Status != status || apiError.Code != code {
		t.Fatalf("APIError = %#v, want status=%d code=%s", apiError, status, code)
	}
}
