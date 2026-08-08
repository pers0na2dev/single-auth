package multisession

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestStandaloneAdapterFallbacksCoverAllSessionOperations(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	adapter := memory.MustNew(memory.WithInitialData(map[string][]storage.Record{
		"user": {
			{"id": "u1", "name": "One", "email": "one@example.test", "emailVerified": true, "createdAt": now, "updatedAt": now},
			{"id": "u2", "name": "Two", "email": "two@example.test", "emailVerified": true, "createdAt": now, "updatedAt": now},
		},
		"session": {
			{"id": "s1", "token": "one", "userId": "u1", "expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now},
			{"id": "s2", "token": "two", "userId": "u2", "expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now},
		},
	}))
	active := SessionState{
		Session: storage.Record{"token": "one", "userId": "u1", "expiresAt": now.Add(time.Hour)},
		User:    storage.Record{"id": "u1"},
	}
	var refreshed string
	descriptor := MustNew(Options{Runtime: Runtime{
		Adapter: adapter, Clock: func() time.Time { return now }, Secret: staticSecret,
		ResolveSession: func(*engine.Context) (*SessionState, error) {
			copy := cloneState(active)
			return &copy, nil
		},
		RefreshSession: func(_ *engine.Context, state SessionState, _ bool) error {
			refreshed, _ = recordString(state.Session, "token")
			return nil
		},
		NewSession: func(*engine.Context) *SessionState { return nil },
	}})
	signOut := engine.Endpoint{
		Name: "signOut", Path: "/sign-out", Methods: []string{"POST"},
		Handler: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(contract.StatusOK, map[string]any{"success": true})
		},
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{signOut}, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := fallbackCookieHeader("one", "two")

	listed, err := dispatcher.Dispatch(contract.NewRequest(
		http.MethodGet,
		"/multi-session/list-device-sessions",
		contract.RequestOptions{Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader})},
	))
	if err != nil {
		t.Fatal(err)
	}
	var sessions []any
	if json.Unmarshal(listed.Body(), &sessions) != nil || len(sessions) != 2 {
		t.Fatalf("fallback list = %s", listed.Body())
	}

	body, _ := json.Marshal(map[string]any{"sessionToken": "two"})
	activated, err := dispatcher.Dispatch(contract.NewRequest(
		http.MethodPost,
		"/multi-session/set-active",
		contract.RequestOptions{
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}), Body: body,
		},
	))
	if err != nil || activated.Status() != http.StatusOK || refreshed != "two" {
		t.Fatalf("fallback activate status=%d refreshed=%q err=%v", activated.Status(), refreshed, err)
	}

	body, _ = json.Marshal(map[string]any{"sessionToken": "one"})
	revoked, err := dispatcher.Dispatch(contract.NewRequest(
		http.MethodPost,
		"/multi-session/revoke",
		contract.RequestOptions{
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}), Body: body,
		},
	))
	if err != nil || revoked.Status() != http.StatusOK {
		t.Fatalf("fallback revoke status=%d err=%v body=%s", revoked.Status(), err, revoked.Body())
	}
	deletedOne, err := adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: "one"}},
	})
	if err != nil || deletedOne != nil {
		t.Fatalf("fallback DeleteSession = %#v, err=%v", deletedOne, err)
	}

	signedOut, err := dispatcher.Dispatch(contract.NewRequest(
		http.MethodPost,
		"/sign-out",
		contract.RequestOptions{Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: fallbackCookieHeader("two")})},
	))
	if err != nil || signedOut.Status() != http.StatusOK {
		t.Fatalf("fallback sign-out status=%d err=%v", signedOut.Status(), err)
	}
	deletedTwo, err := adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: "two"}},
	})
	if err != nil || deletedTwo != nil {
		t.Fatalf("fallback DeleteSessions = %#v, err=%v", deletedTwo, err)
	}
}

func fallbackCookieHeader(tokens ...string) string {
	parsed := cookies.Parsed{}
	for _, token := range tokens {
		parsed.Set(multiCookieName("single-auth.session_token", token), signedCookieValue(token, staticSecret))
	}
	return parsed.Header()
}
