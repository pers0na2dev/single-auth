package multisession

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const staticSecret = "0123456789abcdef0123456789abcdef"

func TestStaticListDeduplicatesUsersAndUsesSerializers(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	var gotTokens []string
	var gotOnlyActive bool
	states := []SessionState{
		{Session: storage.Record{"token": "one", "expiresAt": now.Add(time.Hour)}, User: storage.Record{"id": "u1"}},
		{Session: storage.Record{"token": "two", "expiresAt": now.Add(time.Hour)}, User: storage.Record{"id": "u1"}},
		{Session: storage.Record{"token": "three", "expiresAt": now.Add(-time.Second)}, User: storage.Record{"id": "u2"}},
	}
	plugin := MustNew(Options{Runtime: Runtime{
		Secret: staticSecret, Clock: func() time.Time { return now },
		ResolveSession: func(*engine.Context) (*SessionState, error) { return nil, nil },
		FindSession:    func(_ context.Context, _ string) (*SessionState, error) { return nil, nil },
		FindSessions: func(_ context.Context, tokens []string, onlyActive bool) ([]SessionState, error) {
			gotTokens = append([]string(nil), tokens...)
			gotOnlyActive = onlyActive
			return cloneStates(states), nil
		},
		RefreshSession: func(*engine.Context, SessionState, bool) error { return nil },
		DeleteSession:  func(context.Context, string) error { return nil },
		DeleteSessions: func(context.Context, []string) error { return nil },
		NewSession:     func(*engine.Context) *SessionState { return nil },
		SerializeSession: func(record storage.Record) any {
			return map[string]any{"serializedToken": record["token"]}
		},
		SerializeUser: func(record storage.Record) any {
			return map[string]any{"serializedID": record["id"]}
		},
	}})
	dispatcher := dispatcherForPlugin(t, plugin)
	parsed := cookies.Parsed{}
	for _, token := range []string{"one", "two", "three"} {
		parsed.Set(multiCookieName("single-auth.session_token", token), signedCookieValue(token, staticSecret))
	}
	request := contract.NewRequest(http.MethodGet, "/multi-session/list-device-sessions", contract.RequestOptions{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: parsed.Header()}),
	})
	response, err := dispatcher.Dispatch(request)
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	if !gotOnlyActive || !reflect.DeepEqual(gotTokens, []string{"one", "two", "three"}) {
		t.Fatalf("find sessions tokens=%#v onlyActive=%v", gotTokens, gotOnlyActive)
	}
	var result []map[string]map[string]any
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0]["session"]["serializedToken"] != "one" ||
		result[0]["user"]["serializedID"] != "u1" {
		t.Fatalf("serialized list = %#v", result)
	}
}

func TestStaticRevokeDeletesEverySessionCookieAndChunkWithoutFallback(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	state := SessionState{
		Session: storage.Record{"token": "active", "expiresAt": now.Add(time.Hour)},
		User:    storage.Record{"id": "u1"},
	}
	var deleted string
	resolved := SessionCookies{
		SessionToken: Cookie{Name: "app.token", Attributes: cookies.Options{Path: "/auth", HTTPOnly: true}},
		SessionData:  Cookie{Name: "app.data", Attributes: cookies.Options{Path: "/auth", HTTPOnly: true}},
		DontRemember: Cookie{Name: "app.remember", Attributes: cookies.Options{Path: "/auth", HTTPOnly: true}},
	}
	account := Cookie{Name: "app.account", Attributes: cookies.Options{Path: "/auth", HTTPOnly: true}}
	oauth := Cookie{Name: "app.oauth", Attributes: cookies.Options{Path: "/auth", HTTPOnly: true}}
	resolved.AccountData = &account
	resolved.OAuthState = &oauth
	plugin := MustNew(Options{Runtime: Runtime{
		Secret: staticSecret, Clock: func() time.Time { return now },
		ResolveSession: func(*engine.Context) (*SessionState, error) {
			copy := cloneState(state)
			return &copy, nil
		},
		FindSession: func(_ context.Context, _ string) (*SessionState, error) { return nil, nil },
		FindSessions: func(_ context.Context, _ []string, _ bool) ([]SessionState, error) {
			return []SessionState{}, nil
		},
		RefreshSession: func(*engine.Context, SessionState, bool) error { return nil },
		DeleteSession: func(_ context.Context, token string) error {
			deleted = token
			return nil
		},
		DeleteSessions: func(context.Context, []string) error { return nil },
		NewSession:     func(*engine.Context) *SessionState { return nil },
		ResolveSessionCookies: func(contract.Request) SessionCookies {
			return resolved
		},
	}})
	dispatcher := dispatcherForPlugin(t, plugin)
	requestCookies := cookies.Parsed{}
	requestCookies.Set(multiCookieName(resolved.SessionToken.Name, "active"), signedCookieValue("active", staticSecret))
	requestCookies.Set("app.data.0", "chunk-data")
	requestCookies.Set("app.account.0", "chunk-account")
	body, _ := json.Marshal(map[string]any{"sessionToken": "active"})
	request := contract.NewRequest(http.MethodPost, "/multi-session/revoke", contract.RequestOptions{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: requestCookies.Header()}),
		Body:    body,
	})
	response, err := dispatcher.Dispatch(request)
	if err != nil || response.Status() != http.StatusOK || deleted != "active" {
		t.Fatalf("status=%d deleted=%q err=%v body=%s", response.Status(), deleted, err, response.Body())
	}
	want := map[string]bool{
		multiCookieName("app.token", "active"): false,
		"app.token":                            true, "app.data": true, "app.account": true,
		"app.account.0": true, "app.oauth": true, "app.data.0": true, "app.remember": true,
	}
	for _, line := range response.Headers().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if _, exists := want[parsed.Name]; !exists {
				continue
			}
			if parsed.Attributes.MaxAge == nil || *parsed.Attributes.MaxAge != 0 ||
				parsed.Attributes.Path != "/auth" || !parsed.Attributes.HTTPOnly {
				t.Fatalf("expired cookie = %#v", parsed)
			}
			want[parsed.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expired cookie %q missing from %#v", name, response.Headers().Values("Set-Cookie"))
		}
	}
}

func dispatcherForPlugin(t *testing.T, plugin engine.Plugin) *engine.Dispatcher {
	t.Helper()
	registry, err := engine.NewRegistry(nil, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}
