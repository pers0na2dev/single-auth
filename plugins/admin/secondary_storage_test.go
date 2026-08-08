package admin

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage"
)

type adminSecondaryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newAdminSecondaryStore() *adminSecondaryStore {
	return &adminSecondaryStore{values: map[string]string{}}
}

func (store *adminSecondaryStore) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *adminSecondaryStore) Set(_ context.Context, key, value string, _ int64) error {
	store.mu.Lock()
	store.values[key] = value
	store.mu.Unlock()
	return nil
}

func (store *adminSecondaryStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	delete(store.values, key)
	store.mu.Unlock()
	return nil
}

func TestAdminUsesAuthoritativeSecondarySessionLifecycle(t *testing.T) {
	secondary := newAdminSecondaryStore()
	auth := newRootAuthConfigured(t, Options{}, func(options *singleauth.Options) {
		options.SecondaryStorage = secondary
		options.Session.CookieCache = singleauth.CookieCacheOptions{Enabled: true, MaxAge: 5 * time.Minute}
	})
	root := signUpIdentity(t, auth, "Admin", "secondary-root@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "secondary-user@example.com", "password123")
	_ = signInIdentity(t, auth, user.Email, "password123")

	databaseSessions, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "session"})
	if err != nil || len(databaseSessions) != 0 {
		t.Fatalf("database sessions=%#v err=%v", databaseSessions, err)
	}
	status, _, body := exchange(t, auth, http.MethodPost, "/admin/list-user-sessions", root.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK || len(body["sessions"].([]any)) != 2 {
		t.Fatalf("secondary list status=%d body=%#v", status, body)
	}
	first := body["sessions"].([]any)[0].(map[string]any)
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/revoke-user-session", root.Cookie, map[string]any{
		"sessionToken": first["token"],
	})
	if status != http.StatusOK || body["success"] != true {
		t.Fatalf("secondary revoke status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/list-user-sessions", root.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK || len(body["sessions"].([]any)) != 1 {
		t.Fatalf("secondary list after revoke status=%d body=%#v", status, body)
	}

	attacker := signUpIdentity(t, auth, "Second Admin", "secondary-attacker@example.com", "password123")
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/set-role", root.Cookie, map[string]any{
		"userId": attacker.ID, "role": "user",
	})
	if status != http.StatusOK {
		t.Fatalf("secondary demote status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodGet, "/admin/list-users", attacker.Cookie, nil)
	assertError(t, status, body, http.StatusForbidden, ErrorNotAllowedToListUsers)

	status, _, body = exchange(t, auth, http.MethodPost, "/admin/ban-user", root.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK {
		t.Fatalf("secondary ban status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/list-user-sessions", root.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK || len(body["sessions"].([]any)) != 0 {
		t.Fatalf("secondary sessions after ban status=%d body=%#v", status, body)
	}
}
