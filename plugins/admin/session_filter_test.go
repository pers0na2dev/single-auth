package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCoreListSessionsFiltersImpersonationSessions(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "filter-admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "filter-user@example.com", "password123")
	regularSession := signInIdentity(t, auth, user.Email, "password123")

	status, _, body := exchange(t, auth, http.MethodPost, "/admin/impersonate-user", admin.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK {
		t.Fatalf("impersonate status=%d body=%#v", status, body)
	}

	request := httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/list-sessions", nil)
	request.Header.Set("Origin", "http://auth.example.test")
	request.Header.Set("Cookie", regularSession.Cookie)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	var sessions []map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("decode status=%d body=%q: %v", recorder.Code, recorder.Body.String(), err)
	}
	if recorder.Code != http.StatusOK || len(sessions) != 2 {
		t.Fatalf("status=%d sessions=%#v", recorder.Code, sessions)
	}
	for _, session := range sessions {
		if value, exists := session["impersonatedBy"]; exists && value != nil && value != "" {
			t.Fatalf("impersonation session leaked: %#v", session)
		}
	}
}
