package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestAdminRejectsMissingForgedAndImpersonationCookies(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "security-admin@example.com", "password123")
	user := signUpIdentity(t, auth, "User", "security-user@example.com", "password123")

	status, _, body := exchange(t, auth, http.MethodGet, "/admin/list-users", admin.Cookie+"x", nil)
	if status != http.StatusUnauthorized || body["code"] != "UNAUTHORIZED" {
		t.Fatalf("forged cookie status=%d body=%#v", status, body)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/create-user", "", map[string]any{
		"name": "Denied", "email": "missing-cookie@example.com",
	})
	if status != http.StatusUnauthorized || body["code"] != "UNAUTHORIZED" {
		t.Fatalf("missing cookie status=%d body=%#v", status, body)
	}

	result, err := auth.API().Call(t.Context(), "createUser", singleauth.DirectCallInput{
		Method: http.MethodPost,
		Scheme: "http",
		Host:   "auth.example.test",
		Headers: contract.NewHeaders(
			contract.HeaderField{Name: "Origin", Value: "http://auth.example.test"},
		),
		Body: map[string]any{"name": "Denied Direct", "email": "denied-direct@example.com"},
	})
	if err == nil || result.Response.Status() != http.StatusUnauthorized {
		t.Fatalf("direct headers status=%d value=%#v err=%v", result.Response.Status(), result.Value, err)
	}

	status, headers, body := exchange(t, auth, http.MethodPost, "/admin/impersonate-user", admin.Cookie, map[string]any{"userId": user.ID})
	if status != http.StatusOK {
		t.Fatalf("impersonate status=%d body=%#v", status, body)
	}
	impersonated := cookies.ApplySetCookies(admin.Cookie, headers.Values("Set-Cookie"))
	parsed := cookies.Parse(impersonated)
	tampered := false
	for _, pair := range parsed.Pairs() {
		if strings.Contains(pair.Name, "admin_session") {
			parsed.Set(pair.Name, pair.Value+"tampered")
			tampered = true
		}
	}
	if !tampered {
		t.Fatalf("admin session cookie missing from %q", impersonated)
	}
	status, _, body = exchange(t, auth, http.MethodPost, "/admin/stop-impersonating", parsed.Header(), map[string]any{})
	if status != http.StatusInternalServerError || body["message"] != "Failed to find admin session" {
		t.Fatalf("tampered admin cookie status=%d body=%#v", status, body)
	}
}

func TestConcurrentAdminUpdatesListsAndPermissionChecks(t *testing.T) {
	auth := newRootAuth(t, Options{})
	admin := signUpIdentity(t, auth, "Admin", "concurrent-admin@example.com", "password123")
	const workers = 32
	users := make([]map[string]any, workers)
	for index := range users {
		users[index] = createDirectUser(t, auth, map[string]any{
			"name":  fmt.Sprintf("Concurrent %02d", index),
			"email": fmt.Sprintf("concurrent-%02d@example.com", index),
		})
	}

	start := make(chan struct{})
	errors := make(chan error, workers*3)
	var wait sync.WaitGroup
	for index := range users {
		index := index
		wait.Add(3)
		go func() {
			defer wait.Done()
			<-start
			result, err := auth.API().Call(context.Background(), "adminUpdateUser", singleauth.DirectCallInput{
				Method: http.MethodPost, Scheme: "http", Host: "auth.example.test",
				Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: admin.Cookie}),
				Body: map[string]any{
					"userId": users[index]["id"], "data": map[string]any{"name": fmt.Sprintf("Updated %02d", index)},
				},
			})
			if err != nil || result.Response.Status() != http.StatusOK {
				errors <- fmt.Errorf("update %d: status=%d err=%v", index, result.Response.Status(), err)
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			result, err := auth.API().Call(context.Background(), "listUsers", singleauth.DirectCallInput{
				Method: http.MethodGet, Scheme: "http", Host: "auth.example.test",
				Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: admin.Cookie}),
				Query:   url.Values{"limit": {"100"}},
			})
			if err != nil || result.Response.Status() != http.StatusOK {
				errors <- fmt.Errorf("list %d: status=%d err=%v", index, result.Response.Status(), err)
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			result, err := auth.API().Call(context.Background(), "userHasPermission", singleauth.DirectCallInput{
				Method: http.MethodPost, Scheme: "http", Host: "auth.example.test",
				Body: map[string]any{"role": "admin", "permissions": map[string]any{"user": []string{"create"}}},
			})
			value, ok := result.Value.(map[string]any)
			if err != nil || result.Response.Status() != http.StatusOK || !ok || value["success"] != true {
				errors <- fmt.Errorf("permission %d: status=%d value=%#v err=%v", index, result.Response.Status(), result.Value, err)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	for index, user := range users {
		stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: user["id"]}},
		})
		if err != nil || stored["name"] != fmt.Sprintf("Updated %02d", index) {
			t.Fatalf("user %d=%#v err=%v", index, stored, err)
		}
	}
}
