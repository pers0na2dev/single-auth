package apikey

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestAPIKeyCreateUpdateAuthoritativeSessionTransportRegression(t *testing.T) {
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newVerifyUpdateGetListHarnessWithSession(
				t,
				transport,
				baseVerifyUpdateGetListConfiguration(),
				singleauth.SessionOptions{CookieCache: singleauth.CookieCacheOptions{
					Enabled: true,
					MaxAge:  5 * time.Minute,
				}},
			)
			identity := harness.signUp(t, "authoritative-session")
			if !strings.Contains(identity.Cookie, "session_data") {
				t.Fatalf("sign-up did not issue a session_data cookie: %q", identity.Cookie)
			}
			created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{
				"userId": identity.ID,
			})
			if _, err := harness.adapter.DeleteMany(t.Context(), storage.DeleteManyParams{
				Model: "session", Where: []storage.Where{{Field: "userId", Value: identity.ID}},
			}); err != nil {
				t.Fatal(err)
			}

			cacheStatus, _, cached := harness.exchange(t, http.MethodGet, "/get-session", identity.Cookie, nil, nil)
			if cacheStatus != http.StatusOK || cached["session"] == nil || cached["user"] == nil {
				t.Fatalf("valid session_data cache was not retained: status=%d body=%#v", cacheStatus, cached)
			}

			createStatus, _, createBody := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{}, nil)
			assertAPIKeyUnauthorizedSessionBody(t, createStatus, createBody)
			updateStatus, _, updateBody := harness.exchange(t, http.MethodPost, "/api-key/update", identity.Cookie, map[string]any{
				"keyId": created["id"], "name": "must-not-update",
			}, nil)
			assertAPIKeyUnauthorizedSessionBody(t, updateStatus, updateBody)
		})
	}
}

func TestAPIKeyUpdateZodNullAndMetadataTransportRegression(t *testing.T) {
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newVerifyUpdateGetListHarness(t, transport, baseVerifyUpdateGetListConfiguration())
			identity := harness.signUp(t, "update-validation")
			created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{
				"userId": identity.ID,
			})
			keyID := created["id"]

			invalid := []struct {
				name  string
				field string
				value any
			}{
				{name: "keyId-null", field: "keyId", value: nil},
				{name: "keyId-number", field: "keyId", value: 7},
				{name: "configId-null", field: "configId", value: nil},
				{name: "configId-number", field: "configId", value: 7},
				{name: "name-null", field: "name", value: nil},
				{name: "name-number", field: "name", value: 7},
				{name: "enabled-null", field: "enabled", value: nil},
				{name: "enabled-string", field: "enabled", value: "true"},
				{name: "rateLimitEnabled-null", field: "rateLimitEnabled", value: nil},
				{name: "rateLimitEnabled-string", field: "rateLimitEnabled", value: "true"},
				{name: "remaining-null", field: "remaining", value: nil},
				{name: "remaining-string", field: "remaining", value: "1"},
				{name: "refillAmount-null", field: "refillAmount", value: nil},
				{name: "refillAmount-string", field: "refillAmount", value: "1"},
				{name: "refillInterval-null", field: "refillInterval", value: nil},
				{name: "refillInterval-string", field: "refillInterval", value: "1"},
				{name: "rateLimitTimeWindow-null", field: "rateLimitTimeWindow", value: nil},
				{name: "rateLimitTimeWindow-string", field: "rateLimitTimeWindow", value: "1"},
				{name: "rateLimitMax-null", field: "rateLimitMax", value: nil},
				{name: "rateLimitMax-string", field: "rateLimitMax", value: "1"},
			}
			for _, vector := range invalid {
				vector := vector
				t.Run(vector.name, func(t *testing.T) {
					body := map[string]any{"keyId": keyID, "name": "valid-name"}
					body[vector.field] = vector.value
					status, _, response := harness.exchange(t, http.MethodPost, "/api-key/update", identity.Cookie, body, nil)
					assertAPIKeyValidationBody(t, status, response)
				})
			}

			missingStatus, _, missingBody := harness.exchange(t, http.MethodPost, "/api-key/update", identity.Cookie, map[string]any{"name": "valid-name"}, nil)
			assertAPIKeyValidationBody(t, missingStatus, missingBody)

			coercionStatus, _, coercionBody := harness.exchange(t, http.MethodPost, "/api-key/update", identity.Cookie, map[string]any{
				"keyId": keyID, "name": "valid-name", "userId": nil,
			}, nil)
			assertAPIKeyUnauthorizedSessionBody(t, coercionStatus, coercionBody)

			for _, metadata := range []any{false, 0, ""} {
				createStatus, _, createBody := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{"metadata": metadata}, nil)
				assertAPIKeyMetadataTypeBody(t, createStatus, createBody)
				updateStatus, _, updateBody := harness.exchange(t, http.MethodPost, "/api-key/update", identity.Cookie, map[string]any{
					"keyId": keyID, "metadata": metadata,
				}, nil)
				assertAPIKeyMetadataTypeBody(t, updateStatus, updateBody)
			}

			withNullableValues := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{
				"userId":      identity.ID,
				"expiresIn":   7 * 24 * 60 * 60,
				"metadata":    map[string]any{"clear": true},
				"permissions": map[string][]string{"files": {"read"}},
			})
			cleared := harness.mustInvokeObject(t, "updateApiKey", http.MethodPost, "", map[string]any{
				"keyId": withNullableValues["id"], "userId": identity.ID,
				"expiresIn": nil, "metadata": nil, "permissions": nil,
			})
			if cleared["expiresAt"] != nil || cleared["metadata"] != nil || cleared["permissions"] != nil {
				t.Fatalf("nullable clears drifted: %#v", cleared)
			}
		})
	}
}

func assertAPIKeyUnauthorizedSessionBody(t *testing.T, status int, body map[string]any) {
	t.Helper()
	assertAPIKeyExactErrorBody(t, status, body, http.StatusUnauthorized, ErrorUnauthorizedSession, errorMessages[ErrorUnauthorizedSession])
}

func assertAPIKeyValidationBody(t *testing.T, status int, body map[string]any) {
	t.Helper()
	assertAPIKeyExactErrorBody(t, status, body, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
}

func assertAPIKeyMetadataTypeBody(t *testing.T, status int, body map[string]any) {
	t.Helper()
	assertAPIKeyExactErrorBody(t, status, body, http.StatusBadRequest, ErrorInvalidMetadataType, errorMessages[ErrorInvalidMetadataType])
}

func assertAPIKeyExactErrorBody(t *testing.T, status int, body map[string]any, wantStatus int, code, message string) {
	t.Helper()
	if status != wantStatus || !reflect.DeepEqual(body, map[string]any{"code": code, "message": message}) {
		t.Fatalf("error response status=%d body=%#v, want status=%d body=%#v", status, body, wantStatus, map[string]any{"code": code, "message": message})
	}
}
