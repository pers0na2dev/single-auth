package passkey

import (
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestPasskeyCRUDAndOwnership(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedUser(t, "user-b", "b@example.com")
	passkeyA := harness.seedPasskey(t, "user-a", "credential-a", "Original")
	harness.seedPasskey(t, "user-b", "credential-b", "Other")
	headersA := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "user-a"})
	headersB := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "user-b"})

	response, err := harness.call(t, "GET", "/passkey/list-user-passkeys", nil, headersA, nil)
	if err != nil {
		t.Fatal(err)
	}
	listed := decodeResponse[[]storage.Record](t, response)
	if len(listed) != 1 || listed[0]["userId"] != "user-a" || listed[0]["credentialID"] != "credential-a" {
		t.Fatalf("listed passkeys = %#v", listed)
	}

	response, err = harness.call(t, "POST", "/passkey/update-passkey", nil, headersA, map[string]any{
		"id": passkeyA["id"], "name": "  Work laptop  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	updated := decodeResponse[struct {
		Passkey storage.Record `json:"passkey"`
	}](t, response)
	if updated.Passkey["name"] != "Work laptop" {
		t.Fatalf("updated passkey = %#v", updated.Passkey)
	}

	_, err = harness.call(t, "POST", "/passkey/update-passkey", nil, headersB, map[string]any{
		"id": passkeyA["id"], "name": "hacked",
	})
	assertAPIError(t, err, contract.StatusUnauthorized, ErrorRegistrationNotAllowed)
	_, err = harness.call(t, "POST", "/passkey/delete-passkey", nil, headersB, map[string]any{
		"id": passkeyA["id"],
	})
	assertAPIError(t, err, contract.StatusUnauthorized, "UNAUTHORIZED")

	unchanged, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: passkeyA["id"]}},
	})
	if err != nil || unchanged == nil || unchanged["name"] != "Work laptop" {
		t.Fatalf("passkey after ownership attacks = %#v, err=%v", unchanged, err)
	}

	response, err = harness.call(t, "POST", "/passkey/delete-passkey", nil, headersA, map[string]any{
		"id": passkeyA["id"],
	})
	if err != nil {
		t.Fatal(err)
	}
	deleted := decodeResponse[map[string]bool](t, response)
	if !deleted["status"] {
		t.Fatalf("delete response = %#v", deleted)
	}
	missing, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: passkeyA["id"]}},
	})
	if findErr != nil || missing != nil {
		t.Fatalf("deleted passkey = %#v, err=%v", missing, findErr)
	}
}

func TestPasskeyCRUDValidationAndAuthentication(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	passkey := harness.seedPasskey(t, "user-a", "credential-a", "Original")
	headers := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "user-a"})

	for _, endpoint := range []struct {
		method string
		path   string
		body   any
	}{
		{method: "GET", path: "/passkey/list-user-passkeys"},
		{method: "POST", path: "/passkey/update-passkey", body: map[string]any{"id": passkey["id"], "name": "new"}},
		{method: "POST", path: "/passkey/delete-passkey", body: map[string]any{"id": passkey["id"]}},
	} {
		_, err := harness.call(t, endpoint.method, endpoint.path, nil, contract.Headers{}, endpoint.body)
		assertAPIError(t, err, contract.StatusUnauthorized, "UNAUTHORIZED")
	}

	_, err := harness.call(t, "POST", "/passkey/update-passkey", nil, headers, map[string]any{
		"id": passkey["id"], "name": "   ",
	})
	assertAPIError(t, err, contract.StatusBadRequest, "VALIDATION_ERROR")
	_, err = harness.call(t, "POST", "/passkey/update-passkey", nil, headers, map[string]any{
		"id": "missing", "name": "new",
	})
	assertAPIError(t, err, contract.StatusNotFound, ErrorPasskeyNotFound)
	_, err = harness.call(t, "POST", "/passkey/delete-passkey", nil, headers, map[string]any{
		"id": "missing",
	})
	assertAPIError(t, err, contract.StatusNotFound, ErrorPasskeyNotFound)
	for _, invalid := range []any{
		map[string]any{},
		map[string]any{"id": nil},
		map[string]any{"id": 123},
	} {
		_, err = harness.call(t, "POST", "/passkey/delete-passkey", nil, headers, invalid)
		apiError, ok := contract.AsAPIError(err)
		if !ok || apiError.Status != contract.StatusBadRequest {
			t.Fatalf("invalid delete body %#v: %T %v", invalid, err, err)
		}
	}
	_, err = harness.call(t, "POST", "/passkey/delete-passkey", nil, headers, map[string]any{"id": ""})
	assertAPIError(t, err, contract.StatusNotFound, ErrorPasskeyNotFound)

	stored, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: passkey["id"]}},
	})
	if findErr != nil || stored == nil || stored["name"] != "Original" {
		t.Fatalf("validation mutated passkey = %#v, err=%v", stored, findErr)
	}
}
