package apikey

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/internal/conformancetest"
	"github.com/pers0na2dev/single-auth/storage"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"

	_ "modernc.org/sqlite"
)

type verifyUpdateGetListCase func(*testing.T, string) map[string]any

func TestAPIKeyVerifyUpdateGetListBehaviorAcrossTransports(t *testing.T) {
	cases := verifyUpdateGetListCases()
	if len(cases) != len(verifyUpdateGetListExpectedCases) {
		t.Fatalf("API-key verify/update/get/list cases=%d expectations=%d", len(cases), len(verifyUpdateGetListExpectedCases))
	}
	for _, testCase := range verifyUpdateGetListExpectedCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			run, exists := cases[testCase.Name]
			if !exists {
				t.Fatalf("missing API-key verify/update/get/list case %q", testCase.Name)
			}
			delete(cases, testCase.Name)
			for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					assertVerifyUpdateGetListSameJSON(t, run(t, transport), testCase.Want)
					conformancetest.Log(t, testCase.Name, conformancetest.Dimension{
						Transport:      verifyUpdateGetListEvidenceTransport(t, transport),
						StorageBackend: "sqlite",
					})
				})
			}
		})
	}
	if len(cases) != 0 {
		t.Fatalf("API-key verify/update/get/list cases without expectations: %#v", cases)
	}
}

func verifyUpdateGetListEvidenceTransport(t testing.TB, transport string) string {
	t.Helper()
	switch transport {
	case "net/http":
		return conformancetest.TransportNetHTTP
	case "fasthttp":
		return conformancetest.TransportFastHTTP
	case "fiber":
		return conformancetest.TransportFiber
	default:
		t.Fatalf("unsupported API-key verify/update/get/list transport %q", transport)
		return ""
	}
}

func verifyUpdateGetListCases() map[string]verifyUpdateGetListCase {
	titles := []string{
		"verify API key without key and userId",
		"verify API key with invalid key (should fail)",
		"should fail to verify API key 20 times in a row due to rate-limit",
		"should allow us to verify API key after rate-limit window has passed",
		"should return 429 when API key rate limit is exceeded via before hook",
		"should check if verifying an API key's remaining count does go down",
		"should fail if the API key has no remaining",
		"should fail if the API key is expired",
		"should fail to update API key name without headers or userId",
		"should update API key name with headers",
		"should fail to update API key name with a length larger than the allowed maximum",
		"should fail to update API key name with a length smaller than the allowed minimum",
		"should fail to update API key with no values to update",
		"should update API key expiresIn value",
		"should fail to update expiresIn value if `disableCustomExpiresTime` is enabled",
		"should fail to update expiresIn value if it's smaller than the allowed minimum",
		"should fail to update expiresIn value if it's larger than the allowed maximum",
		"should update API key remaining count",
		"should fail update the refillInterval value since it requires refillAmount as well",
		"should fail update the refillAmount value since it requires refillInterval as well",
		"should update the refillInterval and refillAmount value",
		"should update API key enable value",
		"should fail to update metadata with invalid metadata type",
		"should update metadata with valid metadata type",
		"update API key's returned metadata should be an object",
		"should not modify lastRequest when updating API key configuration",
		"should not auto-decrement remaining when updating API key",
		"should allow explicit remaining updates via body parameter",
		"verifyApiKey should still update lastRequest",
		"verifyApiKey should still decrement remaining",
		"should get an API key by id",
		"should fail to get an API key by ID that doesn't exist",
		"should successfully receive an object metadata from an API key",
		"should fail to list API keys without headers",
		"should list API keys with headers",
		"should list API keys with metadata as an object",
	}
	result := make(map[string]verifyUpdateGetListCase, len(titles))
	for _, title := range titles {
		title := title
		result[title] = func(t *testing.T, transport string) map[string]any {
			return runVerifyUpdateGetListCase(t, transport, title)
		}
	}
	return result
}

func runVerifyUpdateGetListCase(t *testing.T, transport, title string) map[string]any {
	t.Helper()
	configuration := baseVerifyUpdateGetListConfiguration()
	switch title {
	case "should fail to verify API key 20 times in a row due to rate-limit",
		"should allow us to verify API key after rate-limit window has passed":
		configuration.RateLimitTimeWindow = time.Second
	case "should return 429 when API key rate limit is exceeded via before hook":
		configuration.EnableSessionForAPIKeys = true
		configuration.RateLimitTimeWindow = time.Minute
		configuration.RateLimitMax = 2
	case "should fail to update expiresIn value if `disableCustomExpiresTime` is enabled":
		configuration.DisableCustomExpiresTime = true
	case "should fail to update expiresIn value if it's smaller than the allowed minimum":
		configuration.MinimumExpiresIn = 24 * time.Hour
	case "should fail to update expiresIn value if it's larger than the allowed maximum":
		configuration.MaximumExpiresIn = 24 * time.Hour
	}
	harness := newVerifyUpdateGetListHarness(t, transport, configuration)
	identity := harness.signUp(t, "api-key-vector")
	create := func(values map[string]any) map[string]any {
		body := map[string]any{"userId": identity.ID}
		for key, value := range values {
			body[key] = value
		}
		return harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", body)
	}
	update := func(cookie string, body map[string]any) map[string]any {
		return harness.mustInvokeObject(t, "updateApiKey", http.MethodPost, cookie, body)
	}
	verify := func(key string) map[string]any {
		return harness.mustInvokeObject(t, "verifyApiKey", http.MethodPost, "", map[string]any{"key": key})
	}

	switch title {
	case "verify API key without key and userId":
		created := create(nil)
		return verifyUpdateGetListVerifyValue(verify(fmt.Sprint(created["key"])))
	case "verify API key with invalid key (should fail)":
		return verifyUpdateGetListVerifyValue(verify("invalid"))
	case "should fail to verify API key 20 times in a row due to rate-limit":
		created := create(nil)
		valids := make([]any, 0, 20)
		errorCodes := make([]any, 0, 20)
		for index := 0; index < 20; index++ {
			verified := verify(fmt.Sprint(created["key"]))
			valids = append(valids, verified["valid"])
			errorValue, _ := verified["error"].(map[string]any)
			if errorValue == nil {
				errorCodes = append(errorCodes, nil)
			} else {
				errorCodes = append(errorCodes, errorValue["code"])
			}
		}
		return map[string]any{"valids": valids, "errorCodes": errorCodes}
	case "should allow us to verify API key after rate-limit window has passed":
		created := create(nil)
		for index := 0; index < 10; index++ {
			verify(fmt.Sprint(created["key"]))
		}
		harness.advance(1050 * time.Millisecond)
		return verifyUpdateGetListVerifyValue(verify(fmt.Sprint(created["key"])))
	case "should return 429 when API key rate limit is exceeded via before hook":
		created := create(nil)
		headers := http.Header{"X-Api-Key": {fmt.Sprint(created["key"])}}
		statuses := make([]int, 3)
		bodies := make([]map[string]any, 3)
		for index := range statuses {
			statuses[index], _, bodies[index] = harness.exchangeHeaders(t, http.MethodGet, "/get-session", headers, nil, nil)
		}
		return map[string]any{
			"firstError":  statuses[0] < http.StatusBadRequest,
			"secondError": statuses[1] < http.StatusBadRequest,
			"thirdError":  verifyUpdateGetListHTTPError(statuses[2], bodies[2]),
		}
	case "should check if verifying an API key's remaining count does go down":
		status, _, body := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{"remaining": 10}, nil)
		return map[string]any{
			"creationSucceeded":    status < http.StatusBadRequest,
			"creationError":        verifyUpdateGetListHTTPError(status, body),
			"assertionPathEntered": status < http.StatusBadRequest,
		}
	case "should fail if the API key has no remaining":
		created := create(map[string]any{"remaining": 1})
		return map[string]any{
			"first":  verifyUpdateGetListVerifyValue(verify(fmt.Sprint(created["key"]))),
			"second": verifyUpdateGetListVerifyValue(verify(fmt.Sprint(created["key"]))),
		}
	case "should fail if the API key is expired":
		created := create(map[string]any{"expiresIn": 24 * 60 * 60})
		harness.advance(48 * time.Hour)
		return verifyUpdateGetListVerifyValue(verify(fmt.Sprint(created["key"])))
	case "should fail to update API key name without headers or userId":
		created := create(nil)
		return map[string]any{"error": harness.directError(t, "updateApiKey", map[string]any{"keyId": created["id"], "name": "test-api-key"})}
	case "should update API key name with headers":
		created := create(nil)
		updated := update(identity.Cookie, map[string]any{"keyId": created["id"], "name": "Hello World"})
		_, hasPlaintext := updated["key"]
		return map[string]any{"idMatches": updated["id"] == created["id"], "nameChanged": updated["name"] != created["name"], "name": updated["name"], "plaintextOmitted": !hasPlaintext}
	case "should fail to update API key name with a length larger than the allowed maximum":
		created := create(nil)
		return map[string]any{"error": harness.directErrorWithCookie(t, "updateApiKey", identity.Cookie, map[string]any{"keyId": created["id"], "name": "test-api-key-that-is-longer-than-the-allowed-maximum"})}
	case "should fail to update API key name with a length smaller than the allowed minimum":
		created := create(nil)
		return map[string]any{"error": harness.directErrorWithCookie(t, "updateApiKey", identity.Cookie, map[string]any{"keyId": created["id"], "name": ""})}
	case "should fail to update API key with no values to update":
		created := create(nil)
		return map[string]any{"error": harness.directErrorWithCookie(t, "updateApiKey", identity.Cookie, map[string]any{"keyId": created["id"]})}
	case "should update API key expiresIn value":
		created := create(nil)
		before := harness.now()
		updated := update(identity.Cookie, map[string]any{"keyId": created["id"], "expiresIn": 7 * 24 * 60 * 60})
		expiresAt, err := time.Parse(time.RFC3339Nano, fmt.Sprint(updated["expiresAt"]))
		return map[string]any{"expiresAtPresent": err == nil, "expiresInSevenDays": err == nil && expiresAt.Equal(before.Add(7*24*time.Hour))}
	case "should fail to update expiresIn value if `disableCustomExpiresTime` is enabled":
		created := create(nil)
		return map[string]any{"error": harness.directErrorWithCookie(t, "updateApiKey", identity.Cookie, map[string]any{"keyId": created["id"], "expiresIn": 1000 * 60 * 60 * 24 * 7})}
	case "should fail to update expiresIn value if it's smaller than the allowed minimum":
		created := create(nil)
		return map[string]any{"error": harness.directErrorWithCookie(t, "updateApiKey", identity.Cookie, map[string]any{"keyId": created["id"], "expiresIn": 1})}
	case "should fail to update expiresIn value if it's larger than the allowed maximum":
		created := create(nil)
		return map[string]any{"error": harness.directErrorWithCookie(t, "updateApiKey", identity.Cookie, map[string]any{"keyId": created["id"], "expiresIn": 1000 * 60 * 60 * 24 * 365 * 10})}
	case "should update API key remaining count":
		created := create(nil)
		updated := update("", map[string]any{"keyId": created["id"], "remaining": 100, "userId": identity.ID})
		return map[string]any{"remaining": updated["remaining"]}
	case "should fail update the refillInterval value since it requires refillAmount as well":
		created := create(nil)
		return map[string]any{"error": harness.directError(t, "updateApiKey", map[string]any{"keyId": created["id"], "refillInterval": 1000, "userId": identity.ID})}
	case "should fail update the refillAmount value since it requires refillInterval as well":
		created := create(nil)
		return map[string]any{"error": harness.directError(t, "updateApiKey", map[string]any{"keyId": created["id"], "refillAmount": 10, "userId": identity.ID})}
	case "should update the refillInterval and refillAmount value":
		created := create(nil)
		updated := update("", map[string]any{"keyId": created["id"], "refillInterval": 10000, "refillAmount": 100, "userId": identity.ID})
		return map[string]any{"refillInterval": updated["refillInterval"], "refillAmount": updated["refillAmount"]}
	case "should update API key enable value":
		created := create(nil)
		updated := update("", map[string]any{"keyId": created["id"], "enabled": false, "userId": identity.ID})
		return map[string]any{"enabled": updated["enabled"]}
	case "should fail to update metadata with invalid metadata type":
		created := create(nil)
		return map[string]any{"error": harness.directError(t, "updateApiKey", map[string]any{"keyId": created["id"], "metadata": "invalid", "userId": identity.ID})}
	case "should update metadata with valid metadata type":
		created := create(nil)
		updated := update("", map[string]any{"keyId": created["id"], "metadata": map[string]any{"test": "test-123"}, "userId": identity.ID})
		return map[string]any{"metadata": updated["metadata"]}
	case "update API key's returned metadata should be an object":
		created := create(nil)
		updated := update("", map[string]any{"keyId": created["id"], "metadata": map[string]any{"test": "test-12345"}, "userId": identity.ID})
		_, isObject := updated["metadata"].(map[string]any)
		return map[string]any{"metadataIsObject": isObject, "metadata": updated["metadata"]}
	case "should not modify lastRequest when updating API key configuration":
		created := create(nil)
		updated := update("", map[string]any{"keyId": created["id"], "name": "updated-name", "userId": identity.ID})
		return map[string]any{"before": created["lastRequest"] == nil, "after": updated["lastRequest"] == nil}
	case "should not auto-decrement remaining when updating API key":
		created := create(map[string]any{"remaining": 100})
		updated := update("", map[string]any{"keyId": created["id"], "metadata": map[string]any{"foo": "bar"}, "userId": identity.ID})
		return map[string]any{"before": created["remaining"], "after": updated["remaining"]}
	case "should allow explicit remaining updates via body parameter":
		created := create(map[string]any{"remaining": 100})
		updated := update("", map[string]any{"keyId": created["id"], "remaining": 50, "userId": identity.ID})
		return map[string]any{"remaining": updated["remaining"], "lastRequestNull": updated["lastRequest"] == nil}
	case "verifyApiKey should still update lastRequest":
		created := create(nil)
		verified := verify(fmt.Sprint(created["key"]))
		status, _, fetched := harness.exchange(t, http.MethodGet, "/api-key/get", identity.Cookie, nil, url.Values{"id": {fmt.Sprint(created["id"])}, "configId": {"default"}})
		if status != http.StatusOK {
			t.Fatalf("get after verify status=%d body=%#v", status, fetched)
		}
		return map[string]any{"initialLastRequestNull": created["lastRequest"] == nil, "valid": verified["valid"], "lastRequestPresent": fetched["lastRequest"] != nil}
	case "verifyApiKey should still decrement remaining":
		created := create(map[string]any{"remaining": 100})
		verify(fmt.Sprint(created["key"]))
		status, _, fetched := harness.exchange(t, http.MethodGet, "/api-key/get", identity.Cookie, nil, url.Values{"id": {fmt.Sprint(created["id"])}, "configId": {"default"}})
		if status != http.StatusOK {
			t.Fatalf("get after verify status=%d body=%#v", status, fetched)
		}
		return map[string]any{"remaining": fetched["remaining"]}
	case "should get an API key by id":
		created := create(nil)
		status, _, fetched := harness.exchange(t, http.MethodGet, "/api-key/get", identity.Cookie, nil, url.Values{"id": {fmt.Sprint(created["id"])}})
		_, hasPlaintext := fetched["key"]
		return map[string]any{"dataPresent": status == http.StatusOK, "idMatches": fetched["id"] == created["id"], "plaintextOmitted": !hasPlaintext, "errorNull": status == http.StatusOK}
	case "should fail to get an API key by ID that doesn't exist":
		status, _, fetched := harness.exchange(t, http.MethodGet, "/api-key/get", identity.Cookie, nil, url.Values{"id": {"invalid"}})
		return map[string]any{"dataNull": status >= http.StatusBadRequest, "error": verifyUpdateGetListHTTPError(status, fetched)}
	case "should successfully receive an object metadata from an API key":
		created := create(map[string]any{"metadata": map[string]any{"test": "get-object"}})
		status, _, fetched := harness.exchange(t, http.MethodGet, "/api-key/get", identity.Cookie, nil, url.Values{"id": {fmt.Sprint(created["id"])}})
		if status != http.StatusOK {
			t.Fatalf("metadata get status=%d body=%#v", status, fetched)
		}
		_, defined := fetched["metadata"]
		_, isObject := fetched["metadata"].(map[string]any)
		return map[string]any{"metadataDefined": defined, "metadataIsObject": isObject, "metadata": fetched["metadata"]}
	case "should fail to list API keys without headers":
		return map[string]any{"error": harness.directError(t, "listApiKeys", nil)}
	case "should list API keys with headers":
		create(nil)
		status, _, listed := harness.exchange(t, http.MethodGet, "/api-key/list", identity.Cookie, nil, nil)
		if status != http.StatusOK {
			t.Fatalf("list status=%d body=%#v", status, listed)
		}
		keys, _ := listed["apiKeys"].([]any)
		plaintextOmitted := true
		for _, raw := range keys {
			key, _ := raw.(map[string]any)
			if _, exists := key["key"]; exists {
				plaintextOmitted = false
			}
		}
		return map[string]any{"nonEmpty": len(keys) > 0, "totalPositive": verifyUpdateGetListNumber(listed["total"]) > 0, "totalMatches": int64(len(keys)) == verifyUpdateGetListNumber(listed["total"]), "plaintextOmitted": plaintextOmitted}
	case "should list API keys with metadata as an object":
		create(map[string]any{"metadata": map[string]any{"test": "list-object"}})
		status, _, listed := harness.exchange(t, http.MethodGet, "/api-key/list", identity.Cookie, nil, nil)
		if status != http.StatusOK {
			t.Fatalf("list metadata status=%d body=%#v", status, listed)
		}
		keys, _ := listed["apiKeys"].([]any)
		metadata := make([]any, 0, len(keys))
		allObjects := true
		for _, raw := range keys {
			key, _ := raw.(map[string]any)
			if key["metadata"] == nil {
				continue
			}
			metadata = append(metadata, key["metadata"])
			if _, ok := key["metadata"].(map[string]any); !ok {
				allObjects = false
			}
		}
		var first any
		if len(metadata) > 0 {
			first = metadata[0]
		}
		return map[string]any{"nonEmpty": len(keys) > 0, "metadataCount": len(metadata), "allMetadataObjects": allObjects, "firstMetadata": first}
	default:
		t.Fatalf("unknown API-key verify/update/get/list case %q", title)
		return nil
	}
}

type verifyUpdateGetListHarness struct {
	orgAPIKeyHarness
	clockNanos      *atomic.Int64
	exchangeHeaders func(*testing.T, string, string, http.Header, any, url.Values) (int, http.Header, map[string]any)
}

func newVerifyUpdateGetListHarness(t *testing.T, transport string, configuration Configuration) verifyUpdateGetListHarness {
	return newVerifyUpdateGetListHarnessWithSession(t, transport, configuration, singleauth.SessionOptions{})
}

func newVerifyUpdateGetListHarnessWithSession(
	t *testing.T,
	transport string,
	configuration Configuration,
	session singleauth.SessionOptions,
) verifyUpdateGetListHarness {
	t.Helper()
	baseTime := time.Date(2026, time.August, 9, 12, 34, 56, 0, time.UTC)
	clockNanos := &atomic.Int64{}
	clockNanos.Store(baseTime.UnixNano())
	clock := func() time.Time { return time.Unix(0, clockNanos.Load()).UTC() }
	apiSchema, err := Schema(Options{})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(apiSchema)
	if err != nil {
		t.Fatal(err)
	}
	dsn := "file:verify_update_get_list_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(8)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close API-key verify/update/get/list SQLite database: %v", err)
		}
	})
	var sequence atomic.Int64
	adapter, err := sqliteadapter.New(database, sqliteadapter.Options{
		Schema: schema, Clock: clock,
		IDGenerator: func(model string) (any, error) {
			return fmt.Sprintf("%s-%d", model, sequence.Add(1)), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	var keySequence atomic.Int64
	factory := NewFactory(Options{
		Configurations: []Configuration{configuration},
		Runtime: Runtime{KeyGenerator: func(_ context.Context, length int, prefix string) (string, error) {
			value := fmt.Sprintf("%d", keySequence.Add(1))
			if len(value) < length {
				value += strings.Repeat("A", length-len(value))
			}
			return prefix + value[:length], nil
		}},
	})
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test", Secret: "0123456789abcdef0123456789abcdef",
		Database: adapter, Clock: clock, Session: session,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
				Verify: func(hash, value string) bool { return hash == "hashed:"+value },
			},
		},
		PluginFactories: []singleauth.PluginFactory{factory},
	})
	if err != nil {
		t.Fatal(err)
	}
	embedded := orgAPIKeyHarness{auth: auth, adapter: auth.Adapter(), clock: baseTime, roundTrip: newOrgAPIKeyRoundTrip(t, auth, transport)}
	return verifyUpdateGetListHarness{
		orgAPIKeyHarness: embedded,
		clockNanos:       clockNanos,
		exchangeHeaders:  newVerifyUpdateGetListHeaderExchange(t, auth, transport),
	}
}

func baseVerifyUpdateGetListConfiguration() Configuration {
	return Configuration{EnableMetadata: true}
}

func (h verifyUpdateGetListHarness) now() time.Time {
	return time.Unix(0, h.clockNanos.Load()).UTC()
}

func (h verifyUpdateGetListHarness) advance(duration time.Duration) {
	h.clockNanos.Add(int64(duration))
}

func (h verifyUpdateGetListHarness) directError(t *testing.T, name string, body any) map[string]any {
	t.Helper()
	return h.directErrorWithCookie(t, name, "", body)
}

func (h verifyUpdateGetListHarness) directErrorWithCookie(t *testing.T, name, cookie string, body any) map[string]any {
	t.Helper()
	method := http.MethodPost
	if name == "listApiKeys" {
		method = http.MethodGet
	}
	result, err := h.invoke(t, name, method, cookie, body)
	if err == nil {
		t.Fatalf("direct %s unexpectedly succeeded: %#v", name, result.Value)
	}
	apiErr, ok := contract.AsAPIError(err)
	if !ok {
		t.Fatalf("direct %s returned non-API error: %v", name, err)
	}
	return verifyUpdateGetListErrorValue(apiErr.Status, apiErr.Code, apiErr.Message)
}

func verifyUpdateGetListVerifyValue(result map[string]any) map[string]any {
	key, keyPresent := result["key"].(map[string]any)
	_, plaintextPresent := key["key"]
	var remaining, requestCount any
	lastRequestPresent := false
	if keyPresent {
		remaining = key["remaining"]
		requestCount = key["requestCount"]
		lastRequestPresent = key["lastRequest"] != nil
	}
	return map[string]any{
		"valid": result["valid"], "error": result["error"],
		"keyNull": result["key"] == nil, "keyPresent": keyPresent,
		"plaintextOmitted": !keyPresent || !plaintextPresent,
		"remaining":        remaining, "requestCount": requestCount,
		"lastRequestPresent": lastRequestPresent,
	}
}

func verifyUpdateGetListHTTPError(status int, body map[string]any) map[string]any {
	return verifyUpdateGetListErrorValue(status, fmt.Sprint(body["code"]), fmt.Sprint(body["message"]))
}

func verifyUpdateGetListErrorValue(status int, code, message string) map[string]any {
	return map[string]any{
		"statusCode": status, "status": verifyUpdateGetListStatusName(status),
		"code": code, "message": message,
	}
}

func verifyUpdateGetListStatusName(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusTooManyRequests:
		return "TOO_MANY_REQUESTS"
	default:
		return fmt.Sprintf("HTTP_%d", status)
	}
}

func verifyUpdateGetListNumber(value any) int64 {
	switch typed := value.(type) {
	case json.Number:
		result, _ := typed.Int64()
		return result
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func newVerifyUpdateGetListHeaderExchange(
	t *testing.T,
	auth *singleauth.Auth,
	transport string,
) func(*testing.T, string, string, http.Header, any, url.Values) (int, http.Header, map[string]any) {
	t.Helper()
	decode := func(t *testing.T, status int, responseHeaders http.Header, body []byte) (int, http.Header, map[string]any) {
		t.Helper()
		value := map[string]any{}
		if len(body) != 0 {
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatalf("decode header exchange status=%d body=%q: %v", status, body, err)
			}
		}
		return status, responseHeaders, value
	}
	request := func(t *testing.T, method, path string, headers http.Header, body any, query url.Values) (*http.Request, []byte) {
		t.Helper()
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		target := "http://auth.example.test/api/auth" + path
		if len(query) != 0 {
			target += "?" + query.Encode()
		}
		req, err := http.NewRequestWithContext(t.Context(), method, target, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = headers.Clone()
		req.Header.Set("Origin", "http://auth.example.test")
		if len(encoded) != 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, encoded
	}
	switch transport {
	case "net/http":
		return func(t *testing.T, method, path string, headers http.Header, body any, query url.Values) (int, http.Header, map[string]any) {
			req, _ := request(t, method, path, headers, body, query)
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, req)
			return decode(t, recorder.Code, recorder.Header().Clone(), recorder.Body.Bytes())
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(t *testing.T, method, path string, headers http.Header, body any, query url.Values) (int, http.Header, map[string]any) {
			req, encoded := request(t, method, path, headers, body, query)
			var fastRequest fasthttpserver.Request
			fastRequest.Header.SetMethod(method)
			fastRequest.Header.SetHost(req.URL.Host)
			for name, values := range req.Header {
				for _, value := range values {
					fastRequest.Header.Add(name, value)
				}
			}
			fastRequest.SetRequestURI(req.URL.String())
			fastRequest.SetBody(encoded)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&fastRequest, nil, nil)
			handler(&requestContext)
			responseHeaders := make(http.Header)
			requestContext.Response.Header.VisitAll(func(name, value []byte) { responseHeaders.Add(string(name), string(value)) })
			return decode(t, requestContext.Response.StatusCode(), responseHeaders, requestContext.Response.Body())
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(t *testing.T, method, path string, headers http.Header, body any, query url.Values) (int, http.Header, map[string]any) {
			req, _ := request(t, method, path, headers, body, query)
			response, err := app.Test(req, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			responseBody, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			return decode(t, response.StatusCode, response.Header.Clone(), responseBody)
		}
	default:
		t.Fatalf("unsupported API-key verify/update/get/list transport %q", transport)
		return nil
	}
}

func assertVerifyUpdateGetListSameJSON(t *testing.T, actual, expected any) {
	t.Helper()
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualJSON, expectedJSON) {
		t.Fatalf("API-key verify/update/get/list observation mismatch\nactual: %s\nwant:   %s", actualJSON, expectedJSON)
	}
}
