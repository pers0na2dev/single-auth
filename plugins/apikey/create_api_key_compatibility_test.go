package apikey

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	"strings"
	"sync/atomic"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"

	_ "modernc.org/sqlite"
)

type createAPIKeyCase func(*testing.T, string) map[string]any

func TestCreateAPIKeyBehaviorAcrossTransports(t *testing.T) {
	cases := createAPIKeyCases()
	if len(cases) != len(createAPIKeyExpectedCases) {
		t.Fatalf("create API-key cases=%d expectations=%d", len(cases), len(createAPIKeyExpectedCases))
	}
	for _, testCase := range createAPIKeyExpectedCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			run, exists := cases[testCase.Name]
			if !exists {
				t.Fatalf("missing create API-key case %q", testCase.Name)
			}
			delete(cases, testCase.Name)
			for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					assertCreateAPIKeySameJSON(t, run(t, transport), testCase.Want)
				})
			}
		})
	}
	if len(cases) != 0 {
		t.Fatalf("create API-key cases without expectations: %#v", cases)
	}
}

func createAPIKeyCases() map[string]createAPIKeyCase {
	return map[string]createAPIKeyCase{
		"should fail to create API keys from client without headers":                                                                          createClientUnauthorizedCase,
		"should successfully create API keys from client with headers":                                                                        createClientSuccessCase,
		"should fail to create API Keys from server without headers and userId":                                                               createDirectUnauthorizedCase,
		"should fail to create api keys from the client if user id is provided":                                                               createClientUserIDRejectedCase,
		"should successfully create API keys from server with userId":                                                                         createDirectUserIDSuccessCase,
		"should have the real value from rateLimitEnabled":                                                                                    createRateLimitEnabledFalseCase,
		"should have true if the rate limit is undefined":                                                                                     createRateLimitEnabledDefaultCase,
		"should require name in API keys if configured":                                                                                       createRequireNameCase,
		"should respect rateLimit configuration from plugin options":                                                                          createConfiguredRateLimitCase,
		"should create the API key with the given name":                                                                                       createNameCase,
		"should create the API key with a name that's shorter than the allowed minimum":                                                       createInvalidNameCase("test-api-key-that-is-shorter-than-the-allowed-minimum"),
		"should create the API key with a name that's longer than the allowed maximum":                                                        createInvalidNameCase("test-api-key-that-is-longer-than-the-allowed-maximum"),
		"should create the API key with the given prefix":                                                                                     createPrefixCase,
		"should create the API key with a prefix that's shorter than the allowed minimum":                                                     createInvalidPrefixCase("test-api-key-that-is-shorter-than-the-allowed-minimum"),
		"should create the API key with a prefix that's longer than the allowed maximum":                                                      createInvalidPrefixCase("test-api-key-that-is-longer-than-the-allowed-maximum"),
		"should create an API key with a custom expiresIn":                                                                                    createExpiresInCase,
		"should support disabling key hashing":                                                                                                createDisableHashingCase,
		"should fail to create a key with a custom expiresIn value when customExpiresTime is disabled":                                        createDisabledExpirationCase,
		"should create an API key with an expiresIn that's smaller than the allowed minimum":                                                  createInvalidExpirationCase(12 * time.Hour),
		"should fail to create an API key with an expiresIn that's larger than the allowed maximum":                                           createInvalidExpirationCase(10 * 365 * 24 * time.Hour),
		"should fail to create API key with custom refillAndAmount from client auth":                                                          createClientRefillRejectedCase,
		"should fail to create API key when refill interval is provided, but no refill amount":                                                createRefillIntervalOnlyCase,
		"should fail to create API key when refill amount is provided, but no refill interval":                                                createRefillAmountOnlyCase,
		"should create the API key with the given refill interval & refill amount":                                                            createRefillCase,
		"should create API Key with custom remaining":                                                                                         createRemainingCase,
		"should create API Key with remaining explicitly set to null":                                                                         createRemainingNullCase,
		"should create API Key with remaining explicitly set to null and refillAmount and refillInterval are also set":                        createRemainingNullWithRefillCase,
		"should create API Key with remaining explicitly set to 0 and refillAmount also set":                                                  createRemainingZeroWithRefillCase,
		"should create API Key with remaining undefined and default value of null is respected with refillAmount and refillInterval provided": createRemainingUndefinedWithRefillCase,
		"should create API key with invalid metadata":                                                                                         createInvalidMetadataCase,
		"should create API key with valid metadata":                                                                                           createValidMetadataCase,
		"create API key's returned metadata should be an object":                                                                              createReturnedMetadataCase,
		"create API key with with metadata when metadata is disabled (should fail)":                                                           createMetadataDisabledCase,
		"should have the first 6 characters of the key as the start property":                                                                 createDefaultStartCase,
		"should have the start property as null if shouldStore is false":                                                                      createStartDisabledCase,
		"should use the defined charactersLength if provided":                                                                                 createCustomStartLengthCase,
		"should fail to create API key with custom rate-limit options from client auth":                                                       createClientRateLimitRejectedCase,
		"should successfully apply custom rate-limit options on the newly created API key":                                                    createCustomRateLimitCase,
		"should create an API key with permissions":                                                                                           createPermissionsCase,
		"should create an API key with default permissions":                                                                                   createDefaultPermissionsCase,
	}
}

func createClientUnauthorizedCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	status, _, body := harness.exchange(t, http.MethodPost, "/api-key/create", "", map[string]any{}, nil)
	return map[string]any{"error": createHTTPError(status, body)}
}

func createClientSuccessCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "client-success")
	status, _, body := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{}, nil)
	if status != http.StatusOK {
		t.Fatalf("client create status=%d body=%#v", status, body)
	}
	value := createDefaultShape(t, body, identity.ID)
	value["clientError"] = true
	return value
}

func createDirectUnauthorizedCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	return map[string]any{"error": createDirectError(t, harness, "", map[string]any{})}
}

func createClientUserIDRejectedCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	first := harness.signUp(t, "client-user-id-first")
	second := harness.signUp(t, "client-user-id-second")
	withoutStatus, _, withoutBody := harness.exchange(t, http.MethodPost, "/api-key/create", "", map[string]any{"userId": first.ID}, nil)
	withStatus, _, withBody := harness.exchange(t, http.MethodPost, "/api-key/create", first.Cookie, map[string]any{"userId": second.ID}, nil)
	return map[string]any{
		"withoutSession": createHTTPError(withoutStatus, withoutBody),
		"withSession":    createHTTPError(withStatus, withBody),
	}
}

func createDirectUserIDSuccessCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "direct-user-id")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"userId": identity.ID})
	return createDefaultShape(t, created, identity.ID)
}

func createRateLimitEnabledFalseCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "rate-limit-false")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"userId": identity.ID, "rateLimitEnabled": false})
	return map[string]any{"rateLimitEnabled": created["rateLimitEnabled"]}
}

func createRateLimitEnabledDefaultCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "rate-limit-default")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"userId": identity.ID})
	return map[string]any{"rateLimitEnabled": created["rateLimitEnabled"]}
}

func createRequireNameCase(t *testing.T, transport string) map[string]any {
	configuration := baseCreateAPIKeyConfiguration()
	configuration.EnableMetadata = false
	configuration.DefaultPermissions = nil
	configuration.RequireName = true
	harness := newCreateAPIKeyHarness(t, transport, configuration)
	identity := harness.signUp(t, "require-name")
	return map[string]any{"error": createDirectError(t, harness, "", map[string]any{"userId": identity.ID})}
}

func createConfiguredRateLimitCase(t *testing.T, transport string) map[string]any {
	configuration := baseCreateAPIKeyConfiguration()
	configuration.DefaultPermissions = nil
	configuration.RateLimitEnabled = Bool(false)
	configuration.RateLimitTimeWindow = time.Second
	configuration.RateLimitMax = 10
	harness := newCreateAPIKeyHarness(t, transport, configuration)
	identity := harness.signUp(t, "configured-rate-limit")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"userId": identity.ID})
	return map[string]any{
		"rateLimitEnabled":    created["rateLimitEnabled"],
		"rateLimitTimeWindow": created["rateLimitTimeWindow"],
		"rateLimitMax":        created["rateLimitMax"],
	}
}

func createNameCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "create-name")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, identity.Cookie, map[string]any{"name": "test-api-key"})
	return map[string]any{"name": created["name"]}
}

func createInvalidNameCase(name string) createAPIKeyCase {
	return func(t *testing.T, transport string) map[string]any {
		harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
		identity := harness.signUp(t, "invalid-name")
		return map[string]any{"error": createDirectError(t, harness, identity.Cookie, map[string]any{"name": name})}
	}
}

func createPrefixCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "create-prefix")
	prefix := "test-api-key_"
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, identity.Cookie, map[string]any{"prefix": prefix})
	key, _ := created["key"].(string)
	return map[string]any{
		"prefix": created["prefix"], "keyStartsWithPrefix": strings.HasPrefix(key, prefix),
		"randomCharacterLength": len(key) - len(prefix),
	}
}

func createInvalidPrefixCase(prefix string) createAPIKeyCase {
	return func(t *testing.T, transport string) map[string]any {
		harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
		identity := harness.signUp(t, "invalid-prefix")
		return map[string]any{"error": createDirectError(t, harness, identity.Cookie, map[string]any{"prefix": prefix})}
	}
}

func createExpiresInCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "expires-in")
	expiresIn := int64((7 * 24 * time.Hour) / time.Second)
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, identity.Cookie, map[string]any{"expiresIn": expiresIn})
	expiresAt, ok := parseCreateAPIKeyTime(created["expiresAt"])
	return map[string]any{
		"expiresAtPresent":                  ok,
		"expiresWithinOneSecondOfRequested": ok && expiresAt.Sub(harness.clock.Add(7*24*time.Hour)) <= time.Second && expiresAt.Sub(harness.clock.Add(7*24*time.Hour)) >= -time.Second,
	}
}

func createDisableHashingCase(t *testing.T, transport string) map[string]any {
	configuration := baseCreateAPIKeyConfiguration()
	configuration.EnableMetadata = false
	configuration.DefaultPermissions = nil
	configuration.DisableKeyHashing = true
	harness := newCreateAPIKeyHarness(t, transport, configuration)
	identity := harness.signUp(t, "disable-hashing")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, identity.Cookie, map[string]any{})
	record, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{Model: "apikey", Where: []storage.Where{{Field: "id", Value: created["id"]}}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"storedEqualsPlaintext": record != nil && record["key"] == created["key"]}
}

func createDisabledExpirationCase(t *testing.T, transport string) map[string]any {
	configuration := baseCreateAPIKeyConfiguration()
	configuration.DefaultPermissions = nil
	configuration.DisableCustomExpiresTime = true
	harness := newCreateAPIKeyHarness(t, transport, configuration)
	identity := harness.signUp(t, "disabled-expiration")
	return map[string]any{"error": createDirectError(t, harness, identity.Cookie, map[string]any{"expiresIn": int64(10000)})}
}

func createInvalidExpirationCase(duration time.Duration) createAPIKeyCase {
	return func(t *testing.T, transport string) map[string]any {
		harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
		identity := harness.signUp(t, "invalid-expiration")
		return map[string]any{"error": createDirectError(t, harness, identity.Cookie, map[string]any{"expiresIn": int64(duration / time.Second)})}
	}
}

func createClientRefillRejectedCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "client-refill")
	amountStatus, _, amountBody := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{"refillAmount": 10}, nil)
	intervalStatus, _, intervalBody := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{"refillInterval": 1001}, nil)
	return map[string]any{
		"refillAmount":   createHTTPError(amountStatus, amountBody),
		"refillInterval": createHTTPError(intervalStatus, intervalBody),
	}
}

func createRefillIntervalOnlyCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "refill-interval-only")
	return map[string]any{"error": createDirectError(t, harness, "", map[string]any{"refillInterval": 1000, "userId": identity.ID})}
}

func createRefillAmountOnlyCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "refill-amount-only")
	return map[string]any{"error": createDirectError(t, harness, "", map[string]any{"refillAmount": 10, "userId": identity.ID})}
}

func createRefillCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "refill")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"refillInterval": 10000, "refillAmount": 10, "userId": identity.ID})
	return map[string]any{"refillInterval": created["refillInterval"], "refillAmount": created["refillAmount"]}
}

func createRemainingCase(t *testing.T, transport string) map[string]any {
	return createRemainingObservation(t, transport, map[string]any{"remaining": 10}, []string{"remaining"})
}

func createRemainingNullCase(t *testing.T, transport string) map[string]any {
	return createRemainingObservation(t, transport, map[string]any{"remaining": nil}, []string{"remaining"})
}

func createRemainingNullWithRefillCase(t *testing.T, transport string) map[string]any {
	return createRemainingObservation(t, transport, map[string]any{"remaining": nil, "refillAmount": 10, "refillInterval": 1000}, []string{"remaining", "refillAmount", "refillInterval"})
}

func createRemainingZeroWithRefillCase(t *testing.T, transport string) map[string]any {
	return createRemainingObservation(t, transport, map[string]any{"remaining": 0, "refillAmount": 10, "refillInterval": 1000}, []string{"remaining", "refillAmount", "refillInterval"})
}

func createRemainingUndefinedWithRefillCase(t *testing.T, transport string) map[string]any {
	return createRemainingObservation(t, transport, map[string]any{"refillAmount": 10, "refillInterval": 1000}, []string{"remaining", "refillAmount", "refillInterval"})
}

func createRemainingObservation(t *testing.T, transport string, body map[string]any, fields []string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "remaining")
	body["userId"] = identity.ID
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", body)
	result := make(map[string]any, len(fields))
	for _, field := range fields {
		result[field] = created[field]
	}
	return result
}

func createInvalidMetadataCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "invalid-metadata")
	return map[string]any{"error": createDirectError(t, harness, identity.Cookie, map[string]any{"metadata": "invalid"})}
}

func createValidMetadataCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "valid-metadata")
	metadata := map[string]any{"test": "test"}
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, identity.Cookie, map[string]any{"metadata": metadata})
	fetched := createMustDirectQueryObject(t, harness, "getApiKey", identity.Cookie, url.Values{"id": {fmt.Sprint(created["id"])}})
	return map[string]any{"metadata": created["metadata"], "fetchedMetadata": fetched["metadata"]}
}

func createReturnedMetadataCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "returned-metadata")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, identity.Cookie, map[string]any{"metadata": map[string]any{"test": "test-123"}})
	_, isObject := created["metadata"].(map[string]any)
	return map[string]any{"metadataIsObject": isObject, "metadata": created["metadata"]}
}

func createMetadataDisabledCase(t *testing.T, transport string) map[string]any {
	configuration := baseCreateAPIKeyConfiguration()
	configuration.EnableMetadata = false
	configuration.DefaultPermissions = nil
	harness := newCreateAPIKeyHarness(t, transport, configuration)
	identity := harness.signUp(t, "metadata-disabled")
	return map[string]any{"error": createDirectError(t, harness, identity.Cookie, map[string]any{"metadata": map[string]any{"test": "test-123"}})}
}

func createDefaultStartCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "default-start")
	status, _, created := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{}, nil)
	if status != http.StatusOK {
		t.Fatalf("default start create status=%d body=%#v", status, created)
	}
	key, _ := created["key"].(string)
	start, _ := created["start"].(string)
	return map[string]any{"startPresent": start != "", "startLength": len(start), "startMatchesKey": start == key[:min(len(key), 6)]}
}

func createStartDisabledCase(t *testing.T, transport string) map[string]any {
	configuration := baseCreateAPIKeyConfiguration()
	configuration.EnableMetadata = false
	configuration.DefaultPermissions = nil
	configuration.StoreStartingCharacters = Bool(false)
	harness := newCreateAPIKeyHarness(t, transport, configuration)
	identity := harness.signUp(t, "start-disabled")
	status, _, created := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{}, nil)
	if status != http.StatusOK {
		t.Fatalf("start disabled create status=%d body=%#v", status, created)
	}
	return map[string]any{"start": created["start"]}
}

func createCustomStartLengthCase(t *testing.T, transport string) map[string]any {
	configuration := baseCreateAPIKeyConfiguration()
	configuration.EnableMetadata = false
	configuration.DefaultPermissions = nil
	configuration.StoreStartingCharacters = Bool(true)
	configuration.StartingCharactersLength = 3
	harness := newCreateAPIKeyHarness(t, transport, configuration)
	identity := harness.signUp(t, "custom-start")
	status, _, created := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{}, nil)
	if status != http.StatusOK {
		t.Fatalf("custom start create status=%d body=%#v", status, created)
	}
	key, _ := created["key"].(string)
	start, _ := created["start"].(string)
	return map[string]any{"startPresent": start != "", "startLength": len(start), "startMatchesKey": start == key[:min(len(key), 3)]}
}

func createClientRateLimitRejectedCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "client-rate-limit")
	maxStatus, _, maxBody := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{"rateLimitMax": 15}, nil)
	windowStatus, _, windowBody := harness.exchange(t, http.MethodPost, "/api-key/create", identity.Cookie, map[string]any{"rateLimitTimeWindow": 1001}, nil)
	return map[string]any{
		"rateLimitMax":        createHTTPError(maxStatus, maxBody),
		"rateLimitTimeWindow": createHTTPError(windowStatus, windowBody),
	}
}

func createCustomRateLimitCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "custom-rate-limit")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"rateLimitMax": 15, "rateLimitTimeWindow": 1000, "userId": identity.ID})
	return map[string]any{"rateLimitMax": created["rateLimitMax"], "rateLimitTimeWindow": created["rateLimitTimeWindow"]}
}

func createPermissionsCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "permissions")
	permissions := map[string][]string{"files": {"read", "write"}, "users": {"read"}}
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"permissions": permissions, "userId": identity.ID})
	return map[string]any{"permissions": created["permissions"]}
}

func createDefaultPermissionsCase(t *testing.T, transport string) map[string]any {
	harness := newCreateAPIKeyHarness(t, transport, baseCreateAPIKeyConfiguration())
	identity := harness.signUp(t, "default-permissions")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{"userId": identity.ID})
	return map[string]any{"permissions": created["permissions"]}
}

func baseCreateAPIKeyConfiguration() Configuration {
	return Configuration{
		EnableMetadata:     true,
		DefaultPermissions: map[string][]string{"files": {"read"}},
	}
}

func newCreateAPIKeyHarness(t *testing.T, transport string, configuration Configuration) orgAPIKeyHarness {
	t.Helper()
	clock := time.Date(2026, time.August, 9, 12, 34, 56, 0, time.UTC)
	apiSchema, err := Schema(Options{})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(apiSchema)
	if err != nil {
		t.Fatal(err)
	}
	dsn := "file:create_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(8)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close create API-key compatibility SQLite database: %v", err)
		}
	})
	var sequence atomic.Int64
	adapter, err := sqliteadapter.New(database, sqliteadapter.Options{
		Schema: schema, Clock: func() time.Time { return clock },
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
		Database: adapter, Clock: func() time.Time { return clock },
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
	return orgAPIKeyHarness{auth: auth, adapter: auth.Adapter(), clock: clock, roundTrip: newOrgAPIKeyRoundTrip(t, auth, transport)}
}

func createDefaultShape(t *testing.T, key map[string]any, referenceID string) map[string]any {
	t.Helper()
	plaintext, _ := key["key"].(string)
	return map[string]any{
		"keyPresent":            plaintext != "",
		"randomCharacterLength": len(plaintext),
		"referenceMatches":      key["referenceId"] == referenceID,
		"name":                  key["name"],
		"prefix":                key["prefix"],
		"refillInterval":        key["refillInterval"],
		"refillAmount":          key["refillAmount"],
		"lastRefillAt":          createPresenceValue(key["lastRefillAt"]),
		"enabled":               key["enabled"],
		"rateLimitEnabled":      key["rateLimitEnabled"],
		"rateLimitTimeWindow":   key["rateLimitTimeWindow"],
		"rateLimitMax":          key["rateLimitMax"],
		"requestCount":          key["requestCount"],
		"remaining":             key["remaining"],
		"lastRequest":           createPresenceValue(key["lastRequest"]),
		"expiresAt":             createPresenceValue(key["expiresAt"]),
		"createdAtPresent":      key["createdAt"] != nil,
		"updatedAtPresent":      key["updatedAt"] != nil,
		"metadata":              key["metadata"],
		"permissions":           key["permissions"],
	}
}

func createPresenceValue(value any) any {
	if value == nil {
		return nil
	}
	return "present"
}

func createDirectError(t *testing.T, harness orgAPIKeyHarness, cookie string, body map[string]any) map[string]any {
	t.Helper()
	result, err := harness.invoke(t, "createApiKey", http.MethodPost, cookie, body)
	if err == nil {
		t.Fatalf("direct create unexpectedly succeeded: %#v", result.Value)
	}
	apiErr, ok := contract.AsAPIError(err)
	if !ok {
		t.Fatalf("direct create returned non-API error: %v", err)
	}
	return createErrorValue(apiErr.Status, apiErr.Code, apiErr.Message)
}

func createHTTPError(status int, body map[string]any) map[string]any {
	return createErrorValue(status, fmt.Sprint(body["code"]), fmt.Sprint(body["message"]))
}

func createErrorValue(status int, code, message string) map[string]any {
	return map[string]any{
		"statusCode": status,
		"status":     createStatusName(status),
		"code":       code,
		"message":    message,
	}
}

func createStatusName(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	default:
		return fmt.Sprintf("HTTP_%d", status)
	}
}

func createMustDirectQueryObject(t *testing.T, harness orgAPIKeyHarness, name, cookie string, query url.Values) map[string]any {
	t.Helper()
	headers := contract.Headers{}
	if cookie != "" {
		headers.Set("Cookie", cookie)
	}
	result, err := harness.auth.API().Call(t.Context(), name, singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "auth.example.test", Headers: headers, Query: query,
	})
	if err != nil || result.Response.Status() != http.StatusOK {
		t.Fatalf("direct query %s status=%d value=%#v err=%v", name, result.Response.Status(), result.Value, err)
	}
	value, ok := result.Value.(map[string]any)
	if !ok {
		t.Fatalf("direct query %s value is not object: %#v", name, result.Value)
	}
	return value
}

func parseCreateAPIKeyTime(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	return parsed, err == nil
}

func assertCreateAPIKeySameJSON(t *testing.T, actual, expected any) {
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
		t.Fatalf("create API-key observation mismatch\nactual: %s\nwant:   %s", actualJSON, expectedJSON)
	}
}
