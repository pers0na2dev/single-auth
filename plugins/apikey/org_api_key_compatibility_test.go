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
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"

	_ "modernc.org/sqlite"
)

type orgAPIKeyCase func(*testing.T, string) map[string]any

type orgAPIKeyRoundTrip func(*testing.T, string, string, string, []byte) (int, http.Header, []byte)

type orgAPIKeyHarness struct {
	auth      *singleauth.Auth
	adapter   storage.Adapter
	clock     time.Time
	roundTrip orgAPIKeyRoundTrip
}

type orgAPIKeyIdentity struct {
	ID     string
	Cookie string
}

func TestOrganizationAPIKeyBehaviorAcrossTransports(t *testing.T) {
	cases := orgAPIKeyCases()
	if len(cases) != len(orgAPIKeyExpectedCases) {
		t.Fatalf("organization API-key cases=%d expectations=%d", len(cases), len(orgAPIKeyExpectedCases))
	}
	for _, testCase := range orgAPIKeyExpectedCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			run, exists := cases[testCase.Name]
			if !exists {
				t.Fatalf("missing organization API-key case %q", testCase.Name)
			}
			delete(cases, testCase.Name)
			for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					assertSameJSON(t, run(t, transport), testCase.Want)
				})
			}
		})
	}
	if len(cases) != 0 {
		t.Fatalf("organization API-key cases without expectations: %#v", cases)
	}
}

func orgAPIKeyCases() map[string]orgAPIKeyCase {
	return map[string]orgAPIKeyCase{
		"organization owner should have full CRUD access to API keys":        ownerCRUDCase,
		"non-member should be denied access to organization API keys":        nonMemberCase,
		"member without apiKey permissions should be denied (default roles)": defaultMemberCase,
		"should correctly separate user and org keys when listing":           separateKeysCase,
		"verify API key should work for organization-owned keys":             verifyOrganizationKeyCase,
		"admin role should have full apiKey CRUD permissions":                func(t *testing.T, transport string) map[string]any { return customRoleCase(t, transport, "admin") },
		"member role with read-only permission should be limited":            func(t *testing.T, transport string) map[string]any { return customRoleCase(t, transport, "member") },
		"restricted role with no apiKey permissions should be fully denied":  func(t *testing.T, transport string) map[string]any { return customRoleCase(t, transport, "restricted") },
		"should return error when organization plugin is not installed":      missingOrganizationPluginCase,
		"should not allow accessing org key with wrong configId":             wrongConfigCase,
	}
}

func ownerCRUDCase(t *testing.T, transport string) map[string]any {
	harness := newOrgAPIKeyHarnessForTransport(t, true, nil, bothAPIKeyConfigurations(), transport)
	owner := harness.signUp(t, "owner")
	harness.seedOrganization(t, "org-1", owner.ID, "owner")
	createStatus, _, created := harness.exchange(t, http.MethodPost, "/api-key/create", owner.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	}, nil)
	createdID, _ := created["id"].(string)
	listStatus, _, listed := harness.exchange(t, http.MethodGet, "/api-key/list", owner.Cookie, nil, url.Values{
		"organizationId": {"org-1"},
	})
	getStatus, _, got := harness.exchange(t, http.MethodGet, "/api-key/get", owner.Cookie, nil, url.Values{
		"id": {createdID}, "configId": {"org-keys"},
	})
	updateStatus, _, updated := harness.exchange(t, http.MethodPost, "/api-key/update", owner.Cookie, map[string]any{
		"keyId": createdID, "configId": "org-keys", "name": "Updated Key",
	}, nil)
	deleteStatus, _, deleted := harness.exchange(t, http.MethodPost, "/api-key/delete", owner.Cookie, map[string]any{
		"keyId": createdID, "configId": "org-keys",
	}, nil)
	return map[string]any{
		"createOK":               createStatus == http.StatusOK,
		"createReferenceMatches": created["referenceId"] == "org-1",
		"createConfigMatches":    created["configId"] == "org-keys",
		"listOK":                 listStatus == http.StatusOK,
		"listHasKey":             responseHasAPIKey(listed, createdID),
		"getOK":                  getStatus == http.StatusOK && got["id"] == createdID,
		"updateOK":               updateStatus == http.StatusOK && updated["name"] == "Updated Key",
		"deleteOK":               deleteStatus == http.StatusOK && deleted["success"] == true,
	}
}

func nonMemberCase(t *testing.T, transport string) map[string]any {
	harness := newOrgAPIKeyHarnessForTransport(t, true, nil, bothAPIKeyConfigurations(), transport)
	owner := harness.signUp(t, "owner")
	nonMember := harness.signUp(t, "non-member")
	harness.seedOrganization(t, "org-1", owner.ID, "owner")
	key := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, owner.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	})
	keyID, _ := key["id"].(string)
	listStatus, _, listed := harness.exchange(t, http.MethodGet, "/api-key/list", nonMember.Cookie, nil, url.Values{
		"organizationId": {"org-1"},
	})
	createStatus, _, created := harness.exchange(t, http.MethodPost, "/api-key/create", nonMember.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	}, nil)
	getStatus, _, got := harness.exchange(t, http.MethodGet, "/api-key/get", nonMember.Cookie, nil, url.Values{
		"id": {keyID}, "configId": {"org-keys"},
	})
	updateStatus, _, updated := harness.exchange(t, http.MethodPost, "/api-key/update", nonMember.Cookie, map[string]any{
		"keyId": keyID, "configId": "org-keys", "name": "Hacked",
	}, nil)
	deleteStatus, _, deleted := harness.exchange(t, http.MethodPost, "/api-key/delete", nonMember.Cookie, map[string]any{
		"keyId": keyID, "configId": "org-keys",
	}, nil)
	return map[string]any{
		"listError":    httpErrorObservation(listStatus, listed),
		"createError":  httpErrorObservation(createStatus, created),
		"getError":     httpErrorObservation(getStatus, got),
		"updateError":  httpErrorObservation(updateStatus, updated),
		"deleteError":  httpErrorObservation(deleteStatus, deleted),
		"expectedCode": ErrorUserNotMemberOfOrganization,
	}
}

func defaultMemberCase(t *testing.T, transport string) map[string]any {
	harness := newOrgAPIKeyHarnessForTransport(t, true, nil, bothAPIKeyConfigurations(), transport)
	owner := harness.signUp(t, "owner")
	member := harness.signUp(t, "member")
	harness.seedOrganization(t, "org-1", owner.ID, "owner")
	harness.seedMember(t, "org-1", member.ID, "member")
	status, _, body := harness.exchange(t, http.MethodGet, "/api-key/list", member.Cookie, nil, url.Values{
		"organizationId": {"org-1"},
	})
	return map[string]any{"listError": httpErrorObservation(status, body)}
}

func separateKeysCase(t *testing.T, transport string) map[string]any {
	harness := newOrgAPIKeyHarnessForTransport(t, true, nil, bothAPIKeyConfigurations(), transport)
	owner := harness.signUp(t, "owner")
	harness.seedOrganization(t, "org-1", owner.ID, "owner")
	userKey := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{
		"configId": "user-keys", "userId": owner.ID,
	})
	orgKey := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, owner.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	})
	userKeyID, _ := userKey["id"].(string)
	orgKeyID, _ := orgKey["id"].(string)
	userStatus, _, userList := harness.exchange(t, http.MethodGet, "/api-key/list", owner.Cookie, nil, nil)
	orgStatus, _, orgList := harness.exchange(t, http.MethodGet, "/api-key/list", owner.Cookie, nil, url.Values{
		"organizationId": {"org-1"},
	})
	return map[string]any{
		"userListOK":         userStatus == http.StatusOK,
		"userListHasUserKey": responseHasAPIKey(userList, userKeyID),
		"userListHasOrgKey":  responseHasAPIKey(userList, orgKeyID),
		"orgListOK":          orgStatus == http.StatusOK,
		"orgListHasOrgKey":   responseHasAPIKey(orgList, orgKeyID),
		"orgListHasUserKey":  responseHasAPIKey(orgList, userKeyID),
	}
}

func verifyOrganizationKeyCase(t *testing.T, transport string) map[string]any {
	harness := newOrgAPIKeyHarnessForTransport(t, true, nil, bothAPIKeyConfigurations(), transport)
	owner := harness.signUp(t, "owner")
	harness.seedOrganization(t, "org-1", owner.ID, "owner")
	key := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, owner.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	})
	verified := harness.mustInvokeObject(t, "verifyApiKey", http.MethodPost, "", map[string]any{
		"key": key["key"], "configId": "org-keys",
	})
	verifiedKey, _ := verified["key"].(map[string]any)
	return map[string]any{
		"valid":            verified["valid"] == true,
		"configMatches":    verifiedKey["configId"] == "org-keys",
		"referenceMatches": verifiedKey["referenceId"] == "org-1",
	}
}

func customRoleCase(t *testing.T, transport, role string) map[string]any {
	roles := map[string]authorization.Statements{
		"owner":      {"apiKey": {"create", "read", "update", "delete"}},
		"admin":      {"apiKey": {"create", "read", "update", "delete"}},
		"member":     {"apiKey": {"read"}},
		"restricted": {},
	}
	harness := newOrgAPIKeyHarnessForTransport(t, true, roles, []Configuration{{ConfigID: "org-keys", DefaultPrefix: "org_", References: ReferenceOrganization}}, transport)
	owner := harness.signUp(t, "owner")
	actor := harness.signUp(t, role)
	harness.seedOrganization(t, "org-1", owner.ID, "owner")
	harness.seedMember(t, "org-1", actor.ID, role)
	existing := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, owner.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	})
	existingID, _ := existing["id"].(string)
	listStatus, _, listed := harness.exchange(t, http.MethodGet, "/api-key/list", actor.Cookie, nil, url.Values{
		"organizationId": {"org-1"},
	})
	getStatus, _, got := harness.exchange(t, http.MethodGet, "/api-key/get", actor.Cookie, nil, url.Values{
		"id": {existingID}, "configId": {"org-keys"},
	})
	createStatus, _, created := harness.exchange(t, http.MethodPost, "/api-key/create", actor.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	}, nil)
	name := role + " Updated"
	updateStatus, _, updated := harness.exchange(t, http.MethodPost, "/api-key/update", actor.Cookie, map[string]any{
		"keyId": existingID, "configId": "org-keys", "name": name,
	}, nil)
	deleteStatus, _, deleted := harness.exchange(t, http.MethodPost, "/api-key/delete", actor.Cookie, map[string]any{
		"keyId": existingID, "configId": "org-keys",
	}, nil)
	return map[string]any{
		"listOK":      listStatus == http.StatusOK && responseHasAPIKey(listed, existingID),
		"listError":   httpErrorObservation(listStatus, listed),
		"getOK":       getStatus == http.StatusOK && got["id"] == existingID,
		"getError":    httpErrorObservation(getStatus, got),
		"createOK":    createStatus == http.StatusOK && created["id"] != nil,
		"createError": httpErrorObservation(createStatus, created),
		"updateOK":    updateStatus == http.StatusOK && updated["name"] == name,
		"updateError": httpErrorObservation(updateStatus, updated),
		"deleteOK":    deleteStatus == http.StatusOK && deleted["success"] == true,
		"deleteError": httpErrorObservation(deleteStatus, deleted),
	}
}

func missingOrganizationPluginCase(t *testing.T, transport string) map[string]any {
	harness := newOrgAPIKeyHarnessForTransport(t, false, nil, []Configuration{{ConfigID: "org-keys", DefaultPrefix: "org_", References: ReferenceOrganization}}, transport)
	owner := harness.signUp(t, "owner")
	status, _, body := harness.exchange(t, http.MethodPost, "/api-key/create", owner.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "fake-org-id",
	}, nil)
	return map[string]any{"createError": httpErrorObservation(status, body)}
}

func wrongConfigCase(t *testing.T, transport string) map[string]any {
	harness := newOrgAPIKeyHarnessForTransport(t, true, nil, bothAPIKeyConfigurations(), transport)
	owner := harness.signUp(t, "owner")
	harness.seedOrganization(t, "org-1", owner.ID, "owner")
	key := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, owner.Cookie, map[string]any{
		"configId": "org-keys", "organizationId": "org-1",
	})
	keyID, _ := key["id"].(string)
	status, _, body := harness.exchange(t, http.MethodGet, "/api-key/get", owner.Cookie, nil, url.Values{
		"id": {keyID}, "configId": {"user-keys"},
	})
	return map[string]any{"getError": httpErrorObservation(status, body)}
}

func newOrgAPIKeyHarness(t *testing.T, organizationInstalled bool, roles map[string]authorization.Statements, configurations []Configuration) orgAPIKeyHarness {
	return newOrgAPIKeyHarnessForTransport(t, organizationInstalled, roles, configurations, "net/http")
}

func newOrgAPIKeyHarnessForTransport(
	t *testing.T,
	organizationInstalled bool,
	roles map[string]authorization.Statements,
	configurations []Configuration,
	transport string,
) orgAPIKeyHarness {
	t.Helper()
	clock := time.Date(2026, time.August, 9, 12, 34, 56, 0, time.UTC)
	organizationSchema, err := organization.Schema(organization.Options{})
	if err != nil {
		t.Fatal(err)
	}
	apiSchema, err := Schema(Options{})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(organizationSchema)
	if err != nil {
		t.Fatal(err)
	}
	schema, err = schema.Merge(apiSchema)
	if err != nil {
		t.Fatal(err)
	}
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(8)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close API-key compatibility SQLite database: %v", err)
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
	apiKeyFactory := NewFactory(Options{
		Configurations: configurations,
		Organization:   OrganizationAuthorization{CreatorRole: "owner", Roles: roles},
		Runtime: Runtime{
			KeyGenerator: func(_ context.Context, length int, prefix string) (string, error) {
				value := fmt.Sprintf("%d", keySequence.Add(1))
				if len(value) < length {
					value += strings.Repeat("A", length-len(value))
				}
				return prefix + value[:length], nil
			},
		},
	})
	factories := make([]singleauth.PluginFactory, 0, 2)
	if organizationInstalled {
		factories = append(factories, organization.NewFactory(organization.Options{}))
	}
	factories = append(factories, apiKeyFactory)
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:  "http://auth.example.test",
		Secret:   "0123456789abcdef0123456789abcdef",
		Database: adapter,
		Clock:    func() time.Time { return clock },
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
				Verify: func(hash, value string) bool { return hash == "hashed:"+value },
			},
		},
		PluginFactories: factories,
	})
	if err != nil {
		t.Fatal(err)
	}
	return orgAPIKeyHarness{
		auth: auth, adapter: auth.Adapter(), clock: clock,
		roundTrip: newOrgAPIKeyRoundTrip(t, auth, transport),
	}
}

func (h orgAPIKeyHarness) signUp(t *testing.T, name string) orgAPIKeyIdentity {
	t.Helper()
	status, headers, body := h.exchange(t, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": name, "email": name + "@test.com", "password": "password123",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("sign-up %s status=%d body=%#v", name, status, body)
	}
	user, ok := body["user"].(map[string]any)
	if !ok {
		t.Fatalf("sign-up %s has no user object: %#v", name, body)
	}
	id, _ := user["id"].(string)
	if id == "" {
		t.Fatalf("sign-up %s has no user ID: %#v", name, body)
	}
	return orgAPIKeyIdentity{ID: id, Cookie: cookies.ApplySetCookies("", headers.Values("Set-Cookie"))}
}

func (h orgAPIKeyHarness) seedOrganization(t *testing.T, id, creatorUserID, creatorRole string) {
	t.Helper()
	_, err := h.adapter.Create(t.Context(), storage.CreateParams{
		Model: "organization", ForceAllowID: true,
		Data: storage.Record{"id": id, "name": id, "slug": id, "createdAt": h.clock},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.seedMember(t, id, creatorUserID, creatorRole)
}

func (h orgAPIKeyHarness) seedMember(t *testing.T, organizationID, userID, role string) {
	t.Helper()
	_, err := h.adapter.Create(t.Context(), storage.CreateParams{
		Model: "member",
		Data: storage.Record{
			"organizationId": organizationID, "userId": userID,
			"role": role, "createdAt": h.clock,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (h orgAPIKeyHarness) exchange(
	t *testing.T,
	method, path, cookie string,
	body any,
	query url.Values,
) (int, http.Header, map[string]any) {
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
	status, headers, responseBody := h.roundTrip(t, method, target, cookie, encoded)
	decoded := map[string]any{}
	if len(responseBody) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(responseBody))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatalf("decode %s %s status=%d body=%q: %v", method, path, status, responseBody, err)
		}
	}
	return status, headers, decoded
}

func newOrgAPIKeyRoundTrip(t *testing.T, auth *singleauth.Auth, transport string) orgAPIKeyRoundTrip {
	t.Helper()
	switch transport {
	case "net/http":
		return func(t *testing.T, method, target, cookie string, body []byte) (int, http.Header, []byte) {
			t.Helper()
			request := newOrgAPIKeyHTTPRequest(t, method, target, cookie, body)
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			return recorder.Code, recorder.Header().Clone(), append([]byte(nil), recorder.Body.Bytes()...)
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(t *testing.T, method, target, cookie string, body []byte) (int, http.Header, []byte) {
			t.Helper()
			requestURL, err := url.Parse(target)
			if err != nil {
				t.Fatal(err)
			}
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.Header.SetHost(requestURL.Host)
			request.Header.Set("Origin", "http://auth.example.test")
			if len(body) != 0 {
				request.Header.SetContentType("application/json")
			}
			if cookie != "" {
				request.Header.Set("Cookie", cookie)
			}
			request.SetRequestURI(target)
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, nil, nil)
			handler(&requestContext)
			headers := make(http.Header)
			requestContext.Response.Header.VisitAll(func(name, value []byte) {
				if !strings.EqualFold(string(name), "Set-Cookie") {
					headers.Add(string(name), string(value))
				}
			})
			requestContext.Response.Header.VisitAllCookie(func(_, value []byte) {
				headers.Add("Set-Cookie", string(value))
			})
			return requestContext.Response.StatusCode(), headers, append([]byte(nil), requestContext.Response.Body()...)
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(t *testing.T, method, target, cookie string, body []byte) (int, http.Header, []byte) {
			t.Helper()
			request := newOrgAPIKeyHTTPRequest(t, method, target, cookie, body)
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			responseBody, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			return response.StatusCode, response.Header.Clone(), responseBody
		}
	default:
		t.Fatalf("unsupported organization API-key transport %q", transport)
		return nil
	}
}

func newOrgAPIKeyHTTPRequest(t *testing.T, method, target, cookie string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "http://auth.example.test")
	if len(body) != 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	return request
}

func (h orgAPIKeyHarness) invoke(
	t *testing.T,
	name, method, cookie string,
	body any,
) (singleauth.DirectCallResult, error) {
	t.Helper()
	headers := contract.Headers{}
	if cookie != "" {
		headers.Set("Cookie", cookie)
	}
	return h.auth.API().Call(t.Context(), name, singleauth.DirectCallInput{
		Method: method, Scheme: "http", Host: "auth.example.test", Headers: headers, Body: body,
	})
}

func (h orgAPIKeyHarness) mustInvokeObject(
	t *testing.T,
	name, method, cookie string,
	body any,
) map[string]any {
	t.Helper()
	result, err := h.invoke(t, name, method, cookie, body)
	if err != nil || result.Response.Status() != http.StatusOK {
		t.Fatalf("direct %s status=%d value=%#v err=%v", name, result.Response.Status(), result.Value, err)
	}
	value, ok := result.Value.(map[string]any)
	if !ok {
		t.Fatalf("direct %s value is not an object: %#v", name, result.Value)
	}
	return value
}

func bothAPIKeyConfigurations() []Configuration {
	return []Configuration{
		{ConfigID: "user-keys", DefaultPrefix: "usr_", References: ReferenceUser},
		{ConfigID: "org-keys", DefaultPrefix: "org_", References: ReferenceOrganization},
	}
}

func responseHasAPIKey(response map[string]any, id string) bool {
	keys, _ := response["apiKeys"].([]any)
	for _, raw := range keys {
		key, _ := raw.(map[string]any)
		if key["id"] == id {
			return true
		}
	}
	return false
}

func httpErrorObservation(status int, body map[string]any) map[string]any {
	if status < http.StatusBadRequest {
		return map[string]any{"status": nil, "code": nil, "message": nil}
	}
	return map[string]any{"status": status, "code": body["code"], "message": body["message"]}
}

func assertSameJSON(t *testing.T, actual, expected any) {
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
		t.Fatalf("organization API-key observation mismatch\nactual: %s\nwant:   %s", actualJSON, expectedJSON)
	}
}
