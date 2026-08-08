package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

var organizationCRUDScenarios = []string{
	"should allow listing members with membersLimit",
	"should get organization by organizationId",
	"should get organization by organizationSlug",
	"should include invitations in the response",
	"should prioritize organizationSlug over organizationId when both are provided",
	"should return null when no active organization and no query params",
	"should throw BAD_REQUEST when organization doesn't exist",
	"should throw FORBIDDEN when user is not a member of the organization",
	"should use default membershipLimit when no membersLimit is specified",
	"should allow internal organization creation when disabled for users",
	"should allow passing id through `beforeCreateInvitation`",
	"should allow passing id through `beforeCreateTeam`",
	"should apply afterAddMember hook",
	"should apply afterCreateOrganization hook",
	"should apply afterCreateTeam hook",
	"should apply beforeAddMember hook",
	"should apply beforeCreateOrganization hook",
	"should apply beforeCreateTeam hook",
	"should accept a null logo on create",
	"should clear the logo when passing null",
}

func TestOrganizationCRUDScenarios(t *testing.T) {
	for _, title := range organizationCRUDScenarios {
		title := title
		t.Run(title, func(t *testing.T) {
			for _, transport := range organizationCRUDTransports() {
				transport := transport
				t.Run(string(transport), func(t *testing.T) {
					runOrganizationCRUDOrgHTTPScenario(t, title, transport)
				})
			}
		})
	}
}

func TestRemoveMemberByEmailIncludesJoinedUserInHooksAndResponse(t *testing.T) {
	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run(string(transport), func(t *testing.T) {
			var before organization.RemoveMemberHookData
			var after organization.RemoveMemberHookData
			harness := newOrganizationCRUDHarness(t, organization.Options{
				Hooks: organization.OrganizationHooks{
					BeforeRemoveMember: func(_ context.Context, data organization.RemoveMemberHookData) error {
						before = data
						return nil
					},
					AfterRemoveMember: func(_ context.Context, data organization.RemoveMemberHookData) error {
						after = data
						return nil
					},
				},
			})
			created := harness.createHTTP(t, harness.owner, "Joined User Organization", "joined-user-organization", nil)
			organizationID := organizationCRUDString(t, created, "id")
			target := harness.signUp(t, "joined-user@example.test", "Joined User")
			createdMember := harness.addMemberDirect(t, organizationID, target)

			response := harness.exchange(t, http.MethodPost, "/organization/remove-member", harness.owner.Cookie, map[string]any{
				"memberIdOrEmail": strings.ToUpper(target.Email),
				"organizationId":  organizationID,
			})
			requireOrganizationCRUDStatus(t, response, http.StatusOK)
			body := organizationCRUDObject(t, response.Value, "remove-member response")
			removedMember := organizationCRUDObject(t, body["member"], "removed member")
			if removedMember["id"] != createdMember["id"] || removedMember["userId"] != target.ID ||
				removedMember["organizationId"] != organizationID || removedMember["role"] != "member" {
				t.Fatalf("removed member=%#v created=%#v body=%s", removedMember, createdMember, response.Body)
			}
			harness.requireJoinedMemberUser(t, removedMember, target, "removed member response")
			harness.requireJoinedMemberUser(t, before.Member, target, "beforeRemoveMember member")
			harness.requireJoinedMemberUser(t, after.Member, target, "afterRemoveMember member")
			if before.Member == nil || after.Member == nil || before.User["id"] != target.ID ||
				after.User["id"] != target.ID || before.Organization["id"] != organizationID ||
				after.Organization["id"] != organizationID {
				t.Fatalf("remove hooks before=%#v after=%#v", before, after)
			}

			persisted, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
				Model: "member", Where: []storage.Where{{Field: "id", Value: createdMember["id"]}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if persisted != nil {
				t.Fatalf("removed member still persisted: %#v", persisted)
			}
		})
	}
}

func TestRemoveMemberByIDOmitJoinedUserFromHooksAndResponse(t *testing.T) {
	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run(string(transport), func(t *testing.T) {
			var before organization.RemoveMemberHookData
			var after organization.RemoveMemberHookData
			harness := newOrganizationCRUDHarness(t, organization.Options{
				Hooks: organization.OrganizationHooks{
					BeforeRemoveMember: func(_ context.Context, data organization.RemoveMemberHookData) error {
						before = data
						return nil
					},
					AfterRemoveMember: func(_ context.Context, data organization.RemoveMemberHookData) error {
						after = data
						return nil
					},
				},
			})
			created := harness.createHTTP(t, harness.owner, "ID Removal Organization", "id-removal-organization", nil)
			organizationID := organizationCRUDString(t, created, "id")
			target := harness.signUp(t, "id-removal@example.test", "ID Removal User")
			createdMember := harness.addMemberDirect(t, organizationID, target)
			memberID := organizationCRUDString(t, createdMember, "id")

			response := harness.exchange(t, http.MethodPost, "/organization/remove-member", harness.owner.Cookie, map[string]any{
				"memberIdOrEmail": memberID,
				"organizationId":  organizationID,
			})
			requireOrganizationCRUDStatus(t, response, http.StatusOK)
			body := organizationCRUDObject(t, response.Value, "remove-member response")
			removedMember := organizationCRUDObject(t, body["member"], "removed member")
			if removedMember["id"] != memberID || removedMember["userId"] != target.ID ||
				removedMember["organizationId"] != organizationID || removedMember["role"] != "member" {
				t.Fatalf("removed member=%#v created=%#v body=%s", removedMember, createdMember, response.Body)
			}
			for label, member := range map[string]map[string]any{
				"response": removedMember, "beforeRemoveMember": before.Member, "afterRemoveMember": after.Member,
			} {
				if user, exists := member["user"]; exists {
					t.Fatalf("%s member unexpectedly contains joined user=%#v; member=%#v", label, user, member)
				}
			}
			if before.Member == nil || after.Member == nil || before.User["id"] != target.ID ||
				after.User["id"] != target.ID || before.Organization["id"] != organizationID ||
				after.Organization["id"] != organizationID {
				t.Fatalf("remove hooks before=%#v after=%#v", before, after)
			}

			persisted, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
				Model: "member", Where: []storage.Where{{Field: "id", Value: memberID}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if persisted != nil {
				t.Fatalf("removed member still persisted: %#v", persisted)
			}
		})
	}
}

func (harness *organizationCRUDHarness) requireJoinedMemberUser(
	t *testing.T,
	member map[string]any,
	want organizationCRUDActor,
	label string,
) {
	t.Helper()
	if member == nil {
		t.Fatalf("%s is nil", label)
	}
	var user map[string]any
	switch value := member["user"].(type) {
	case storage.Record:
		user = map[string]any(value)
	case map[string]any:
		user = value
	default:
		t.Fatalf("%s.user=%#v want object", label, member["user"])
	}
	requireOrganizationCRUDExactKeys(t, user, label+".user", "id", "name", "email", "image")
	if user["id"] != want.ID || user["name"] != want.Name || user["email"] != want.Email || user["image"] != nil {
		t.Fatalf("%s.user=%#v want=%#v", label, user, want)
	}
}

type organizationCRUDHarness struct {
	auth        *singleauth.Auth
	transport   organizationCRUDTransport
	fastHandler fasthttpserver.RequestHandler
	fiberApp    *fiberframework.App
	owner       organizationCRUDActor
}

type organizationCRUDTransport string

const (
	organizationCRUDNetHTTP  organizationCRUDTransport = "net-http"
	organizationCRUDFastHTTP organizationCRUDTransport = "fasthttp"
	organizationCRUDFiber    organizationCRUDTransport = "fiber"
)

func organizationCRUDTransports() []organizationCRUDTransport {
	return []organizationCRUDTransport{
		organizationCRUDNetHTTP,
		organizationCRUDFastHTTP,
		organizationCRUDFiber,
	}
}

type organizationCRUDActor struct {
	ID     string
	Name   string
	Email  string
	Token  string
	Cookie string
}

type organizationCRUDWireResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
	Value   any
}

func newOrganizationCRUDHarness(
	t *testing.T,
	options organization.Options,
) *organizationCRUDHarness {
	t.Helper()
	transport := organizationCRUDTransport(t.Name()[strings.LastIndex(t.Name(), "/")+1:])
	plugin := organization.MustNew(options)
	harness := &organizationCRUDHarness{transport: transport, auth: singleauth.MustNew(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           "organization-crud-org-compatibility-secret-32-bytes",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories:  []singleauth.PluginFactory{plugin},
	})}
	switch transport {
	case organizationCRUDNetHTTP:
	case organizationCRUDFastHTTP:
		harness.fastHandler = fasthttptransport.NewHandler(harness.auth.Dispatcher())
	case organizationCRUDFiber:
		harness.fiberApp = fiberframework.New()
		harness.fiberApp.Use(fibertransport.NewHandler(harness.auth.Dispatcher()))
	default:
		t.Fatalf("unsupported organization CRUD transport %q", transport)
	}
	harness.owner = harness.signUp(t, "owner@example.test", "Owner")
	return harness
}

func (harness *organizationCRUDHarness) exchange(
	t *testing.T,
	method string,
	path string,
	cookieHeader string,
	body any,
) organizationCRUDWireResponse {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	response := harness.exchangeEncoded(t, method, path, cookieHeader, body != nil, encoded)
	if len(bytes.TrimSpace(response.Body)) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(response.Body))
		decoder.UseNumber()
		if err := decoder.Decode(&response.Value); err != nil {
			t.Fatalf("decode %s %s response %q: %v", method, path, response.Body, err)
		}
	}
	if contentType := response.Headers.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("%s %s content-type=%q body=%s", method, path, contentType, response.Body)
	}
	return response
}

func (harness *organizationCRUDHarness) exchangeEncoded(
	t *testing.T,
	method string,
	path string,
	cookieHeader string,
	hasBody bool,
	encoded []byte,
) organizationCRUDWireResponse {
	t.Helper()
	target := "http://auth.example.test/api/auth" + path
	switch harness.transport {
	case organizationCRUDNetHTTP:
		request := httptest.NewRequest(method, target, bytes.NewReader(encoded))
		setOrganizationCRUDRequestHeaders(request.Header, method, cookieHeader, hasBody)
		recorder := httptest.NewRecorder()
		harness.auth.ServeHTTP(recorder, request)
		return organizationCRUDWireResponse{
			Status: recorder.Code, Headers: recorder.Header().Clone(), Body: append([]byte(nil), recorder.Body.Bytes()...),
		}

	case organizationCRUDFastHTTP:
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.SetRequestURI(target)
		if hasBody {
			request.Header.SetContentType("application/json")
			request.SetBodyRaw(encoded)
		}
		if cookieHeader != "" {
			request.Header.Set("Cookie", cookieHeader)
		}
		if method != http.MethodGet && method != http.MethodHead {
			request.Header.Set("Origin", "http://auth.example.test")
		}
		var endpointContext fasthttpserver.RequestCtx
		endpointContext.Init(&request, nil, nil)
		harness.fastHandler(&endpointContext)
		headers := make(http.Header)
		endpointContext.Response.Header.VisitAll(func(name, value []byte) {
			headers.Add(string(name), string(value))
		})
		endpointContext.Response.Header.VisitAllCookie(func(_, value []byte) {
			headers.Add("Set-Cookie", string(value))
		})
		return organizationCRUDWireResponse{
			Status: endpointContext.Response.StatusCode(), Headers: headers,
			Body: append([]byte(nil), endpointContext.Response.Body()...),
		}

	case organizationCRUDFiber:
		request, err := http.NewRequest(method, target, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		setOrganizationCRUDRequestHeaders(request.Header, method, cookieHeader, hasBody)
		response, err := harness.fiberApp.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		responseBody, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		return organizationCRUDWireResponse{
			Status: response.StatusCode, Headers: response.Header.Clone(), Body: responseBody,
		}

	default:
		t.Fatalf("unsupported organization CRUD transport %q", harness.transport)
		return organizationCRUDWireResponse{}
	}
}

func setOrganizationCRUDRequestHeaders(
	headers http.Header,
	method string,
	cookieHeader string,
	hasBody bool,
) {
	if hasBody {
		headers.Set("Content-Type", "application/json")
	}
	if cookieHeader != "" {
		headers.Set("Cookie", cookieHeader)
	}
	if method != http.MethodGet && method != http.MethodHead {
		headers.Set("Origin", "http://auth.example.test")
	}
}

func (harness *organizationCRUDHarness) invoke(
	t *testing.T,
	name string,
	body any,
) organizationCRUDWireResponse {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.NewRequest(http.MethodPost, "/:direct", contract.RequestOptions{
		Context: t.Context(), Scheme: "http", Host: "auth.example.test",
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
		Body:    encoded,
	})
	response, invokeErr := harness.auth.Invoke(name, engine.DirectInput{Request: request})
	result := organizationCRUDWireResponse{
		Status: response.Status(), Headers: make(http.Header), Body: response.Body(),
	}
	for _, field := range response.Headers().Fields() {
		result.Headers.Add(field.Name, field.Value)
	}
	if len(bytes.TrimSpace(result.Body)) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(result.Body))
		decoder.UseNumber()
		if err := decoder.Decode(&result.Value); err != nil {
			t.Fatalf("decode direct %s response %q: %v", name, result.Body, err)
		}
	}
	if invokeErr != nil {
		t.Fatalf("direct %s status=%d err=%v body=%s", name, result.Status, invokeErr, result.Body)
	}
	return result
}

func (harness *organizationCRUDHarness) signUp(t *testing.T, email, name string) organizationCRUDActor {
	t.Helper()
	response := harness.exchange(t, http.MethodPost, "/sign-up/email", "", map[string]any{
		"email": email, "name": name, "password": "password123",
	})
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	body := organizationCRUDObject(t, response.Value, "sign-up response")
	user := organizationCRUDObject(t, body["user"], "sign-up user")
	cookieHeader := cookies.ApplySetCookies("", response.Headers.Values("Set-Cookie"))
	if cookieHeader == "" {
		t.Fatalf("sign-up did not issue session cookie: headers=%#v body=%s", response.Headers, response.Body)
	}
	actor := organizationCRUDActor{
		ID: organizationCRUDString(t, user, "id"), Name: name, Email: email,
		Token: organizationCRUDString(t, body, "token"), Cookie: cookieHeader,
	}
	if user["name"] != name || user["email"] != email {
		t.Fatalf("sign-up user=%#v want name=%q email=%q", user, name, email)
	}
	harness.requireSession(t, actor, nil)
	return actor
}

func (harness *organizationCRUDHarness) requireSession(
	t *testing.T,
	actor organizationCRUDActor,
	wantActiveOrganizationID *string,
) map[string]any {
	t.Helper()
	response := harness.exchange(t, http.MethodGet, "/get-session", actor.Cookie, nil)
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	value := organizationCRUDObject(t, response.Value, "get-session response")
	user := organizationCRUDObject(t, value["user"], "get-session user")
	session := organizationCRUDObject(t, value["session"], "get-session session")
	if user["id"] != actor.ID || user["email"] != actor.Email || session["token"] != actor.Token {
		t.Fatalf("get-session response=%#v actor=%#v body=%s", value, actor, response.Body)
	}
	active, exists := session["activeOrganizationId"]
	if wantActiveOrganizationID == nil {
		if exists && active != nil && active != "" {
			t.Fatalf("activeOrganizationId=%#v want null/absent body=%s", active, response.Body)
		}
	} else if !exists || active != *wantActiveOrganizationID {
		t.Fatalf("activeOrganizationId=%#v exists=%v want=%q body=%s", active, exists, *wantActiveOrganizationID, response.Body)
	}
	return value
}

func (harness *organizationCRUDHarness) createHTTPRaw(
	t *testing.T,
	actor organizationCRUDActor,
	name string,
	slug string,
	fields map[string]any,
	wantMemberRole string,
) (map[string]any, organizationCRUDWireResponse) {
	t.Helper()
	body := map[string]any{"name": name, "slug": slug}
	for key, value := range fields {
		body[key] = value
	}
	response := harness.exchange(t, http.MethodPost, "/organization/create", actor.Cookie, body)
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	created := organizationCRUDObject(t, response.Value, "create organization response")
	organizationID := organizationCRUDString(t, created, "id")
	if created["slug"] != slug {
		t.Fatalf("created organization slug=%#v want=%q body=%s", created["slug"], slug, response.Body)
	}
	requireOrganizationCRUDTimestamp(t, created, "createdAt")
	members := organizationCRUDArray(t, created["members"], "created organization members")
	if len(members) != 1 {
		t.Fatalf("created organization members=%#v want one body=%s", members, response.Body)
	}
	member := organizationCRUDObject(t, members[0], "created owner member")
	if member["organizationId"] != organizationID || member["userId"] != actor.ID || member["role"] != wantMemberRole {
		t.Fatalf("created owner member=%#v actor=%#v body=%s", member, actor, response.Body)
	}
	requireOrganizationCRUDTimestamp(t, member, "createdAt")
	harness.requireSession(t, actor, &organizationID)
	return created, response
}

func (harness *organizationCRUDHarness) createHTTP(
	t *testing.T,
	actor organizationCRUDActor,
	name string,
	slug string,
	fields map[string]any,
) map[string]any {
	t.Helper()
	created, response := harness.createHTTPRaw(t, actor, name, slug, fields, "owner")
	if created["name"] != name {
		t.Fatalf("created organization name=%#v want=%q body=%s", created["name"], name, response.Body)
	}
	return created
}

func (harness *organizationCRUDHarness) setActiveHTTP(
	t *testing.T,
	actor organizationCRUDActor,
	body map[string]any,
	wantOrganizationID *string,
) {
	t.Helper()
	response := harness.exchange(t, http.MethodPost, "/organization/set-active", actor.Cookie, body)
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	if wantOrganizationID == nil {
		if response.Value != nil || string(bytes.TrimSpace(response.Body)) != "null" {
			t.Fatalf("clear active response=%#v body=%s want JSON null", response.Value, response.Body)
		}
	} else {
		organizationValue := organizationCRUDObject(t, response.Value, "set-active response")
		if organizationValue["id"] != *wantOrganizationID {
			t.Fatalf("set-active response=%#v want id=%q body=%s", organizationValue, *wantOrganizationID, response.Body)
		}
	}
	harness.requireSession(t, actor, wantOrganizationID)
}

func (harness *organizationCRUDHarness) getFullHTTP(
	t *testing.T,
	actor organizationCRUDActor,
	query url.Values,
) organizationCRUDWireResponse {
	t.Helper()
	path := "/organization/get-full-organization"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return harness.exchange(t, http.MethodGet, path, actor.Cookie, nil)
}

func (harness *organizationCRUDHarness) requireFullOrganization(
	t *testing.T,
	response organizationCRUDWireResponse,
	wantOrganizationID string,
	wantName string,
	wantActors []organizationCRUDActor,
) map[string]any {
	t.Helper()
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	organizationValue := organizationCRUDObject(t, response.Value, "full organization response")
	if organizationValue["id"] != wantOrganizationID || organizationValue["name"] != wantName {
		t.Fatalf("full organization=%#v want id=%q name=%q body=%s", organizationValue, wantOrganizationID, wantName, response.Body)
	}
	requireOrganizationCRUDTimestamp(t, organizationValue, "createdAt")
	organizationCRUDArray(t, organizationValue["invitations"], "full organization invitations")
	members := organizationCRUDArray(t, organizationValue["members"], "full organization members")
	if len(members) != len(wantActors) {
		t.Fatalf("full organization members=%d want=%d body=%s", len(members), len(wantActors), response.Body)
	}
	wantByID := make(map[string]organizationCRUDActor, len(wantActors))
	for _, actor := range wantActors {
		wantByID[actor.ID] = actor
	}
	for index, rawMember := range members {
		member := organizationCRUDObject(t, rawMember, fmt.Sprintf("full organization member %d", index))
		harness.requireMemberUser(t, member, wantOrganizationID, wantByID, response.Body)
	}
	return organizationValue
}

func (harness *organizationCRUDHarness) requireMemberUser(
	t *testing.T,
	member map[string]any,
	wantOrganizationID string,
	wantByID map[string]organizationCRUDActor,
	body []byte,
) {
	t.Helper()
	if member["organizationId"] != wantOrganizationID {
		t.Fatalf("member organizationId=%#v want=%q body=%s", member["organizationId"], wantOrganizationID, body)
	}
	userID := organizationCRUDString(t, member, "userId")
	actor, exists := wantByID[userID]
	if !exists {
		t.Fatalf("unexpected member userId=%q body=%s", userID, body)
	}
	user := organizationCRUDObject(t, member["user"], "member.user")
	requireOrganizationCRUDExactKeys(t, user, "member.user", "id", "name", "email", "image")
	if user["id"] != actor.ID || user["name"] != actor.Name || user["email"] != actor.Email || user["image"] != nil {
		t.Fatalf("member.user=%#v want actor=%#v body=%s", user, actor, body)
	}
}

func (harness *organizationCRUDHarness) addMemberDirect(
	t *testing.T,
	organizationID string,
	actor organizationCRUDActor,
) map[string]any {
	t.Helper()
	response := harness.invoke(t, "addMember", map[string]any{
		"organizationId": organizationID, "userId": actor.ID, "role": "member",
	})
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	member := organizationCRUDObject(t, response.Value, "direct add-member response")
	if member["organizationId"] != organizationID || member["userId"] != actor.ID || member["role"] != "member" {
		t.Fatalf("direct add-member response=%#v body=%s", member, response.Body)
	}
	return member
}

func runOrganizationCRUDOrgHTTPScenario(
	t *testing.T,
	title string,
	transport organizationCRUDTransport,
) {
	t.Helper()
	switch title {
	case "should get organization by organizationId":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		first := harness.createHTTP(t, harness.owner, "test", "test", map[string]any{"metadata": map[string]any{"test": "test"}})
		second := harness.createHTTP(t, harness.owner, "test-second", "test-second", map[string]any{"metadata": map[string]any{"test": "second-org"}})
		firstID := organizationCRUDString(t, first, "id")
		secondID := organizationCRUDString(t, second, "id")
		harness.setActiveHTTP(t, harness.owner, map[string]any{"organizationId": secondID}, &secondID)
		response := harness.getFullHTTP(t, harness.owner, url.Values{"organizationId": []string{firstID}})
		harness.requireFullOrganization(t, response, firstID, "test", []organizationCRUDActor{harness.owner})

	case "should get organization by organizationSlug":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		response := harness.getFullHTTP(t, harness.owner, url.Values{"organizationSlug": []string{"test"}})
		harness.requireFullOrganization(t, response, organizationCRUDString(t, created, "id"), "test", []organizationCRUDActor{harness.owner})

	case "should return null when no active organization and no query params":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		harness.createHTTP(t, harness.owner, "test", "test", nil)
		harness.setActiveHTTP(t, harness.owner, map[string]any{"organizationId": nil}, nil)
		response := harness.getFullHTTP(t, harness.owner, nil)
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
		if response.Value != nil || string(bytes.TrimSpace(response.Body)) != "null" {
			t.Fatalf("organization without selector=%#v body=%s want JSON null", response.Value, response.Body)
		}

	case "should throw FORBIDDEN when user is not a member of the organization":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		other := harness.signUp(t, "test3@test.com", "test3")
		response := harness.getFullHTTP(t, other, url.Values{"organizationId": []string{organizationCRUDString(t, created, "id")}})
		requireOrganizationCRUDWireError(t, response, http.StatusForbidden, organization.ErrorUserNotOrganizationMember, "User is not a member of the organization")

	case "should throw BAD_REQUEST when organization doesn't exist":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		response := harness.getFullHTTP(t, harness.owner, url.Values{"organizationId": []string{"non-existent-org-id"}})
		requireOrganizationCRUDWireError(t, response, http.StatusBadRequest, organization.ErrorOrganizationNotFound, "Organization not found")

	case "should include invitations in the response":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		organizationID := organizationCRUDString(t, created, "id")
		harness.setActiveHTTP(t, harness.owner, map[string]any{"organizationId": organizationID}, &organizationID)
		invitationResponse := harness.exchange(t, http.MethodPost, "/organization/invite-member", harness.owner.Cookie, map[string]any{
			"email": "invited@test.com", "role": "member",
		})
		requireOrganizationCRUDStatus(t, invitationResponse, http.StatusOK)
		invitation := organizationCRUDObject(t, invitationResponse.Value, "create invitation response")
		if invitation["organizationId"] != organizationID || invitation["email"] != "invited@test.com" ||
			invitation["role"] != "member" || invitation["status"] != "pending" || invitation["inviterId"] != harness.owner.ID {
			t.Fatalf("create invitation response=%#v body=%s", invitation, invitationResponse.Body)
		}
		fullResponse := harness.getFullHTTP(t, harness.owner, nil)
		full := harness.requireFullOrganization(t, fullResponse, organizationID, "test", []organizationCRUDActor{harness.owner})
		invitations := organizationCRUDArray(t, full["invitations"], "full organization invitations")
		if len(invitations) != 1 {
			t.Fatalf("full organization invitations=%#v body=%s", invitations, fullResponse.Body)
		}
		listed := organizationCRUDObject(t, invitations[0], "listed invitation")
		if listed["id"] != invitation["id"] || listed["email"] != "invited@test.com" || listed["role"] != "member" {
			t.Fatalf("listed invitation=%#v created=%#v body=%s", listed, invitation, fullResponse.Body)
		}

	case "should prioritize organizationSlug over organizationId when both are provided":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		first := harness.createHTTP(t, harness.owner, "test", "test", nil)
		second := harness.createHTTP(t, harness.owner, "test-second", "test-second", nil)
		response := harness.getFullHTTP(t, harness.owner, url.Values{
			"organizationId":   []string{organizationCRUDString(t, first, "id")},
			"organizationSlug": []string{organizationCRUDString(t, second, "slug")},
		})
		harness.requireFullOrganization(t, response, organizationCRUDString(t, second, "id"), "test-second", []organizationCRUDActor{harness.owner})

	case "should allow listing members with membersLimit":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		organizationID := organizationCRUDString(t, created, "id")
		harness.setActiveHTTP(t, harness.owner, map[string]any{"organizationId": organizationID}, &organizationID)
		other := harness.signUp(t, "test2@test.com", "test2")
		harness.addMemberDirect(t, organizationID, other)
		fullResponse := harness.getFullHTTP(t, harness.owner, nil)
		harness.requireFullOrganization(t, fullResponse, organizationID, "test", []organizationCRUDActor{harness.owner, other})
		limitedResponse := harness.getFullHTTP(t, harness.owner, url.Values{"membersLimit": []string{"1"}})
		requireOrganizationCRUDStatus(t, limitedResponse, http.StatusOK)
		limited := organizationCRUDObject(t, limitedResponse.Value, "limited full organization")
		members := organizationCRUDArray(t, limited["members"], "limited members")
		if len(members) != 1 {
			t.Fatalf("limited members=%#v body=%s", members, limitedResponse.Body)
		}
		member := organizationCRUDObject(t, members[0], "limited member")
		harness.requireMemberUser(t, member, organizationID, map[string]organizationCRUDActor{
			harness.owner.ID: harness.owner, other.ID: other,
		}, limitedResponse.Body)

	case "should use default membershipLimit when no membersLimit is specified":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		organizationID := organizationCRUDString(t, created, "id")
		harness.setActiveHTTP(t, harness.owner, map[string]any{"organizationId": organizationID}, &organizationID)
		actors := []organizationCRUDActor{harness.owner}
		for index := 3; index <= 5; index++ {
			actor := harness.signUp(t, fmt.Sprintf("test-%d@test.com", index), fmt.Sprintf("test%d", index))
			harness.addMemberDirect(t, organizationID, actor)
			actors = append(actors, actor)
		}
		response := harness.getFullHTTP(t, harness.owner, nil)
		full := harness.requireFullOrganization(t, response, organizationID, "test", actors)
		members := organizationCRUDArray(t, full["members"], "default-limit members")
		if len(members) <= 3 || len(members) > 6 {
			t.Fatalf("default membershipLimit returned %d members body=%s", len(members), response.Body)
		}

	case "should apply beforeCreateOrganization hook":
		called := false
		harness := newOrganizationCRUDHarness(t, organization.Options{Hooks: organization.OrganizationHooks{
			BeforeCreateOrganization: func(_ context.Context, _ organization.BeforeCreateOrganizationData) (storage.Record, error) {
				called = true
				return storage.Record{"name": "changed-name", "metadata": map[string]any{"hookCalled": true}}, nil
			},
		}})
		created, response := harness.createHTTPRaw(t, harness.owner, "test", "test", nil, "owner")
		metadata := organizationCRUDObject(t, created["metadata"], "before-create metadata")
		if !called || created["name"] != "changed-name" || len(metadata) != 1 || metadata["hookCalled"] != true {
			t.Fatalf("before-create response=%#v called=%v body=%s", created, called, response.Body)
		}

	case "should apply afterCreateOrganization hook":
		called := false
		harness := newOrganizationCRUDHarness(t, organization.Options{Hooks: organization.OrganizationHooks{
			AfterCreateOrganization: func(_ context.Context, _ organization.AfterCreateOrganizationData) error {
				called = true
				return nil
			},
		}})
		harness.createHTTP(t, harness.owner, "test", "test", nil)
		if !called {
			t.Fatal("after-create hook was not called")
		}

	case "should apply beforeAddMember hook":
		called := false
		harness := newOrganizationCRUDHarness(t, organization.Options{Hooks: organization.OrganizationHooks{
			BeforeAddMember: func(_ context.Context, _ organization.BeforeAddMemberData) (storage.Record, error) {
				called = true
				return storage.Record{"role": "changed-role"}, nil
			},
		}})
		created, createResponse := harness.createHTTPRaw(t, harness.owner, "test", "test", nil, "changed-role")
		if created["name"] != "test" {
			t.Fatalf("before-add-member create response=%#v body=%s", created, createResponse.Body)
		}
		organizationID := organizationCRUDString(t, created, "id")
		response := harness.exchange(t, http.MethodGet, "/organization/get-active-member", harness.owner.Cookie, nil)
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
		member := organizationCRUDObject(t, response.Value, "active member response")
		if !called || member["organizationId"] != organizationID || member["userId"] != harness.owner.ID || member["role"] != "changed-role" {
			t.Fatalf("before-add-member response=%#v called=%v body=%s", member, called, response.Body)
		}
		harness.requireMemberUser(t, member, organizationID, map[string]organizationCRUDActor{harness.owner.ID: harness.owner}, response.Body)

	case "should apply afterAddMember hook":
		called := false
		harness := newOrganizationCRUDHarness(t, organization.Options{Hooks: organization.OrganizationHooks{
			AfterAddMember: func(_ context.Context, _ organization.AfterAddMemberData) error {
				called = true
				return nil
			},
		}})
		harness.createHTTP(t, harness.owner, "test", "test", nil)
		if !called {
			t.Fatal("after-add-member hook was not called")
		}

	case "should apply beforeCreateTeam hook":
		called := false
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Teams: organization.TeamsOptions{Enabled: true},
			Hooks: organization.OrganizationHooks{BeforeCreateTeam: func(_ context.Context, _ organization.BeforeCreateTeamData) (storage.Record, error) {
				called = true
				return storage.Record{"name": "changed-name"}, nil
			}},
		})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		organizationID := organizationCRUDString(t, created, "id")
		response := harness.exchange(t, http.MethodGet, "/organization/list-teams?organizationId="+url.QueryEscape(organizationID), harness.owner.Cookie, nil)
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
		teams := organizationCRUDArray(t, response.Value, "organization teams")
		if !called || len(teams) != 1 {
			t.Fatalf("before-create-team teams=%#v called=%v body=%s", teams, called, response.Body)
		}
		team := organizationCRUDObject(t, teams[0], "default team")
		if team["name"] != "changed-name" || team["organizationId"] != organizationID {
			t.Fatalf("before-create-team team=%#v body=%s", team, response.Body)
		}

	case "should apply afterCreateTeam hook":
		called := false
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Teams: organization.TeamsOptions{Enabled: true},
			Hooks: organization.OrganizationHooks{AfterCreateTeam: func(_ context.Context, _ organization.AfterCreateTeamData) error {
				called = true
				return nil
			}},
		})
		harness.createHTTP(t, harness.owner, "test", "test", nil)
		if !called {
			t.Fatal("after-create-team hook was not called")
		}

	case "should allow passing id through `beforeCreateTeam`":
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Teams: organization.TeamsOptions{Enabled: true},
			Hooks: organization.OrganizationHooks{BeforeCreateTeam: func(_ context.Context, _ organization.BeforeCreateTeamData) (storage.Record, error) {
				return storage.Record{"id": "custom-team-id"}, nil
			}},
		})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		organizationID := organizationCRUDString(t, created, "id")
		response := harness.exchange(t, http.MethodGet, "/organization/list-teams?organizationId="+url.QueryEscape(organizationID), harness.owner.Cookie, nil)
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
		teams := organizationCRUDArray(t, response.Value, "organization teams")
		if len(teams) != 1 {
			t.Fatalf("custom-team teams=%#v body=%s", teams, response.Body)
		}
		team := organizationCRUDObject(t, teams[0], "custom team")
		if team["id"] != "custom-team-id" || team["organizationId"] != organizationID {
			t.Fatalf("custom team=%#v body=%s", team, response.Body)
		}

	case "should allow passing id through `beforeCreateInvitation`":
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Hooks: organization.OrganizationHooks{BeforeCreateInvitation: func(_ context.Context, _ organization.BeforeCreateInvitationData) (storage.Record, error) {
				return storage.Record{"id": "custom-invitation-id"}, nil
			}},
			SendInvitationEmail: func(context.Context, organization.Invitation) error { return nil },
		})
		created := harness.createHTTP(t, harness.owner, "test", "test", nil)
		organizationID := organizationCRUDString(t, created, "id")
		response := harness.exchange(t, http.MethodPost, "/organization/invite-member", harness.owner.Cookie, map[string]any{
			"email": "invited@test.com", "role": "member", "organizationId": organizationID,
		})
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
		invitation := organizationCRUDObject(t, response.Value, "custom invitation response")
		if invitation["id"] != "custom-invitation-id" || invitation["organizationId"] != organizationID || invitation["inviterId"] != harness.owner.ID {
			t.Fatalf("custom invitation response=%#v body=%s", invitation, response.Body)
		}

	case "should allow internal organization creation when disabled for users":
		allowed := false
		harness := newOrganizationCRUDHarness(t, organization.Options{AllowUserToCreateOrganization: &allowed})
		signUpResponse := harness.invoke(t, "signUpEmail", map[string]any{
			"email": "internal@test.com", "password": "password123", "name": "Internal User",
		})
		requireOrganizationCRUDStatus(t, signUpResponse, http.StatusOK)
		signUp := organizationCRUDObject(t, signUpResponse.Value, "direct sign-up response")
		userID := organizationCRUDString(t, organizationCRUDObject(t, signUp["user"], "direct sign-up user"), "id")
		response := harness.invoke(t, "createOrganization", map[string]any{
			"name": "Internal Org", "slug": "internal-org", "userId": userID,
		})
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
		created := organizationCRUDObject(t, response.Value, "internal organization response")
		if created["name"] != "Internal Org" || created["slug"] != "internal-org" {
			t.Fatalf("internal organization response=%#v body=%s", created, response.Body)
		}
		members := organizationCRUDArray(t, created["members"], "internal organization members")
		if len(members) != 1 || organizationCRUDObject(t, members[0], "internal member")["userId"] != userID {
			t.Fatalf("internal organization members=%#v body=%s", members, response.Body)
		}

	case "should clear the logo when passing null":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		logo := "https://example.com/logo.png"
		created := harness.createHTTP(t, harness.owner, "Logo Org", "logo-org", map[string]any{"logo": logo})
		if created["logo"] != logo {
			t.Fatalf("created logo=%#v want=%q", created["logo"], logo)
		}
		organizationID := organizationCRUDString(t, created, "id")
		response := harness.exchange(t, http.MethodPost, "/organization/update", harness.owner.Cookie, map[string]any{
			"organizationId": organizationID, "data": map[string]any{"logo": nil},
		})
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
		updated := organizationCRUDObject(t, response.Value, "update organization response")
		logoValue, exists := updated["logo"]
		if !exists || logoValue != nil {
			t.Fatalf("updated logo=%#v exists=%v body=%s", logoValue, exists, response.Body)
		}
		fullResponse := harness.getFullHTTP(t, harness.owner, nil)
		full := harness.requireFullOrganization(t, fullResponse, organizationID, "Logo Org", []organizationCRUDActor{harness.owner})
		logoValue, exists = full["logo"]
		if !exists || logoValue != nil {
			t.Fatalf("persisted logo=%#v exists=%v body=%s", logoValue, exists, fullResponse.Body)
		}

	case "should accept a null logo on create":
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "Null Logo Org", "null-logo-org", map[string]any{"logo": nil})
		logoValue, exists := created["logo"]
		if !exists || logoValue != nil {
			t.Fatalf("null logo=%#v exists=%v response=%#v", logoValue, exists, created)
		}

	default:
		t.Fatalf("unhandled organization CRUD scenario %q", title)
	}
}

func requireOrganizationCRUDStatus(t *testing.T, response organizationCRUDWireResponse, want int) {
	t.Helper()
	if response.Status != want {
		t.Fatalf("wire status=%d want=%d headers=%#v body=%s", response.Status, want, response.Headers, response.Body)
	}
}

func requireOrganizationCRUDWireError(
	t *testing.T,
	response organizationCRUDWireResponse,
	wantStatus int,
	wantCode string,
	wantMessage string,
) {
	t.Helper()
	requireOrganizationCRUDStatus(t, response, wantStatus)
	body := organizationCRUDObject(t, response.Value, "wire error")
	requireOrganizationCRUDExactKeys(t, body, "wire error", "code", "message")
	if body["code"] != wantCode || body["message"] != wantMessage {
		t.Fatalf("wire error=%#v want code=%q message=%q raw=%s", body, wantCode, wantMessage, response.Body)
	}
}

func organizationCRUDObject(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s=%#v want JSON object", label, value)
	}
	return object
}

func organizationCRUDArray(t *testing.T, value any, label string) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("%s=%#v want JSON array", label, value)
	}
	return array
}

func organizationCRUDString(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		t.Fatalf("JSON field %s=%#v in %#v want non-empty string", key, object[key], object)
	}
	return value
}

func requireOrganizationCRUDExactKeys(t *testing.T, object map[string]any, label string, keys ...string) {
	t.Helper()
	want := append([]string(nil), keys...)
	got := make([]string, 0, len(object))
	for key := range object {
		got = append(got, key)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s keys=%v want=%v object=%#v", label, got, want, object)
	}
}

func requireOrganizationCRUDTimestamp(t *testing.T, object map[string]any, key string) time.Time {
	t.Helper()
	raw := organizationCRUDString(t, object, key)
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("JSON field %s=%q is not RFC3339: %v", key, raw, err)
	}
	return value
}
