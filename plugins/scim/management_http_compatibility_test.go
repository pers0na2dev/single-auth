package scim

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/plugins/genericoauth"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/plugins/sso"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type scimManagementCase func(*testing.T, string)

type scimManagementScenario struct {
	Suite string
	Name  string
	Run   scimManagementCase
}

type scimManagementSetup struct {
	SCIM              Options
	Organization      organization.Options
	SSO               sso.Options
	SocialProviderIDs []string
	GenericOAuth      bool
}

type scimManagementIdentity struct {
	ID     string
	Email  string
	Cookie string
}

type scimManagementRoundTrip func(*testing.T, string, string, string, http.Header, []byte) (int, http.Header, []byte)

type scimManagementHarness struct {
	auth      *singleauth.Auth
	adapter   storage.Adapter
	clock     time.Time
	roundTrip scimManagementRoundTrip
}

func TestSCIMManagementBehaviorAcrossTransports(t *testing.T) {
	scenarios := scimManagementScenarios()
	if len(scenarios) != 42 {
		t.Fatalf("SCIM management scenario count=%d, want 42", len(scenarios))
	}
	seen := make(map[string]struct{}, len(scenarios))
	for _, scenario := range scenarios {
		scenario := scenario
		key := scenario.Suite + "::" + scenario.Name
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate SCIM management scenario %q", key)
		}
		seen[key] = struct{}{}
		t.Run(key, func(t *testing.T) {
			for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
				transport := transport
				t.Run(transport, func(t *testing.T) { scenario.Run(t, transport) })
			}
		})
	}
}

func scimManagementScenarios() []scimManagementScenario {
	result := make([]scimManagementScenario, 0, 42)
	add := func(suite, title string, run scimManagementCase) {
		result = append(result, scimManagementScenario{Suite: suite, Name: title, Run: run})
	}
	generateSuite := "SCIM provider management > POST /scim/generate-token"
	add(generateSuite, "should require user session", scimCaseRequiresSession)
	add(generateSuite, "should deny personal token creation when canGenerateToken returns false", scimCaseCanGenerateFalse)
	add(generateSuite, "should allow token creation when canGenerateToken returns true (member is null for personal)", scimCaseCanGenerateTrue)
	add(generateSuite, "should fail if the authenticated user does not belong to the given org", scimCaseNotOrganizationMember)
	add(generateSuite, "should fail to generate a SCIM token on invalid provider", scimCaseInvalidProvider)
	add(generateSuite, "rejects providerId values that collide with built-in account providers", scimCaseBuiltInProviderCollisions)
	add(generateSuite, "rejects providerId values that collide with configured social providers", scimCaseSocialProviderCollisions)
	add(generateSuite, "rejects providerId values that collide with configured generic OAuth providers", scimCaseGenericOAuthCollision)
	add(generateSuite, "rejects providerId values that collide with SSO providers", scimCaseSSOProviderCollision)
	add(generateSuite, "prevents SSO provider registration with an existing SCIM providerId", scimCaseReverseSSOCollision)
	add(generateSuite, "rejects providerId values that collide with default SSO providers", scimCaseDefaultSSOCollision)
	add(generateSuite, "should generate a new scim token (client)", scimCaseGenerateClient)
	add(generateSuite, "should generate a new scim token (plain)", scimCaseGeneratePlain)
	add(generateSuite, "should generate a new scim token (hashed)", scimCaseGenerateHashed)
	add(generateSuite, "should generate a new scim token (custom hash)", scimCaseGenerateCustomHash)
	add(generateSuite, "should generate a new scim token (encrypted)", scimCaseGenerateEncrypted)
	add(generateSuite, "should generate a new scim token (custom encryption)", scimCaseGenerateCustomEncryption)
	add(generateSuite, "rejects a SCIM token whose secret does not match the stored value", scimCaseRejectsForgedToken)
	add(generateSuite, "should generate a new scim token associated to an org", scimCaseGenerateOrganizationToken)
	add(generateSuite, "should execute hooks before SCIM token generation", scimCaseBeforeTokenHook)
	add(generateSuite, "should execute hooks after SCIM token generation", scimCaseAfterTokenHook)
	add(generateSuite, "should deny regenerate when user is not the owner of a personal provider", scimCaseDenyPersonalRegenerate)
	add(generateSuite, "should deny regenerate when provider belongs to another org", scimCaseDenyOrganizationRegenerate)

	listSuite := "SCIM provider management > GET /scim/list-provider-connections"
	add(listSuite, "should return empty list when user is not in any org", scimCaseListEmpty)
	add(listSuite, "should return org-scoped providers for orgs the user is a member of", scimCaseListOrganizationProviders)
	add(listSuite, "should return owned non-org providers in list for the owner", scimCaseListOwnedPersonalProviders)

	getSuite := "SCIM provider management > GET /scim/get-provider-connection"
	add(getSuite, "should return provider details when user is org member", scimCaseGetOrganizationProvider)
	add(getSuite, "should return own non-org provider", scimCaseGetPersonalProvider)
	add(getSuite, "should deny access to non-org provider when user is not the owner", scimCaseGetPersonalDenied)
	add(getSuite, "should return 403 when provider belongs to another org", scimCaseGetOtherOrganizationDenied)
	add(getSuite, "should return 403 when token creator was removed from org (org membership required)", scimCaseGetRemovedOwnerDenied)
	add(getSuite, "should return 404 for unknown providerId", scimCaseGetUnknown)

	deleteSuite := "SCIM provider management > POST /scim/delete-provider-connection"
	add(deleteSuite, "should delete org-scoped provider and invalidate token when user is org member", scimCaseDeleteOrganizationProvider)
	add(deleteSuite, "should return 403 when provider belongs to another org", scimCaseDeleteOtherOrganizationDenied)
	add(deleteSuite, "should return 404 for unknown providerId", scimCaseDeleteUnknown)
	add(deleteSuite, "should deny delete of non-org provider when user is not the owner", scimCaseDeletePersonalDenied)

	roleSuite := "SCIM provider management > role-based authorization"
	add(roleSuite, "should deny org-scoped token generation for a regular member", scimCaseRoleMemberDenied)
	add(roleSuite, "should allow org-scoped token generation for an admin", scimCaseRoleAdminAllowed)
	add(roleSuite, "should allow org provider access for members with multiple roles", scimCaseMultipleRolesAllowed)
	add(roleSuite, "should respect custom requiredRole configuration", scimCaseCustomRequiredRole)
	add(roleSuite, "should default to the organization creator role when it is customized", scimCaseCustomCreatorRole)
	add(roleSuite, "should filter org providers by role in list endpoint", scimCaseListRoleFilter)
	return result
}

func newSCIMManagementHarness(t *testing.T, transport string, setup scimManagementSetup) scimManagementHarness {
	t.Helper()
	fixedNow := time.Date(2026, time.August, 9, 18, 0, 0, 0, time.UTC)
	factories := []singleauth.PluginFactory{
		sso.NewFactory(setup.SSO),
		NewFactory(setup.SCIM),
		organization.NewFactory(setup.Organization),
	}
	if setup.GenericOAuth {
		factories = append(factories, genericoauth.NewFactory(genericoauth.Options{Config: []genericoauth.Config{{
			ProviderID: "generic-provider", ClientID: "generic-client-id", ClientSecret: "generic-client-secret",
			AuthorizationURL: "https://idp.example.com/auth", TokenURL: "https://idp.example.com/token",
			UserInfoURL: "https://idp.example.com/userinfo",
		}}}))
	}
	socialProviders := make(map[string]*providers.Provider, len(setup.SocialProviderIDs))
	for _, id := range setup.SocialProviderIDs {
		socialProviders[id] = &providers.Provider{ID: id, Name: id}
	}
	rateLimitEnabled := false
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test", Secret: "0123456789abcdef0123456789abcdef",
		Clock: func() time.Time { return fixedNow }, RateLimit: singleauth.RateLimitOptions{Enabled: &rateLimitEnabled},
		Logger: logger.Options{Disabled: true}, SocialProviders: socialProviders,
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
	return scimManagementHarness{
		auth: auth, adapter: auth.Adapter(), clock: fixedNow,
		roundTrip: newSCIMManagementRoundTrip(t, auth, transport),
	}
}

func (h scimManagementHarness) signUp(t *testing.T, localPart string) scimManagementIdentity {
	t.Helper()
	email := localPart + "@policy.test"
	status, headers, body := h.exchange(t, http.MethodPost, "/sign-up/email", "", nil, map[string]any{
		"email": email, "password": "password123", "name": localPart,
	})
	if status != http.StatusOK {
		t.Fatalf("sign up %s status=%d body=%#v", email, status, body)
	}
	user, _ := body["user"].(map[string]any)
	userID, _ := user["id"].(string)
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	if userID == "" || cookie == "" {
		t.Fatalf("sign up %s user/cookie=%#v/%q", email, user, cookie)
	}
	return scimManagementIdentity{ID: userID, Email: email, Cookie: cookie}
}

func (h scimManagementHarness) seedOrganization(t *testing.T, organizationID string, owner scimManagementIdentity, role string) {
	t.Helper()
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{
		Model: "organization", ForceAllowID: true,
		Data: storage.Record{"id": organizationID, "name": organizationID, "slug": organizationID, "createdAt": h.clock},
	}); err != nil {
		t.Fatal(err)
	}
	h.seedMember(t, organizationID, owner.ID, role)
}

func (h scimManagementHarness) seedMember(t *testing.T, organizationID, userID, role string) {
	t.Helper()
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{Model: "member", Data: storage.Record{
		"organizationId": organizationID, "userId": userID, "role": role, "createdAt": h.clock,
	}}); err != nil {
		t.Fatal(err)
	}
}

func (h scimManagementHarness) generate(t *testing.T, actor scimManagementIdentity, providerID, organizationID string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{"providerId": providerID}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	status, _, response := h.exchange(t, http.MethodPost, "/scim/generate-token", actor.Cookie, nil, body)
	return status, response
}

func (h scimManagementHarness) registerSSO(t *testing.T, actor scimManagementIdentity, providerID string) (int, map[string]any) {
	t.Helper()
	status, _, response := h.exchange(t, http.MethodPost, "/sso/register", actor.Cookie, nil, map[string]any{
		"providerId": providerID,
		"issuer":     "https://idp.example.com",
		"domain":     "example.com",
		"samlConfig": map[string]any{
			"entryPoint":  "https://idp.example.com/sso",
			"cert":        "test-cert",
			"callbackUrl": "http://auth.example.test/api/sso/callback",
			"spMetadata":  map[string]any{},
		},
	})
	return status, response
}

func (h scimManagementHarness) exchange(
	t *testing.T,
	method, path, cookie string,
	headers http.Header,
	body any,
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
	status, responseHeaders, responseBody := h.roundTrip(t, method, target, cookie, headers, encoded)
	decoded := map[string]any{}
	if len(responseBody) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(responseBody))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatalf("decode %s %s status=%d body=%q: %v", method, path, status, responseBody, err)
		}
	}
	return status, responseHeaders, decoded
}

func newSCIMManagementRoundTrip(t *testing.T, auth *singleauth.Auth, transport string) scimManagementRoundTrip {
	t.Helper()
	switch transport {
	case "net/http":
		return func(t *testing.T, method, target, cookie string, headers http.Header, body []byte) (int, http.Header, []byte) {
			t.Helper()
			request := newSCIMManagementHTTPRequest(t, method, target, cookie, headers, body)
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			return recorder.Code, recorder.Header().Clone(), append([]byte(nil), recorder.Body.Bytes()...)
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(t *testing.T, method, target, cookie string, headers http.Header, body []byte) (int, http.Header, []byte) {
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
			for name, values := range headers {
				for _, value := range values {
					request.Header.Add(name, value)
				}
			}
			request.SetRequestURI(target)
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, nil, nil)
			handler(&requestContext)
			responseHeaders := make(http.Header)
			requestContext.Response.Header.VisitAll(func(name, value []byte) {
				if !strings.EqualFold(string(name), "Set-Cookie") {
					responseHeaders.Add(string(name), string(value))
				}
			})
			requestContext.Response.Header.VisitAllCookie(func(_, value []byte) {
				responseHeaders.Add("Set-Cookie", string(value))
			})
			return requestContext.Response.StatusCode(), responseHeaders, append([]byte(nil), requestContext.Response.Body()...)
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(t *testing.T, method, target, cookie string, headers http.Header, body []byte) (int, http.Header, []byte) {
			t.Helper()
			request := newSCIMManagementHTTPRequest(t, method, target, cookie, headers, body)
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
		t.Fatalf("unsupported SCIM management transport %q", transport)
		return nil
	}
}

func newSCIMManagementHTTPRequest(t *testing.T, method, target, cookie string, headers http.Header, body []byte) *http.Request {
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
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	return request
}

func requireSCIMStatus(t *testing.T, got, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("SCIM status=%d body=%#v, want %d", got, body, want)
	}
}

func requireSCIMError(t *testing.T, status int, body map[string]any, wantStatus int, wantMessage string) {
	t.Helper()
	requireSCIMStatus(t, status, wantStatus, body)
	if body["message"] != wantMessage {
		t.Fatalf("SCIM error body=%#v, want message %q", body, wantMessage)
	}
}

func requireGeneratedToken(t *testing.T, status int, body map[string]any) string {
	t.Helper()
	requireSCIMStatus(t, status, http.StatusCreated, body)
	token, _ := body["scimToken"].(string)
	if token == "" {
		t.Fatalf("SCIM token response=%#v", body)
	}
	return token
}

func providerIDsFromResponse(t *testing.T, response map[string]any) []string {
	t.Helper()
	raw, _ := response["providers"].([]any)
	result := make([]string, 0, len(raw))
	for _, entry := range raw {
		provider, _ := entry.(map[string]any)
		providerID, _ := provider["providerId"].(string)
		result = append(result, providerID)
	}
	sort.Strings(result)
	return result
}

func providerFromResponse(t *testing.T, response map[string]any, providerID string) map[string]any {
	t.Helper()
	raw, ok := response["providers"].([]any)
	if !ok {
		t.Fatalf("SCIM provider response=%#v, want providers array", response)
	}
	for _, entry := range raw {
		provider, ok := entry.(map[string]any)
		if ok && provider["providerId"] == providerID {
			return provider
		}
	}
	t.Fatalf("SCIM provider %q absent from response=%#v", providerID, response)
	return nil
}

func (h scimManagementHarness) assertTokenUsable(t *testing.T, token, userName string) {
	t.Helper()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	status, _, body := h.exchange(t, http.MethodPost, "/scim/v2/Users", "", headers, map[string]any{"userName": userName})
	requireSCIMStatus(t, status, http.StatusCreated, body)
}

func (h scimManagementHarness) storedProvider(t *testing.T, providerID string) storage.Record {
	t.Helper()
	record, err := h.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "scimProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
	})
	if err != nil || record == nil {
		t.Fatalf("SCIM provider %q row=%#v err=%v", providerID, record, err)
	}
	return record
}

func scimCaseRequiresSession(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	status, _, body := h.exchange(t, http.MethodPost, "/scim/generate-token", "", nil, map[string]any{"providerId": "the id"})
	requireSCIMStatus(t, status, http.StatusUnauthorized, body)
}

func scimCaseCanGenerateFalse(t *testing.T, transport string) {
	setup := scimManagementSetup{SCIM: Options{CanGenerateToken: func(_ context.Context, payload TokenGenerationPayload) (bool, error) {
		return payload.OrganizationID != "", nil
	}}}
	h := newSCIMManagementHarness(t, transport, setup)
	actor := h.signUp(t, "can-generate-false")
	status, body := h.generate(t, actor, "personal-provider", "")
	requireSCIMError(t, status, body, http.StatusForbidden, "You are not allowed to generate a SCIM token")
}

func scimCaseCanGenerateTrue(t *testing.T, transport string) {
	var calls atomic.Int32
	setup := scimManagementSetup{SCIM: Options{CanGenerateToken: func(_ context.Context, payload TokenGenerationPayload) (bool, error) {
		calls.Add(1)
		if payload.ProviderID != "personal-provider" || payload.Member != nil || payload.OrganizationID != "" {
			return false, fmt.Errorf("unexpected personal token payload: %#v", payload)
		}
		return true, nil
	}}}
	h := newSCIMManagementHarness(t, transport, setup)
	actor := h.signUp(t, "can-generate-true")
	status, body := h.generate(t, actor, "personal-provider", "")
	requireGeneratedToken(t, status, body)
	if calls.Load() != 1 {
		t.Fatalf("canGenerateToken calls=%d, want 1", calls.Load())
	}
}

func scimCaseNotOrganizationMember(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "not-org-member")
	status, body := h.generate(t, actor, "the id", "missing-org")
	requireSCIMError(t, status, body, http.StatusForbidden, "You are not a member of the organization")
}

func scimCaseInvalidProvider(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "invalid-provider")
	status, body := h.generate(t, actor, "the:provider", "")
	requireSCIMError(t, status, body, http.StatusBadRequest, "Provider id contains forbidden characters")
}

func scimCaseBuiltInProviderCollisions(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "built-in-collisions")
	for _, providerID := range []string{"credential", "email-otp", "magic-link", "phone-number", "anonymous", "siwe"} {
		status, body := h.generate(t, actor, providerID, "")
		requireSCIMError(t, status, body, http.StatusBadRequest, "Provider id collides with another account provider and cannot be used for SCIM")
	}
}

func scimCaseSocialProviderCollisions(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SocialProviderIDs: []string{"google", "github", "discord"}})
	actor := h.signUp(t, "social-collisions")
	for _, providerID := range []string{"google", "github", "discord"} {
		status, body := h.generate(t, actor, providerID, "")
		requireSCIMError(t, status, body, http.StatusBadRequest, "Provider id collides with another account provider and cannot be used for SCIM")
	}
}

func scimCaseGenericOAuthCollision(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{GenericOAuth: true})
	actor := h.signUp(t, "generic-collision")
	status, body := h.generate(t, actor, "generic-provider", "")
	requireSCIMError(t, status, body, http.StatusBadRequest, "Provider id collides with another account provider and cannot be used for SCIM")
}

func scimCaseSSOProviderCollision(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "sso-collision")
	status, response := h.registerSSO(t, actor, "sso-provider")
	if status != http.StatusOK {
		t.Fatalf("register SSO status=%d body=%#v", status, response)
	}
	status, body := h.generate(t, actor, "sso-provider", "")
	requireSCIMError(t, status, body, http.StatusBadRequest, "Provider id collides with another account provider and cannot be used for SCIM")
}

func scimCaseReverseSSOCollision(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "reverse-sso-collision")
	status, body := h.generate(t, actor, "scim-provider", "")
	requireGeneratedToken(t, status, body)
	status, body = h.registerSSO(t, actor, "scim-provider")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("reverse SSO collision status=%d body=%#v, want 422", status, body)
	}
}

func scimCaseDefaultSSOCollision(t *testing.T, transport string) {
	setup := scimManagementSetup{SSO: sso.Options{DefaultSSO: []sso.DefaultProvider{{
		ProviderID: "default-sso-provider", Domain: "example.com",
		SAMLConfig: sso.SAMLConfig{
			Issuer: "https://idp.example.com", EntryPoint: "https://idp.example.com/sso",
			Certificate: "test-cert", CallbackURL: "http://auth.example.test/api/sso/callback",
		},
	}}}}
	h := newSCIMManagementHarness(t, transport, setup)
	actor := h.signUp(t, "default-sso-collision")
	status, body := h.generate(t, actor, "default-sso-provider", "")
	requireSCIMError(t, status, body, http.StatusBadRequest, "Provider id collides with another account provider and cannot be used for SCIM")
}

func runSCIMGenerationAndProvision(t *testing.T, transport, localPart, providerID string, options Options) (scimManagementHarness, scimManagementIdentity, string) {
	t.Helper()
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SCIM: options})
	actor := h.signUp(t, localPart)
	status, body := h.generate(t, actor, providerID, "")
	token := requireGeneratedToken(t, status, body)
	h.assertTokenUsable(t, token, "provisioned-"+localPart)
	return h, actor, token
}

func scimCaseGenerateClient(t *testing.T, transport string) {
	runSCIMGenerationAndProvision(t, transport, "client-token", "the id", Options{})
}

func scimCaseGeneratePlain(t *testing.T, transport string) {
	h, _, token := runSCIMGenerationAndProvision(t, transport, "plain-token", "plain-provider", Options{
		StoreSCIMToken: TokenStorage{Mode: TokenStoragePlain},
	})
	secret, _, _, err := decodeBearerToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if stored := recordString(h.storedProvider(t, "plain-provider"), "scimToken"); stored != secret {
		t.Fatalf("plain stored token=%q, want secret", stored)
	}
}

func scimCaseGenerateHashed(t *testing.T, transport string) {
	h, _, token := runSCIMGenerationAndProvision(t, transport, "hashed-token", "hashed-provider", Options{
		StoreSCIMToken: TokenStorage{Mode: TokenStorageHashed},
	})
	secret, _, _, err := decodeBearerToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if stored := recordString(h.storedProvider(t, "hashed-provider"), "scimToken"); stored != hashToken(secret) || stored == secret {
		t.Fatalf("hashed stored token=%q secret=%q", stored, secret)
	}
}

func scimCaseGenerateCustomHash(t *testing.T, transport string) {
	customHash := func(_ context.Context, value string) (string, error) { return value + "hello", nil }
	h, _, token := runSCIMGenerationAndProvision(t, transport, "custom-hash-token", "custom-hash-provider", Options{
		StoreSCIMToken: TokenStorage{Hash: customHash},
	})
	secret, _, _, err := decodeBearerToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if stored := recordString(h.storedProvider(t, "custom-hash-provider"), "scimToken"); stored != secret+"hello" {
		t.Fatalf("custom hash stored token=%q", stored)
	}
}

func scimCaseGenerateEncrypted(t *testing.T, transport string) {
	h, _, token := runSCIMGenerationAndProvision(t, transport, "encrypted-token", "encrypted-provider", Options{
		StoreSCIMToken: TokenStorage{Mode: TokenStorageEncrypted},
	})
	secret, _, _, err := decodeBearerToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if stored := recordString(h.storedProvider(t, "encrypted-provider"), "scimToken"); stored == "" || stored == secret {
		t.Fatalf("encrypted stored token=%q secret=%q", stored, secret)
	}
}

func scimCaseGenerateCustomEncryption(t *testing.T, transport string) {
	identity := func(_ context.Context, value string) (string, error) { return value, nil }
	runSCIMGenerationAndProvision(t, transport, "custom-encryption-token", "custom-encryption-provider", Options{
		StoreSCIMToken: TokenStorage{Encrypt: identity, Decrypt: identity},
	})
}

func scimCaseRejectsForgedToken(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SCIM: Options{
		StoreSCIMToken: TokenStorage{Mode: TokenStorageHashed},
	}})
	actor := h.signUp(t, "forged-token")
	status, body := h.generate(t, actor, "forged-provider", "")
	token := requireGeneratedToken(t, status, body)
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) < 2 || parts[0] == "" {
		t.Fatalf("generated token payload=%q", decoded)
	}
	last := parts[0][len(parts[0])-1]
	replacement := byte('x')
	if last == replacement {
		replacement = 'y'
	}
	parts[0] = parts[0][:len(parts[0])-1] + string(replacement)
	forged := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, ":")))
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+forged)
	status, _, body = h.exchange(t, http.MethodPost, "/scim/v2/Users", "", headers, map[string]any{"userName": "forged-user"})
	requireSCIMStatus(t, status, http.StatusUnauthorized, body)
}

func scimCaseGenerateOrganizationToken(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "org-token-owner")
	h.seedOrganization(t, "org-token", owner, "owner")
	status, body := h.generate(t, owner, "org-provider", "org-token")
	token := requireGeneratedToken(t, status, body)
	_, _, organizationID, err := decodeBearerToken(token)
	if err != nil || organizationID != "org-token" {
		t.Fatalf("organization token scope=%q err=%v", organizationID, err)
	}
}

func scimCaseBeforeTokenHook(t *testing.T, transport string) {
	setup := scimManagementSetup{SCIM: Options{BeforeSCIMTokenGenerated: func(_ context.Context, payload TokenGenerationPayload) error {
		if recordString(payload.Member, "role") == "owner" {
			return managementError(http.StatusForbidden, "FORBIDDEN", "You do not have enough privileges to generate a SCIM token")
		}
		return nil
	}}}
	h := newSCIMManagementHarness(t, transport, setup)
	owner := h.signUp(t, "before-hook-owner")
	h.seedOrganization(t, "before-hook-org", owner, "owner")
	status, body := h.generate(t, owner, "before-hook-provider", "before-hook-org")
	requireSCIMError(t, status, body, http.StatusForbidden, "You do not have enough privileges to generate a SCIM token")
}

func scimCaseAfterTokenHook(t *testing.T, transport string) {
	var called atomic.Bool
	setup := scimManagementSetup{SCIM: Options{
		StoreSCIMToken: TokenStorage{Mode: TokenStoragePlain},
		AfterSCIMTokenGenerated: func(_ context.Context, payload TokenGenerationPayload) error {
			if payload.SCIMProvider == nil || payload.SCIMProvider.SCIMToken == "" || payload.SCIMToken == "" {
				return fmt.Errorf("incomplete after-token payload: %#v", payload)
			}
			called.Store(true)
			return nil
		},
	}}
	h := newSCIMManagementHarness(t, transport, setup)
	actor := h.signUp(t, "after-hook")
	status, body := h.generate(t, actor, "after-hook-provider", "")
	requireGeneratedToken(t, status, body)
	if !called.Load() {
		t.Fatal("afterSCIMTokenGenerated was not called")
	}
}

func scimCaseDenyPersonalRegenerate(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SCIM: Options{ProviderOwnership: ProviderOwnership{Enabled: true}}})
	userA := h.signUp(t, "personal-owner-a")
	userB := h.signUp(t, "personal-owner-b")
	status, body := h.generate(t, userA, "user-a-owned-provider", "")
	requireGeneratedToken(t, status, body)
	status, body = h.generate(t, userB, "user-a-owned-provider", "")
	requireSCIMError(t, status, body, http.StatusForbidden, "You must be the owner to access this provider")
}

func scimCaseDenyOrganizationRegenerate(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	userA := h.signUp(t, "org-owner-a")
	userB := h.signUp(t, "org-owner-b")
	h.seedOrganization(t, "org-a", userA, "owner")
	h.seedOrganization(t, "org-b", userB, "owner")
	status, body := h.generate(t, userA, "other-org", "org-a")
	requireGeneratedToken(t, status, body)
	status, body = h.generate(t, userB, "other-org", "")
	requireSCIMError(t, status, body, http.StatusForbidden, "You must be a member of the organization to access this provider")
}

func scimCaseListEmpty(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "list-empty")
	status, _, body := h.exchange(t, http.MethodGet, "/scim/list-provider-connections", actor.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if providers := providerIDsFromResponse(t, body); len(providers) != 0 {
		t.Fatalf("provider list=%#v, want empty", providers)
	}
}

func scimCaseListOrganizationProviders(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	userA := h.signUp(t, "list-org-a")
	userB := h.signUp(t, "list-org-b")
	h.seedOrganization(t, "list-org-a", userA, "owner")
	h.seedOrganization(t, "list-org-b", userB, "owner")
	for _, providerID := range []string{"provider-1", "provider-2"} {
		status, body := h.generate(t, userA, providerID, "list-org-a")
		requireGeneratedToken(t, status, body)
	}
	status, body := h.generate(t, userB, "provider-3", "list-org-b")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", userA.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); !reflect.DeepEqual(got, []string{"provider-1", "provider-2"}) {
		t.Fatalf("organization provider list=%#v", got)
	}
	for _, providerID := range []string{"provider-1", "provider-2"} {
		provider := providerFromResponse(t, body, providerID)
		id, _ := provider["id"].(string)
		if id == "" || provider["organizationId"] != "list-org-a" {
			t.Fatalf("organization provider %q details=%#v", providerID, provider)
		}
	}
}

func scimCaseListOwnedPersonalProviders(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SCIM: Options{ProviderOwnership: ProviderOwnership{Enabled: true}}})
	userA := h.signUp(t, "list-personal-a")
	userB := h.signUp(t, "list-personal-b")
	status, body := h.generate(t, userA, "user-a-personal-provider", "")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", userA.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); !reflect.DeepEqual(got, []string{"user-a-personal-provider"}) {
		t.Fatalf("owner provider list=%#v", got)
	}
	if provider := providerFromResponse(t, body, "user-a-personal-provider"); provider["organizationId"] != nil {
		t.Fatalf("personal provider details=%#v, want null organizationId", provider)
	}
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", userB.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); len(got) != 0 {
		t.Fatalf("non-owner provider list=%#v", got)
	}
}

func scimCaseGetOrganizationProvider(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "get-org")
	h.seedOrganization(t, "get-org", owner, "owner")
	status, body := h.generate(t, owner, "my-provider", "get-org")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/get-provider-connection?providerId=my-provider", owner.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	id, _ := body["id"].(string)
	if id == "" || body["providerId"] != "my-provider" || body["organizationId"] != "get-org" {
		t.Fatalf("provider details=%#v", body)
	}
}

func scimCaseGetPersonalProvider(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "get-personal")
	status, body := h.generate(t, owner, "no-org-provider", "")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/get-provider-connection?providerId=no-org-provider", owner.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if body["providerId"] != "no-org-provider" || body["organizationId"] != nil {
		t.Fatalf("personal provider details=%#v", body)
	}
}

func scimCaseGetPersonalDenied(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SCIM: Options{ProviderOwnership: ProviderOwnership{Enabled: true}}})
	userA := h.signUp(t, "get-personal-owner")
	userB := h.signUp(t, "get-personal-other")
	status, body := h.generate(t, userA, "get-owned-provider", "")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/get-provider-connection?providerId=get-owned-provider", userB.Cookie, nil, nil)
	requireSCIMError(t, status, body, http.StatusForbidden, "You must be the owner to access this provider")
}

func scimCaseGetOtherOrganizationDenied(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	userA := h.signUp(t, "get-other-a")
	userB := h.signUp(t, "get-other-b")
	h.seedOrganization(t, "get-other-org-a", userA, "owner")
	h.seedOrganization(t, "get-other-org-b", userB, "owner")
	status, body := h.generate(t, userA, "get-other-provider", "get-other-org-a")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/get-provider-connection?providerId=get-other-provider", userB.Cookie, nil, nil)
	requireSCIMError(t, status, body, http.StatusForbidden, "You must be a member of the organization to access this provider")
}

func scimCaseGetRemovedOwnerDenied(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	userA := h.signUp(t, "removed-owner-a")
	userB := h.signUp(t, "removed-owner-b")
	h.seedOrganization(t, "removed-owner-org", userA, "owner")
	h.seedMember(t, "removed-owner-org", userB.ID, "owner")
	status, body := h.generate(t, userA, "removed-owner-provider", "removed-owner-org")
	requireGeneratedToken(t, status, body)
	if err := h.adapter.Delete(t.Context(), storage.DeleteParams{Model: "member", Where: []storage.Where{
		{Field: "organizationId", Value: "removed-owner-org"}, {Field: "userId", Value: userA.ID},
	}}); err != nil {
		t.Fatal(err)
	}
	status, _, body = h.exchange(t, http.MethodGet, "/scim/get-provider-connection?providerId=removed-owner-provider", userA.Cookie, nil, nil)
	requireSCIMError(t, status, body, http.StatusForbidden, "You must be a member of the organization to access this provider")
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", userA.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); len(got) != 0 {
		t.Fatalf("removed owner list=%#v", got)
	}
}

func scimCaseGetUnknown(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "get-unknown")
	status, _, body := h.exchange(t, http.MethodGet, "/scim/get-provider-connection?providerId=unknown", actor.Cookie, nil, nil)
	requireSCIMError(t, status, body, http.StatusNotFound, "SCIM provider not found")
}

func scimCaseDeleteOrganizationProvider(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "delete-org")
	h.seedOrganization(t, "delete-org", owner, "owner")
	status, body := h.generate(t, owner, "delete-provider", "delete-org")
	token := requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", owner.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); !reflect.DeepEqual(got, []string{"delete-provider"}) {
		t.Fatalf("list before delete=%#v", got)
	}
	status, _, body = h.exchange(t, http.MethodPost, "/scim/delete-provider-connection", owner.Cookie, nil, map[string]any{"providerId": "delete-provider"})
	requireSCIMStatus(t, status, http.StatusOK, body)
	if body["success"] != true {
		t.Fatalf("delete response=%#v", body)
	}
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", owner.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); len(got) != 0 {
		t.Fatalf("list after delete=%#v", got)
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	status, _, body = h.exchange(t, http.MethodPost, "/scim/v2/Users", "", headers, map[string]any{"userName": "deleted-token-user"})
	requireSCIMStatus(t, status, http.StatusUnauthorized, body)
}

func scimCaseDeleteOtherOrganizationDenied(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	userA := h.signUp(t, "delete-other-a")
	userB := h.signUp(t, "delete-other-b")
	h.seedOrganization(t, "delete-other-org-a", userA, "owner")
	h.seedOrganization(t, "delete-other-org-b", userB, "owner")
	status, body := h.generate(t, userA, "delete-other-provider", "delete-other-org-a")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodPost, "/scim/delete-provider-connection", userB.Cookie, nil, map[string]any{"providerId": "delete-other-provider"})
	requireSCIMError(t, status, body, http.StatusForbidden, "You must be a member of the organization to access this provider")
}

func scimCaseDeleteUnknown(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	actor := h.signUp(t, "delete-unknown")
	status, _, body := h.exchange(t, http.MethodPost, "/scim/delete-provider-connection", actor.Cookie, nil, map[string]any{"providerId": "unknown"})
	requireSCIMError(t, status, body, http.StatusNotFound, "SCIM provider not found")
}

func scimCaseDeletePersonalDenied(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SCIM: Options{ProviderOwnership: ProviderOwnership{Enabled: true}}})
	userA := h.signUp(t, "delete-personal-a")
	userB := h.signUp(t, "delete-personal-b")
	status, body := h.generate(t, userA, "delete-personal-provider", "")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodPost, "/scim/delete-provider-connection", userB.Cookie, nil, map[string]any{"providerId": "delete-personal-provider"})
	requireSCIMError(t, status, body, http.StatusForbidden, "You must be the owner to access this provider")
}

func scimCaseRoleMemberDenied(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "role-member-owner")
	member := h.signUp(t, "role-member-user")
	h.seedOrganization(t, "role-member-org", owner, "owner")
	h.seedMember(t, "role-member-org", member.ID, "member")
	status, body := h.generate(t, member, "member-attempt", "role-member-org")
	requireSCIMError(t, status, body, http.StatusForbidden, "Insufficient role for this operation")
}

func scimCaseRoleAdminAllowed(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "role-admin-owner")
	admin := h.signUp(t, "role-admin-user")
	h.seedOrganization(t, "role-admin-org", owner, "owner")
	h.seedMember(t, "role-admin-org", admin.ID, "admin")
	status, body := h.generate(t, admin, "admin-attempt", "role-admin-org")
	requireGeneratedToken(t, status, body)
}

func scimCaseMultipleRolesAllowed(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "multi-role-owner")
	member := h.signUp(t, "multi-role-user")
	h.seedOrganization(t, "multi-role-org", owner, "owner")
	h.seedMember(t, "multi-role-org", member.ID, "member,admin")
	status, body := h.generate(t, member, "multi-role-provider", "multi-role-org")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", member.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); !reflect.DeepEqual(got, []string{"multi-role-provider"}) {
		t.Fatalf("multi-role list=%#v", got)
	}
	status, _, body = h.exchange(t, http.MethodGet, "/scim/get-provider-connection?providerId=multi-role-provider", member.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if body["providerId"] != "multi-role-provider" || body["organizationId"] != "multi-role-org" {
		t.Fatalf("multi-role provider=%#v", body)
	}
}

func scimCaseCustomRequiredRole(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{SCIM: Options{RequiredRoles: []string{"owner"}}})
	owner := h.signUp(t, "custom-role-owner")
	admin := h.signUp(t, "custom-role-admin")
	h.seedOrganization(t, "custom-role-org", owner, "owner")
	h.seedMember(t, "custom-role-org", admin.ID, "admin")
	status, body := h.generate(t, admin, "custom-role-attempt", "custom-role-org")
	requireSCIMError(t, status, body, http.StatusForbidden, "Insufficient role for this operation")
	status, body = h.generate(t, owner, "custom-role-attempt", "custom-role-org")
	requireGeneratedToken(t, status, body)
}

func scimCaseCustomCreatorRole(t *testing.T, transport string) {
	setup := scimManagementSetup{Organization: organization.Options{CreatorRole: "super-admin"}}
	h := newSCIMManagementHarness(t, transport, setup)
	creator := h.signUp(t, "custom-creator")
	h.seedOrganization(t, "custom-creator-org", creator, "super-admin")
	status, body := h.generate(t, creator, "custom-creator-provider", "custom-creator-org")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", creator.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); !reflect.DeepEqual(got, []string{"custom-creator-provider"}) {
		t.Fatalf("custom creator provider list=%#v", got)
	}
}

func scimCaseListRoleFilter(t *testing.T, transport string) {
	h := newSCIMManagementHarness(t, transport, scimManagementSetup{})
	owner := h.signUp(t, "list-role-owner")
	member := h.signUp(t, "list-role-member")
	h.seedOrganization(t, "list-role-org", owner, "owner")
	h.seedMember(t, "list-role-org", member.ID, "member")
	status, body := h.generate(t, owner, "list-role-provider", "list-role-org")
	requireGeneratedToken(t, status, body)
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", owner.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); !reflect.DeepEqual(got, []string{"list-role-provider"}) {
		t.Fatalf("owner role-filter list=%#v", got)
	}
	status, _, body = h.exchange(t, http.MethodGet, "/scim/list-provider-connections", member.Cookie, nil, nil)
	requireSCIMStatus(t, status, http.StatusOK, body)
	if got := providerIDsFromResponse(t, body); len(got) != 0 {
		t.Fatalf("member role-filter list=%#v", got)
	}
}
