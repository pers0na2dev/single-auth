package organization_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

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

type authorizationOrgRoleObservation struct {
	Result map[string]bool
}

type authorizationHarness struct {
	auth           *singleauth.Auth
	organizationID string
	memberCookie   string
}

func TestRequireOrgRoleAllowsAnyMatchingMemberRole(t *testing.T) {
	want := authorizationOrgRoleObservation{Result: map[string]bool{"ok": true}}
	t.Run("requireOrgRole::allows members whose multi-role membership includes an allowed role", func(t *testing.T) {
		for _, mode := range []string{"direct", "net-http", "fasthttp", "fiber"} {
			mode := mode
			t.Run(mode, func(t *testing.T) {
				harness := newAuthorizationHarness(t)
				actual := harness.call(t, mode)
				if !reflect.DeepEqual(actual, want) {
					t.Fatalf("requireOrgRole observation=%#v, want %#v", actual, want)
				}
			})
		}
	})
}

func newAuthorizationHarness(t *testing.T) *authorizationHarness {
	t.Helper()
	plugin := organization.MustNew(organization.Options{})
	middleware, err := plugin.RequireOrgRole(organization.RequireOrgRoleOptions{
		OrgIDParam: "organizationId", OrgIDSource: organization.OrgIDSourceQuery,
		AllowedRoles: []string{"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := engine.Endpoint{
		Name: "checkOrgAdmin", Path: "/test-check-org-admin",
		Methods: []string{http.MethodGet},
		Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware, middleware},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			session, sessionOK := singleauth.SessionFromEndpointContext(ctx)
			member, ok := organization.VerifiedMemberFromContext(ctx)
			if !sessionOK || session == nil || session.User == nil || !ok || member["role"] != "member,admin" || member["userId"] != session.User["id"] {
				return contract.Response{}, contract.NewAPIError(
					contract.StatusInternalServerError,
					"VERIFIED_MEMBER_MISSING",
					"Verified member missing",
				)
			}
			return contract.JSONResponse(contract.StatusOK, map[string]bool{"ok": true})
		},
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		PluginFactories: []singleauth.PluginFactory{plugin},
		Endpoints:       []engine.Endpoint{endpoint},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Org Owner", Email: "org-owner@test.com", Password: "password123",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Multi Role Member", Email: "multi-role-member@test.com", Password: "password123",
	}); err != nil {
		t.Fatal(err)
	}
	ownerSignIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
		Email: "org-owner@test.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	memberSignIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
		Email: "multi-role-member@test.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerCookie := cookies.ApplySetCookies("", ownerSignIn.Headers.Values("Set-Cookie"))
	memberCookie := cookies.ApplySetCookies("", memberSignIn.Headers.Values("Set-Cookie"))
	if ownerCookie == "" {
		t.Fatal("owner sign-in did not bind a session cookie")
	}
	if memberCookie == "" {
		t.Fatal("member sign-in did not bind a session cookie")
	}
	ownerHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: ownerCookie})
	memberHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: memberCookie})
	memberSession, err := auth.API().GetSession(t.Context(), singleauth.GetSessionInput{Headers: memberHeaders})
	if err != nil || memberSession == nil || memberSession.User.ID == "" {
		t.Fatalf("member getSession=%#v err=%v", memberSession, err)
	}
	created, err := auth.API().Call(t.Context(), "createOrganization", singleauth.DirectCallInput{
		Method: http.MethodPost, Headers: ownerHeaders,
		Body: map[string]any{"name": "Test Organization", "slug": "test-organization"},
	})
	if err != nil {
		t.Fatal(err)
	}
	createdObject, ok := created.Value.(map[string]any)
	if !ok {
		t.Fatalf("createOrganization value=%#v", created.Value)
	}
	organizationID, _ := createdObject["id"].(string)
	if organizationID == "" {
		t.Fatalf("createOrganization value=%#v", created.Value)
	}
	added, err := auth.API().Call(t.Context(), "addMember", singleauth.DirectCallInput{
		Method: http.MethodPost, Headers: ownerHeaders,
		Body: map[string]any{
			"organizationId": organizationID,
			"userId":         memberSession.User.ID,
			"role":           []string{"member", "admin"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	addedObject, ok := added.Value.(map[string]any)
	if !ok || addedObject["role"] != "member,admin" {
		t.Fatalf("addMember value=%#v", added.Value)
	}
	persisted, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "member",
		Where: []storage.Where{
			{Field: "userId", Value: memberSession.User.ID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil || persisted == nil || persisted["role"] != "member,admin" {
		t.Fatalf("persisted member=%#v err=%v", persisted, err)
	}
	return &authorizationHarness{
		auth: auth, organizationID: organizationID, memberCookie: memberCookie,
	}
}

func TestRequireOrgRoleSessionPrecedesOrganizationAndParameterChecks(t *testing.T) {
	harness := newAuthorizationHarness(t)
	request := httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/test-check-org-admin", nil)
	recorder := httptest.NewRecorder()
	harness.auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), `"code":"UNAUTHORIZED"`) {
		t.Fatalf("unauthenticated status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/test-check-org-admin", nil)
	request.Header.Set("Cookie", harness.memberCookie)
	recorder = httptest.NewRecorder()
	harness.auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "Missing required parameter: organizationId") {
		t.Fatalf("missing organization status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRequireOrgRoleSessionPrecedesOrganizationPluginCheck(t *testing.T) {
	plugin := organization.MustNew(organization.Options{})
	middleware, err := plugin.RequireOrgRole(organization.RequireOrgRoleOptions{
		OrgIDParam: "organizationId", OrgIDSource: organization.OrgIDSourceQuery,
		AllowedRoles: []string{"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		Endpoints: []engine.Endpoint{{
			Name: "checkOrgAdmin", Path: "/test-check-org-admin", Methods: []string{http.MethodGet},
			Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware, middleware},
			Handler: func(*engine.Context) (contract.Response, error) {
				return contract.JSONResponse(contract.StatusOK, map[string]bool{"ok": true})
			},
		}},
	})
	requestURL := "http://auth.example.test/api/auth/test-check-org-admin?organizationId=missing"
	request := httptest.NewRequest(http.MethodGet, requestURL, nil)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated missing-plugin status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	if _, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "No Org Plugin", Email: "no-org-plugin@example.com", Password: "password123",
	}); err != nil {
		t.Fatal(err)
	}
	signedIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
		Email: "no-org-plugin@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookies.ApplySetCookies("", signedIn.Headers.Values("Set-Cookie"))
	request = httptest.NewRequest(http.MethodGet, requestURL, nil)
	request.Header.Set("Cookie", cookie)
	recorder = httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "Organization plugin is required for org role authorization") {
		t.Fatalf("authenticated missing-plugin status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func (harness *authorizationHarness) call(t *testing.T, mode string) authorizationOrgRoleObservation {
	t.Helper()
	requestURL := "http://auth.example.test/api/auth/test-check-org-admin?organizationId=" + url.QueryEscape(harness.organizationID)
	decode := func(status int, body []byte) authorizationOrgRoleObservation {
		t.Helper()
		if status != http.StatusOK {
			t.Fatalf("checkOrgAdmin status=%d body=%s", status, body)
		}
		var result map[string]bool
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return authorizationOrgRoleObservation{Result: result}
	}

	switch mode {
	case "direct":
		result, err := harness.auth.API().Call(t.Context(), "checkOrgAdmin", singleauth.DirectCallInput{
			Method:  http.MethodGet,
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: harness.memberCookie}),
			Query:   url.Values{"organizationId": {harness.organizationID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(result.Value)
		if err != nil {
			t.Fatal(err)
		}
		return decode(result.Response.Status(), body)

	case "net-http":
		request := httptest.NewRequest(http.MethodGet, requestURL, nil)
		request.Header.Set("Cookie", harness.memberCookie)
		recorder := httptest.NewRecorder()
		harness.auth.ServeHTTP(recorder, request)
		return decode(recorder.Code, recorder.Body.Bytes())

	case "fasthttp":
		handler := fasthttptransport.NewHandler(harness.auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.Header.Set("Cookie", harness.memberCookie)
		request.SetRequestURI(requestURL)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		return decode(requestContext.Response.StatusCode(), requestContext.Response.Body())

	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(harness.auth.Dispatcher()))
		request, err := http.NewRequest(http.MethodGet, requestURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Cookie", harness.memberCookie)
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return decode(response.StatusCode, body)

	default:
		t.Fatalf("unsupported mode %q", mode)
		return authorizationOrgRoleObservation{}
	}
}
