package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

type testPluginFactory struct {
	id     string
	schema storage.Schema
	build  func(PluginHost) (engine.Plugin, error)
}

func (factory *testPluginFactory) PluginID() string { return factory.id }

func (factory *testPluginFactory) Schema() (storage.Schema, error) { return factory.schema, nil }

func (factory *testPluginFactory) Build(host PluginHost) (engine.Plugin, error) {
	if factory.build == nil {
		return engine.Plugin{ID: factory.id}, nil
	}
	return factory.build(host)
}

func TestPluginFactoryPreviewsSchemaBindsHostAndRateRules(t *testing.T) {
	enabled := true
	origins := []string{"https://trusted.example"}
	factorySchema := storage.Schema{Models: map[string]storage.ModelSchema{
		"factoryAudit": {
			ModelName: "factory_audit",
			Fields: map[string]storage.FieldAttribute{
				"value": {Type: storage.FieldString},
			},
		},
	}}
	factory := &testPluginFactory{id: "factory-probe", schema: factorySchema}
	factory.build = func(host PluginHost) (engine.Plugin, error) {
		if host.Adapter == nil || !host.InternalAdapter.valid() || host.Logger == nil || host.Clock == nil || host.Random == nil ||
			host.AdapterForContext == nil || host.EncryptSecret == nil || host.DecryptSecret == nil ||
			host.ResolveBaseURL == nil || host.ListEndpoints == nil || host.TrustedOrigins == nil || host.IsTrustedOrigin == nil || host.ResolveIPAddress == nil || host.SessionCookie == nil || host.Cookie == nil ||
			host.HasPlugin == nil || host.SocialProvider == nil || host.RegisterSocialProvider == nil ||
			host.CreateOAuthState == nil || host.HandleOAuthUser == nil || host.LinkOAuthAccount == nil ||
			host.ResolveSession == nil || host.GetSession == nil || host.FindSession == nil || host.FindSessions == nil ||
			host.CreateSession == nil || host.IssueSession == nil || host.RefreshSession == nil || host.ExpireSessionCookies == nil || host.DeleteSession == nil || host.DeleteSessions == nil ||
			host.RevokeSessions == nil || host.RevokeUnproven == nil || host.CreateUser == nil ||
			host.NewSession == nil || host.SetNewSession == nil ||
			host.ParseUserInput == nil || host.SerializeUser == nil || host.SerializeSession == nil ||
			host.RunBackground == nil || host.ValidateCSRF == nil || host.ValidateFormCSRF == nil || host.ValidateRedirect == nil ||
			host.HashPassword == nil || host.WrapPasswordHash == nil ||
			host.BeforeEmailVerification == nil || host.AfterEmailVerification == nil ||
			host.OnPasswordReset == nil ||
			host.CreateVerification == nil || host.FindVerification == nil || host.PeekVerification == nil ||
			host.ConsumeVerification == nil || host.UpdateVerification == nil ||
			host.DeleteVerification == nil ||
			host.InstallDefaultEmailVerification == nil {
			// Keep the dependency check readable while still requiring plugin-init
			// database-hook registration to be present.
			return engine.Plugin{}, errors.New("incomplete plugin host")
		}
		if host.RegisterDatabaseHooks == nil {
			return engine.Plugin{}, errors.New("incomplete plugin host")
		}
		if _, exists := host.Options.Schema.Models["factoryAudit"]; !exists {
			return engine.Plugin{}, errors.New("factory schema was not installed before Build")
		}
		if _, err := host.Adapter.Create(context.Background(), storage.CreateParams{
			Model: "factoryAudit", Data: storage.Record{"value": "built"},
		}); err != nil {
			return engine.Plugin{}, err
		}

		// Build receives an independent snapshot. Mutating it must not mutate the
		// runtime or the caller's input.
		host.Options.TrustedOrigins[0] = "https://mutated.example"
		delete(host.Options.Schema.Models, "factoryAudit")

		return engine.Plugin{
			ID: "", // New fills the deterministic factory ID.
			Endpoints: []engine.Endpoint{{
				Name: "factoryProbe", Path: "/factory-probe", Methods: []string{http.MethodGet},
				Handler: func(*engine.Context) (contract.Response, error) {
					return jsonResponse(contract.StatusOK, map[string]any{"factory": true})
				},
			}},
			RateLimit: []ratelimit.MatcherRule{{
				Match: func(path string) bool { return path == "/factory-probe" },
				Rule:  ratelimit.Rule{Window: 60, Max: 1},
			}},
		}, nil
	}

	input := Options{
		TrustedOrigins:  origins,
		RateLimit:       RateLimitOptions{Enabled: &enabled},
		Plugins:         []engine.Plugin{{ID: "static-probe"}},
		PluginFactories: []PluginFactory{factory},
	}
	auth, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	if origins[0] != "https://trusted.example" || auth.Options().TrustedOrigins[0] != origins[0] {
		t.Fatalf("plugin mutated trusted origins: input=%q runtime=%q", origins[0], auth.Options().TrustedOrigins[0])
	}
	if _, exists := auth.Options().Schema.Models["factoryAudit"]; !exists {
		t.Fatal("factory schema missing from final options")
	}
	plugins := auth.Options().Plugins
	if len(plugins) != 2 || plugins[0].ID != "static-probe" || plugins[1].ID != "factory-probe" {
		t.Fatalf("plugin order = %#v", plugins)
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "factoryAudit"})
	if err != nil || len(rows) != 1 || rows[0]["value"] != "built" {
		t.Fatalf("factory rows = %#v, %v", rows, err)
	}

	// Mutating the schema retained by the caller after New cannot change the
	// installed runtime schema.
	field := factory.schema.Models["factoryAudit"]
	field.Fields["value"] = storage.FieldAttribute{Type: storage.FieldBoolean}
	factory.schema.Models["factoryAudit"] = field
	if got := auth.Options().Schema.Models["factoryAudit"].Fields["value"].Type; got != storage.FieldString {
		t.Fatalf("runtime schema changed through factory alias: %q", got)
	}

	request := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://auth.test/api/auth/factory-probe", nil))
		return recorder
	}
	if first := request(); first.Code != contract.StatusOK {
		t.Fatalf("first factory request = %d %s", first.Code, first.Body.String())
	}
	if second := request(); second.Code != contract.StatusTooManyRequests {
		t.Fatalf("factory rate rule status = %d %s", second.Code, second.Body.String())
	}
}

func TestPluginHostPeekVerificationPreservesExpiredRowsForPurposeAwarePlugins(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	var host PluginHost
	factory := &testPluginFactory{id: "verification-peek"}
	factory.build = func(input PluginHost) (engine.Plugin, error) {
		host = input
		return engine.Plugin{ID: "verification-peek"}, nil
	}
	auth, err := New(Options{Clock: func() time.Time { return now }, PluginFactories: []PluginFactory{factory}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.CreateVerification(t.Context(), "expired-purpose", "value", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	peeked, err := host.PeekVerification(t.Context(), "expired-purpose")
	if err != nil || peeked == nil || peeked["value"] != "value" {
		t.Fatalf("peek expired row=%#v err=%v", peeked, err)
	}
	found, err := host.FindVerification(t.Context(), "expired-purpose")
	if err != nil || found == nil || found["value"] != "value" {
		t.Fatalf("find must return the row selected before cleanup: row=%#v err=%v", found, err)
	}
	foundAgain, err := host.FindVerification(t.Context(), "expired-purpose")
	if err != nil || foundAgain != nil {
		t.Fatalf("second find must observe cleanup: row=%#v err=%v", foundAgain, err)
	}
	count, err := auth.Adapter().Count(t.Context(), storage.CountParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "expired-purpose"}},
	})
	if err != nil || count != 0 {
		t.Fatalf("expired database rows after Find=%d err=%v", count, err)
	}
}

func TestPluginHostValidateFormCSRFForcesCookielessOriginChecks(t *testing.T) {
	factory := &testPluginFactory{id: "form-csrf"}
	factory.build = func(host PluginHost) (engine.Plugin, error) {
		return engine.Plugin{ID: "form-csrf", Endpoints: []engine.Endpoint{{
			Name: "formCSRFProbe", Path: "/form-csrf-probe", Methods: []string{http.MethodPost},
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				if err := host.ValidateFormCSRF(ctx); err != nil {
					return contract.Response{}, err
				}
				return contract.JSONResponse(contract.StatusOK, map[string]any{"ok": true})
			},
		}}}, nil
	}
	auth, err := New(Options{
		BaseURL: "http://localhost:3000", TrustedOrigins: []string{"http://localhost:3000"},
		PluginFactories: []PluginFactory{factory},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		input := httptest.NewRequest(http.MethodPost, "http://localhost:3000/api/auth/form-csrf-probe", strings.NewReader(`{}`))
		input.Header.Set("Content-Type", "application/json")
		for name, value := range headers {
			input.Header.Set(name, value)
		}
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, input)
		return recorder
	}
	if response := request(map[string]string{"Origin": "https://evil.example"}); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request(map[string]string{
		"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
	}); response.Code != http.StatusForbidden {
		t.Fatalf("cross-site navigation status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request(nil); response.Code != http.StatusOK {
		t.Fatalf("server-to-server status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPluginHostCreateSessionDoesNotWriteCookiesWhileIssueSessionDoes(t *testing.T) {
	secondary := newSecondaryMemory()
	var userID string
	factory := &testPluginFactory{id: "session-factory"}
	factory.build = func(host PluginHost) (engine.Plugin, error) {
		endpoint := func(name, path string, create func(*engine.Context, string, bool) (*PluginSessionState, error)) engine.Endpoint {
			return engine.Endpoint{
				Name: name, Path: path, Methods: []string{http.MethodPost},
				Handler: func(ctx *engine.Context) (contract.Response, error) {
					state, err := create(ctx, userID, false)
					if err != nil {
						return contract.Response{}, err
					}
					token, _ := recordString(state.Session, "token")
					return jsonResponse(contract.StatusOK, map[string]any{"token": token})
				},
			}
		}
		return engine.Plugin{ID: "session-factory", Endpoints: []engine.Endpoint{
			endpoint("createSessionWithoutCookie", "/create-session-without-cookie", host.CreateSession),
			endpoint("issueSessionWithCookie", "/issue-session-with-cookie", host.IssueSession),
		}}, nil
	}
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		SecondaryStorage: secondary,
		PluginFactories:  []PluginFactory{factory},
	})
	user, err := auth.Adapter().Create(t.Context(), storage.CreateParams{Data: storage.Record{
		"name": "Protocol User", "email": "protocol-session@example.test", "emailVerified": true,
	}, Model: "user"})
	if err != nil {
		t.Fatal(err)
	}
	userID, _ = recordString(user, "id")
	if userID == "" {
		t.Fatalf("created user = %#v", user)
	}

	created, err := auth.Invoke("createSessionWithoutCookie", engine.DirectInput{})
	if err != nil {
		t.Fatal(err)
	}
	if values := created.Headers().Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("CreateSession Set-Cookie = %#v", values)
	}
	var createdBody map[string]any
	if err := json.Unmarshal(created.Body(), &createdBody); err != nil {
		t.Fatal(err)
	}
	createdToken, _ := createdBody["token"].(string)
	if createdToken == "" || secondary.value(createdToken) == "" {
		t.Fatalf("CreateSession token=%q secondary=%q", createdToken, secondary.value(createdToken))
	}

	issued, err := auth.Invoke("issueSessionWithCookie", engine.DirectInput{})
	if err != nil {
		t.Fatal(err)
	}
	cookies := strings.Join(issued.Headers().Values("Set-Cookie"), ";")
	if !strings.Contains(cookies, "single-auth.session_token=") {
		t.Fatalf("IssueSession Set-Cookie = %q", cookies)
	}
	var issuedBody map[string]any
	if err := json.Unmarshal(issued.Body(), &issuedBody); err != nil {
		t.Fatal(err)
	}
	issuedToken, _ := issuedBody["token"].(string)
	if issuedToken == "" || secondary.value(issuedToken) == "" {
		t.Fatalf("IssueSession token=%q secondary=%q", issuedToken, secondary.value(issuedToken))
	}
}

func TestPluginFactoryInitializationCanUpdateFollowingOptions(t *testing.T) {
	var delivered string
	installer := &testPluginFactory{id: "installer"}
	installer.build = func(host PluginHost) (engine.Plugin, error) {
		err := host.InstallDefaultEmailVerification(func(_ context.Context, email string) error {
			delivered = email
			return nil
		})
		return engine.Plugin{ID: "installer"}, err
	}
	observer := &testPluginFactory{id: "observer"}
	observer.build = func(host PluginHost) (engine.Plugin, error) {
		if host.Options.EmailVerification.SendVerificationEmail == nil {
			return engine.Plugin{}, errors.New("prior initialization update is not visible")
		}
		return engine.Plugin{ID: "observer"}, nil
	}

	auth, err := New(Options{PluginFactories: []PluginFactory{installer, observer}})
	if err != nil {
		t.Fatal(err)
	}
	sender := auth.Options().EmailVerification.SendVerificationEmail
	if sender == nil {
		t.Fatal("installed verification sender missing from final options")
	}
	if err := sender(t.Context(), EmailVerificationMessage{User: modelUserForFactory("factory@example.com")}); err != nil {
		t.Fatal(err)
	}
	if delivered != "factory@example.com" {
		t.Fatalf("delivered email = %q", delivered)
	}
}

func modelUserForFactory(email string) model.User {
	return model.User{Email: email}
}

func TestPluginFactoryValidationErrors(t *testing.T) {
	var typedNil *testPluginFactory
	buildFailure := errors.New("build failed")
	tests := []struct {
		name    string
		factory PluginFactory
		want    string
	}{
		{name: "nil", factory: nil, want: "must not be nil"},
		{name: "typed nil", factory: typedNil, want: "must not be nil"},
		{name: "empty id", factory: &testPluginFactory{}, want: "ID must not be empty"},
		{
			name: "invalid schema",
			factory: &testPluginFactory{id: "invalid-schema", schema: storage.Schema{Models: map[string]storage.ModelSchema{
				"invalid": {Fields: map[string]storage.FieldAttribute{"field": {Type: "invalid"}}},
			}}},
			want: "plugin factory schema at index 0",
		},
		{
			name: "build failure",
			factory: &testPluginFactory{id: "broken", build: func(PluginHost) (engine.Plugin, error) {
				return engine.Plugin{}, buildFailure
			}},
			want: "initialize plugin broken: build failed",
		},
		{
			name: "mismatched id",
			factory: &testPluginFactory{id: "declared", build: func(PluginHost) (engine.Plugin, error) {
				return engine.Plugin{ID: "different"}, nil
			}},
			want: "built mismatched plugin different",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Options{PluginFactories: []PluginFactory{test.factory}})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
