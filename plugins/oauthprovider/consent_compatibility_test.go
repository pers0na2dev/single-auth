package oauthprovider

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"

	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type consentCase struct {
	Title       string
	Observation consentObservation
}

type consentObservation struct {
	Status                    int      `json:"status,omitempty"`
	Scopes                    []string `json:"scopes,omitempty"`
	IdentityPreserved         bool     `json:"identityPreserved,omitempty"`
	CreatedAtPreserved        bool     `json:"createdAtPreserved,omitempty"`
	UpdatedAtIsWholeSecond    bool     `json:"updatedAtIsWholeSecond,omitempty"`
	FirstClientMatches        bool     `json:"firstClientMatches,omitempty"`
	FirstUserMatches          bool     `json:"firstUserMatches,omitempty"`
	FirstScopes               []string `json:"firstScopes,omitempty"`
	SecondClientMatches       bool     `json:"secondClientMatches,omitempty"`
	SecondUserMatches         bool     `json:"secondUserMatches,omitempty"`
	SecondScopes              []string `json:"secondScopes,omitempty"`
	TimestampsAreWholeSeconds bool     `json:"timestampsAreWholeSeconds,omitempty"`
	DataIsNull                bool     `json:"dataIsNull,omitempty"`
	Removed                   bool     `json:"removed,omitempty"`
	MatchesCreatedConsent     bool     `json:"matchesCreatedConsent,omitempty"`
	Count                     int      `json:"count,omitempty"`
	OrderMatches              bool     `json:"orderMatches,omitempty"`
}

type consentExchange func(
	name, method, target, userID string,
	body []byte,
) (int, []byte, error)

type consentHarness struct {
	service  *ConsentService
	exchange consentExchange
	now      time.Time
	userID   string
	client1  string
	client2  string
}

func TestOAuthProviderConsentHTTP(t *testing.T) {
	if len(harnessObservationTitles()) != len(consentCases) {
		t.Fatalf("consent harness titles = %d, want %d", len(harnessObservationTitles()), len(consentCases))
	}
	for _, title := range harnessObservationTitles() {
		found := false
		for _, candidate := range consentCases {
			if candidate.Title == title {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unexpected consent harness title %q", title)
		}
	}
	for _, vector := range consentCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber", "direct"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					harness := newConsentHarness(t, transportName)
					actual := harness.run(t)
					observed, exists := actual[vector.Title]
					if !exists {
						t.Fatalf("consent observation missing for %q", vector.Title)
					}
					if !reflect.DeepEqual(observed, vector.Observation) {
						t.Fatalf("consent observation = %#v, want %#v", observed, vector.Observation)
					}
				})
			}
		})
	}
}

func harnessObservationTitles() []string {
	return []string{
		"should create a tester consents",
		"should get a specific consent",
		"should get user's consents",
		"should not allow updates to scopes not granted to client",
		"should allow scopes change to client",
		"should reject updates to a consent owned by another user",
		"should delete the consent",
	}
}

func newConsentHarness(t *testing.T, transportName string) *consentHarness {
	t.Helper()
	now := time.Date(2028, time.January, 2, 3, 4, 5, 987000000, time.UTC)
	schema, err := storage.CoreSchema().Merge(OAuthProviderSchema())
	if err != nil {
		t.Fatal(err)
	}
	adapter := memory.MustNew(
		memory.WithSchema(schema),
		memory.WithClock(func() time.Time { return now }),
	)
	const userID = "consent-user"
	for _, user := range []storage.Record{
		{"id": userID, "name": "Consent User", "email": "consent@test.com", "emailVerified": true},
		{"id": "other-consent-user", "name": "Other Consent Owner", "email": "other-consent-owner@test.com", "emailVerified": false},
	} {
		if _, err := adapter.Create(t.Context(), storage.CreateParams{
			Model: "user", Data: user, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, client := range []storage.Record{
		{
			"clientId": "consent-client-default", "clientSecret": "secret-1",
			"redirectUris": []string{"http://localhost:5000/api/auth/oauth2/callback/test"},
			"userId":       userID,
		},
		{
			"clientId": "consent-client-restricted", "clientSecret": "secret-2",
			"redirectUris": []string{"http://localhost:5000/api/auth/oauth2/callback/test"},
			"scopes":       []string{"openid", "profile"}, "userId": userID,
		},
	} {
		if _, err := adapter.Create(t.Context(), storage.CreateParams{
			Model: "oauthClient", Data: client,
		}); err != nil {
			t.Fatal(err)
		}
	}
	service, err := NewConsentService(ConsentOptions{Runtime: ConsentRuntime{
		Adapter: adapter,
		Clock:   func() time.Time { return now },
		ResolveSession: func(ctx *engine.Context) (*ConsentSession, error) {
			user, _ := ctx.Request().Headers().Get("X-Consent-User")
			if user == "" {
				return nil, consentUnauthorized()
			}
			return &ConsentSession{User: storage.Record{"id": user}}, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry(nil, service.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return &consentHarness{
		service:  service,
		exchange: newConsentExchange(t, transportName, dispatcher), now: now,
		userID: userID, client1: "consent-client-default", client2: "consent-client-restricted",
	}
}

func (harness *consentHarness) run(t *testing.T) map[string]consentObservation {
	t.Helper()
	firstScopes := []string{"profile"}
	secondScopes := []string{"openid", "profile"}
	consent1, err := harness.service.CreateConsent(t.Context(), CreateConsentInput{
		ClientID: harness.client1, UserID: harness.userID, Scopes: firstScopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	consent2, err := harness.service.CreateConsent(t.Context(), CreateConsentInput{
		ClientID: harness.client2, UserID: harness.userID, Scopes: secondScopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]consentObservation{
		"should create a tester consents": {
			FirstClientMatches:        consentRecordString(consent1, "clientId") == harness.client1,
			FirstUserMatches:          consentRecordString(consent1, "userId") == harness.userID,
			FirstScopes:               consentTestStrings(consent1["scopes"]),
			SecondClientMatches:       consentRecordString(consent2, "clientId") == harness.client2,
			SecondUserMatches:         consentRecordString(consent2, "userId") == harness.userID,
			SecondScopes:              consentTestStrings(consent2["scopes"]),
			TimestampsAreWholeSeconds: consentRecordWholeSeconds(consent1) && consentRecordWholeSeconds(consent2),
		},
	}

	consent1ID := consentRecordString(consent1, "id")
	consent2ID := consentRecordString(consent2, "id")
	status, encoded := harness.call(t, "getOAuthConsent", http.MethodGet,
		"/api/auth"+GetConsentPath+"?id="+url.QueryEscape(consent1ID), harness.userID, nil)
	var specific map[string]any
	decodeConsentJSON(t, encoded, &specific)
	result["should get a specific consent"] = consentObservation{
		Status: status, MatchesCreatedConsent: consentJSONMatchesRecord(t, specific, consent1),
	}

	status, encoded = harness.call(t, "getOAuthConsents", http.MethodGet,
		"/api/auth"+GetConsentsPath, harness.userID, nil)
	var listed []map[string]any
	decodeConsentJSON(t, encoded, &listed)
	orderMatches := len(listed) == 2 &&
		consentJSONMatchesRecord(t, listed[0], consent1) &&
		consentJSONMatchesRecord(t, listed[1], consent2)
	result["should get user's consents"] = consentObservation{
		Status: status, Count: len(listed), OrderMatches: orderMatches,
	}

	status, _ = harness.callJSON(t, "updateOAuthConsent", UpdateConsentPath, harness.userID, map[string]any{
		"id": consent2ID, "update": map[string]any{"scopes": []string{"email"}},
	})
	result["should not allow updates to scopes not granted to client"] = consentObservation{Status: status}

	status, encoded = harness.callJSON(t, "updateOAuthConsent", UpdateConsentPath, harness.userID, map[string]any{
		"id": consent1ID, "update": map[string]any{"scopes": []string{"email"}},
	})
	var updated map[string]any
	decodeConsentJSON(t, encoded, &updated)
	result["should allow scopes change to client"] = consentObservation{
		Status:                 status,
		Scopes:                 consentTestStrings(updated["scopes"]),
		IdentityPreserved:      updated["id"] == consent1ID,
		CreatedAtPreserved:     consentJSONTime(updated["createdAt"]).Equal(consentRecordTime(consent1, "createdAt")),
		UpdatedAtIsWholeSecond: consentJSONTime(updated["updatedAt"]).Nanosecond() == 0,
	}

	otherConsent, err := harness.service.CreateConsent(t.Context(), CreateConsentInput{
		ClientID: harness.client1, UserID: "other-consent-user", Scopes: firstScopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _ = harness.callJSON(t, "updateOAuthConsent", UpdateConsentPath, harness.userID, map[string]any{
		"id":     consentRecordString(otherConsent, "id"),
		"update": map[string]any{"scopes": firstScopes},
	})
	result["should reject updates to a consent owned by another user"] = consentObservation{Status: status}

	status, encoded = harness.callJSON(t, "deleteOAuthConsent", DeleteConsentPath, harness.userID, map[string]any{
		"id": consent1ID,
	})
	deleteStatus := status
	dataIsNull := string(bytes.TrimSpace(encoded)) == "null"
	status, _ = harness.call(t, "getOAuthConsent", http.MethodGet,
		"/api/auth"+GetConsentPath+"?id="+url.QueryEscape(consent1ID), harness.userID, nil)
	result["should delete the consent"] = consentObservation{
		Status: deleteStatus, DataIsNull: dataIsNull, Removed: status == http.StatusNotFound,
	}
	return result
}

func (harness *consentHarness) callJSON(
	t *testing.T,
	name, path, userID string,
	body any,
) (int, []byte) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return harness.call(t, name, http.MethodPost, "/api/auth"+path, userID, encoded)
}

func (harness *consentHarness) call(
	t *testing.T,
	name, method, target, userID string,
	body []byte,
) (int, []byte) {
	t.Helper()
	status, encoded, err := harness.exchange(name, method, target, userID, body)
	if err != nil {
		t.Fatal(err)
	}
	return status, encoded
}

func newConsentExchange(
	t *testing.T,
	transportName string,
	dispatcher *engine.Dispatcher,
) consentExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		handler := nethttptransport.NewHandler(dispatcher)
		return func(_, method, target, userID string, body []byte) (int, []byte, error) {
			request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Consent-User", userID)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, encoded, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(dispatcher)
		return func(_, method, target, userID string, body []byte) (int, []byte, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.Header.SetHost("localhost:3000")
			request.Header.SetContentType("application/json")
			request.Header.Set("X-Consent-User", userID)
			request.SetRequestURI(target)
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123}, nil)
			handler(&requestContext)
			return requestContext.Response.StatusCode(), append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(dispatcher))
		return func(_, method, target, userID string, body []byte) (int, []byte, error) {
			request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			if err != nil {
				return 0, nil, err
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Consent-User", userID)
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return 0, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, encoded, err
		}
	case "direct":
		return func(name, method, target, userID string, body []byte) (int, []byte, error) {
			parsed, err := url.Parse(target)
			if err != nil {
				return 0, nil, err
			}
			headers := contract.NewHeaders(
				contract.HeaderField{Name: "Content-Type", Value: "application/json"},
				contract.HeaderField{Name: "X-Consent-User", Value: userID},
			)
			request := contract.NewRequest(method, parsed.Path, contract.RequestOptions{
				Scheme: "http", Host: "localhost:3000", RawQuery: parsed.RawQuery,
				Headers: headers, Body: body,
			})
			response, dispatchErr := dispatcher.Invoke(name, engine.DirectInput{Request: request})
			if response.Status() == 0 {
				return 0, nil, dispatchErr
			}
			return response.Status(), response.Body(), nil
		}
	default:
		t.Fatalf("unknown OAuth consent transport %q", transportName)
		return nil
	}
}

func decodeConsentJSON(t *testing.T, encoded []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatalf("decode consent JSON %q: %v", encoded, err)
	}
}

func consentJSONMatchesRecord(t *testing.T, actual map[string]any, expected storage.Record) bool {
	t.Helper()
	encoded, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	var normalized map[string]any
	decodeConsentJSON(t, encoded, &normalized)
	return reflect.DeepEqual(actual, normalized)
}

func consentTestStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, entry := range typed {
			if text, ok := entry.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func consentRecordTime(record storage.Record, key string) time.Time {
	value, _ := record[key].(time.Time)
	return value
}

func consentRecordWholeSeconds(record storage.Record) bool {
	return consentRecordTime(record, "createdAt").Nanosecond() == 0 &&
		consentRecordTime(record, "updatedAt").Nanosecond() == 0
}

func consentJSONTime(value any) time.Time {
	text, _ := value.(string)
	parsed, _ := time.Parse(time.RFC3339Nano, text)
	return parsed
}
