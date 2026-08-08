package singleauth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestRegisteredSAMLProviderSignInAcrossTransports(t *testing.T) {
	for _, configFormat := range []struct {
		name  string
		value func(*testing.T) any
	}{
		{name: "json-string", value: registeredSAMLConfigJSON},
		{name: "json-bytes", value: registeredSAMLConfigBytes},
		{name: "decoded-object", value: registeredSAMLConfigObject},
	} {
		configFormat := configFormat
		t.Run(configFormat.name, func(t *testing.T) {
			for _, lookup := range []struct {
				name         string
				body         map[string]any
				recordDomain string
			}{
				{
					name: "provider-id", body: map[string]any{"providerId": "registered-saml", "callbackURL": "/dashboard"},
					recordDomain: "corp.example.com, example.net",
				},
				{
					name: "exact-domain", body: map[string]any{"domain": "corp.example.com", "callbackURL": "/dashboard"},
					recordDomain: "corp.example.com",
				},
				{
					name: "normalized-domain-set", body: map[string]any{"email": "alice@team.corp.example.com", "callbackURL": "/dashboard"},
					recordDomain: "corp.example.com, example.net",
				},
			} {
				lookup := lookup
				t.Run(lookup.name, func(t *testing.T) {
					body, err := json.Marshal(lookup.body)
					if err != nil {
						t.Fatal(err)
					}
					for _, transport := range samlTestTransports() {
						transport := transport
						t.Run(transport, func(t *testing.T) {
							record := registeredSAMLProviderRecord(t, boolPointer(true))
							record["samlConfig"] = configFormat.value(t)
							record["domain"] = lookup.recordDomain
							auth := newRegisteredSAMLAuth(t, true, record)
							observation := observeSAMLSignIn(t, invokeSAMLSignIn(t, auth, transport, body))
							assertRegisteredSAMLRequest(t, observation, "https://registered-idp.example.com",
								"http://localhost:3000/api/auth/sso/saml2/callback/registered-saml")
						})
					}
				})
			}
		})
	}
}

func TestRegisteredSAMLProviderRequiresVerifiedDomainAcrossTransports(t *testing.T) {
	body := []byte(`{"providerId":"registered-saml","callbackURL":"/dashboard"}`)
	for _, marker := range []struct {
		name     string
		verified *bool
	}{
		{name: "false", verified: boolPointer(false)},
		{name: "missing", verified: nil},
	} {
		marker := marker
		t.Run(marker.name, func(t *testing.T) {
			for _, transport := range samlTestTransports() {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					auth := newRegisteredSAMLAuth(t, true, registeredSAMLProviderRecord(t, marker.verified))
					status, responseBody := invokeSAMLSignInResponse(t, auth, transport, body)
					if status != http.StatusUnauthorized || !strings.Contains(string(responseBody), "Provider domain has not been verified") {
						t.Fatalf("status=%d body=%s", status, responseBody)
					}
				})
			}
		})
	}
}

func TestRegisteredSAMLProviderSkipsVerificationWhenDisabledAcrossTransports(t *testing.T) {
	body := []byte(`{"providerId":"registered-saml","callbackURL":"/dashboard"}`)
	for _, marker := range []struct {
		name     string
		verified *bool
	}{
		{name: "false", verified: boolPointer(false)},
		{name: "missing", verified: nil},
	} {
		marker := marker
		t.Run(marker.name, func(t *testing.T) {
			for _, transport := range samlTestTransports() {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					auth := newRegisteredSAMLAuth(t, false, registeredSAMLProviderRecord(t, marker.verified))
					observation := observeSAMLSignIn(t, invokeSAMLSignIn(t, auth, transport, body))
					assertRegisteredSAMLRequest(t, observation, "https://registered-idp.example.com",
						"http://localhost:3000/api/auth/sso/saml2/callback/registered-saml")
				})
			}
		})
	}
}

func TestSAMLDefaultProviderPrecedenceAndDatabaseFallbackAcrossTransports(t *testing.T) {
	body := []byte(`{"providerId":"registered-saml","callbackURL":"/dashboard"}`)
	for _, test := range []struct {
		name           string
		body           []byte
		defaults       []samlplugin.DefaultProvider
		domainVerified bool
		wantIssuer     string
		wantCallback   string
	}{
		{
			name: "matching-default-wins-before-unverified-database-row",
			body: body,
			defaults: []samlplugin.DefaultProvider{newDefaultSAMLProvider(
				"registered-saml", "default.example.com", "https://default-idp.example.com",
				"http://localhost:3000/api/auth/sso/saml2/callback/default-saml",
			)},
			domainVerified: false,
			wantIssuer:     "https://default-idp.example.com",
			wantCallback:   "http://localhost:3000/api/auth/sso/saml2/callback/default-saml",
		},
		{
			name: "matching-default-domain-wins-before-unverified-database-row",
			body: []byte(`{"email":"alice@team.corp.example.com","callbackURL":"/dashboard"}`),
			defaults: []samlplugin.DefaultProvider{newDefaultSAMLProvider(
				"default-domain-saml", "corp.example.com", "https://default-domain-idp.example.com",
				"http://localhost:3000/api/auth/sso/saml2/callback/default-domain-saml",
			)},
			domainVerified: false,
			wantIssuer:     "https://default-domain-idp.example.com",
			wantCallback:   "http://localhost:3000/api/auth/sso/saml2/callback/default-domain-saml",
		},
		{
			name: "unrelated-default-falls-back-to-database",
			body: body,
			defaults: []samlplugin.DefaultProvider{newDefaultSAMLProvider(
				"other-saml", "other.example.com", "https://other-idp.example.com",
				"http://localhost:3000/api/auth/sso/saml2/callback/other-saml",
			)},
			domainVerified: true,
			wantIssuer:     "https://registered-idp.example.com",
			wantCallback:   "http://localhost:3000/api/auth/sso/saml2/callback/registered-saml",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			for _, transport := range samlTestTransports() {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					auth := newRegisteredSAMLAuth(
						t, true, registeredSAMLProviderRecord(t, boolPointer(test.domainVerified)), test.defaults...,
					)
					observation := observeSAMLSignIn(t, invokeSAMLSignIn(t, auth, transport, test.body))
					assertRegisteredSAMLRequest(t, observation, test.wantIssuer, test.wantCallback)
				})
			}
		})
	}
}

func TestRegisteredSAMLProviderLookupFailuresAcrossTransports(t *testing.T) {
	for _, test := range []struct {
		name       string
		body       []byte
		configure  func(*testing.T, storage.Record)
		wantStatus int
		wantBody   string
	}{
		{
			name: "selector-required", body: []byte(`{"callbackURL":"/dashboard"}`),
			configure:  func(*testing.T, storage.Record) {},
			wantStatus: http.StatusBadRequest, wantBody: "email, domain or providerId is required",
		},
		{
			name: "unknown-provider", body: []byte(`{"providerId":"missing","callbackURL":"/dashboard"}`),
			configure:  func(*testing.T, storage.Record) {},
			wantStatus: http.StatusNotFound, wantBody: "No provider found for the issuer",
		},
		{
			name: "malformed-stored-json", body: []byte(`{"providerId":"registered-saml","callbackURL":"/dashboard"}`),
			configure:  func(_ *testing.T, record storage.Record) { record["samlConfig"] = `{"issuer":` },
			wantStatus: http.StatusBadRequest, wantBody: "Invalid SSO provider",
		},
		{
			name: "incomplete-stored-config", body: []byte(`{"providerId":"registered-saml","callbackURL":"/dashboard"}`),
			configure:  func(_ *testing.T, record storage.Record) { record["samlConfig"] = `{}` },
			wantStatus: http.StatusBadRequest, wantBody: "Invalid SAML configuration",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			for _, transport := range samlTestTransports() {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					record := registeredSAMLProviderRecord(t, boolPointer(true))
					test.configure(t, record)
					auth := newRegisteredSAMLAuth(t, true, record)
					status, responseBody := invokeSAMLSignInResponse(t, auth, transport, test.body)
					if status != test.wantStatus || !strings.Contains(string(responseBody), test.wantBody) {
						t.Fatalf("status=%d body=%s", status, responseBody)
					}
				})
			}
		})
	}
}

func TestRegisteredSAMLProviderConcurrentSignIn(t *testing.T) {
	auth := newRegisteredSAMLAuth(t, true, registeredSAMLProviderRecord(t, boolPointer(true)))
	body := []byte(`{"providerId":"registered-saml","callbackURL":"/dashboard"}`)
	const workers = 32
	start := make(chan struct{})
	results := make(chan struct {
		relayState string
		err        error
	}, workers)
	for range workers {
		go func() {
			<-start
			relayState, err := invokeRegisteredSAMLDirect(auth, body)
			results <- struct {
				relayState string
				err        error
			}{relayState: relayState, err: err}
		}()
	}
	close(start)
	seen := make(map[string]struct{}, workers)
	var firstErr error
	for range workers {
		result := <-results
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		if _, exists := seen[result.relayState]; exists {
			t.Fatalf("duplicate RelayState %q", result.relayState)
		}
		seen[result.relayState] = struct{}{}
	}
	if firstErr != nil {
		t.Fatal(firstErr)
	}
}

func newRegisteredSAMLAuth(
	t *testing.T,
	domainVerificationEnabled bool,
	providerRecord storage.Record,
	defaults ...samlplugin.DefaultProvider,
) *singleauth.Auth {
	t.Helper()
	options := samlplugin.Options{
		DefaultSSO: defaults,
		DomainVerification: samlplugin.DomainVerificationOptions{
			Enabled: domainVerificationEnabled,
		},
	}
	factory := samlplugin.NewFactory(options)
	pluginSchema, err := factory.Schema()
	if err != nil {
		t.Fatal(err)
	}
	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	schema, err = schema.Merge(pluginSchema)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 10, 1, 0, 0, 0, time.UTC)
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithClock(func() time.Time { return now }),
		memory.WithInitialData(map[string][]storage.Record{
			"user": {{
				"id": "owner", "name": "Owner", "email": "owner@example.com",
				"emailVerified": true, "createdAt": now, "updatedAt": now,
			}},
			"ssoProvider": {providerRecord},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Database: adapter,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories:  []singleauth.PluginFactory{factory},
		Clock:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func registeredSAMLProviderRecord(t *testing.T, domainVerified *bool) storage.Record {
	t.Helper()
	record := storage.Record{
		"id": "provider-record", "issuer": "https://registered-idp.example.com",
		"domain": "corp.example.com, example.net", "samlConfig": registeredSAMLConfigJSON(t),
		"oidcConfig": nil, "userId": "owner", "providerId": "registered-saml",
	}
	if domainVerified != nil {
		record["domainVerified"] = *domainVerified
	}
	return record
}

func registeredSAMLConfig() samlplugin.SAMLConfig {
	return samlplugin.SAMLConfig{
		Issuer: "https://registered-idp.example.com", EntryPoint: samlSmokeEntryPoint,
		Certificate: "registered-test-certificate",
		CallbackURL: "http://localhost:3000/api/auth/sso/saml2/callback/registered-saml",
	}
}

func registeredSAMLConfigJSON(t *testing.T) any {
	t.Helper()
	encoded, err := json.Marshal(registeredSAMLConfig())
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func registeredSAMLConfigBytes(t *testing.T) any {
	t.Helper()
	encoded, err := json.Marshal(registeredSAMLConfig())
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func registeredSAMLConfigObject(t *testing.T) any {
	t.Helper()
	encoded, err := json.Marshal(registeredSAMLConfig())
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func newDefaultSAMLProvider(providerID, domain, issuer, callbackURL string) samlplugin.DefaultProvider {
	config := registeredSAMLConfig()
	config.Issuer = issuer
	config.CallbackURL = callbackURL
	return samlplugin.DefaultProvider{ProviderID: providerID, Domain: domain, SAMLConfig: config}
}

func assertRegisteredSAMLRequest(t *testing.T, observation samlSmokeObservation, issuer, callbackURL string) {
	t.Helper()
	if !observation.HasURL || !observation.Redirect || !observation.PointsToIDP || !observation.HasRequest {
		t.Fatalf("registered provider observation=%#v", observation)
	}
	if observation.Request == nil || observation.Request.Issuer != issuer ||
		observation.Request.AssertionConsumerServiceURL != callbackURL {
		t.Fatalf("registered provider request=%#v", observation.Request)
	}
}

func invokeRegisteredSAMLDirect(auth *singleauth.Auth, body []byte) (string, error) {
	request := contract.NewRequest(http.MethodPost, "/api/auth/sign-in/sso", contract.RequestOptions{
		Scheme: "http", Host: "localhost:3000", Body: body,
		Headers: contract.NewHeaders(
			contract.HeaderField{Name: "Content-Type", Value: "application/json"},
			contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"},
		),
	})
	response, err := auth.Invoke("signInSSO", engine.DirectInput{Request: request})
	if err != nil {
		return "", err
	}
	if response.Status() != http.StatusOK {
		return "", fmt.Errorf("status=%d body=%s", response.Status(), response.Body())
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		return "", err
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		return "", err
	}
	relayState := parsed.Query().Get("RelayState")
	if relayState == "" {
		return "", fmt.Errorf("missing RelayState in %q", result.URL)
	}
	return relayState, nil
}

func samlTestTransports() []string {
	return []string{"direct", "net/http", "fasthttp", "fiber"}
}

func boolPointer(value bool) *bool { return &value }
