package singleauth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	organizationplugin "github.com/pers0na2dev/single-auth/plugins/organization"
	ssoplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type ssoTXTFixture struct {
	mu      sync.Mutex
	records map[string][]string
}

func (fixture *ssoTXTFixture) lookup(_ context.Context, name string) ([]string, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]string(nil), fixture.records[name]...), nil
}

func (fixture *ssoTXTFixture) set(name string, records ...string) {
	fixture.mu.Lock()
	fixture.records[name] = append([]string(nil), records...)
	fixture.mu.Unlock()
}

func TestSSOProviderManagementAndDomainVerificationAcrossTransports(t *testing.T) {
	server := newSSOOIDCServer(t)
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			dns := &ssoTXTFixture{records: map[string][]string{}}
			auth, adapter := newSSOManagementAuth(t, server, dns.lookup)
			cookies := make(map[string]string)
			signUp := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sign-up/email",
				[]byte(`{"name":"Owner","email":"owner@example.com","password":"password123"}`), cookies)
			if signUp.status != http.StatusOK {
				t.Fatalf("sign-up status=%d body=%s", signUp.status, signUp.body)
			}
			registrationBody, _ := json.Marshal(map[string]any{
				"issuer": server.server.URL, "domain": "corp.example", "providerId": "managed-enterprise",
				"oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "enterprise-secret"},
			})
			registered := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sso/register", registrationBody, cookies)
			if registered.status != http.StatusOK {
				t.Fatalf("register status=%d body=%s", registered.status, registered.body)
			}
			var provider map[string]any
			if err := json.Unmarshal(registered.body, &provider); err != nil {
				t.Fatal(err)
			}
			token, _ := provider["domainVerificationToken"].(string)
			if len(token) != 24 || provider["domainVerified"] != false {
				t.Fatalf("registration verification fields=%#v", provider)
			}

			listed := ssoOIDCExchange(t, auth, transport, http.MethodGet, "/sso/providers", nil, cookies)
			if listed.status != http.StatusOK || strings.Contains(string(listed.body), "enterprise-secret") {
				t.Fatalf("list status=%d body=%s", listed.status, listed.body)
			}
			var listBody struct {
				Providers []map[string]any `json:"providers"`
			}
			if err := json.Unmarshal(listed.body, &listBody); err != nil || len(listBody.Providers) != 1 {
				t.Fatalf("list body=%s err=%v", listed.body, err)
			}
			if config, _ := listBody.Providers[0]["oidcConfig"].(map[string]any); config["clientIdLastFour"] != "****ient" {
				t.Fatalf("sanitized list provider=%#v", listBody.Providers[0])
			}
			got := ssoOIDCExchange(t, auth, transport, http.MethodGet,
				"/sso/get-provider?providerId=managed-enterprise", nil, cookies)
			if got.status != http.StatusOK || strings.Contains(string(got.body), "clientSecret") || strings.Contains(string(got.body), "enterprise-secret") {
				t.Fatalf("get status=%d body=%s", got.status, got.body)
			}
			unauthenticated := ssoOIDCExchange(t, auth, transport, http.MethodGet,
				"/sso/get-provider?providerId=managed-enterprise", nil, make(map[string]string))
			if unauthenticated.status != http.StatusUnauthorized {
				t.Fatalf("unauthenticated get status=%d body=%s", unauthenticated.status, unauthenticated.body)
			}
			intruderCookies := make(map[string]string)
			intruderSignUp := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sign-up/email",
				[]byte(`{"name":"Intruder","email":"intruder@example.com","password":"password123"}`), intruderCookies)
			if intruderSignUp.status != http.StatusOK {
				t.Fatalf("intruder sign-up status=%d body=%s", intruderSignUp.status, intruderSignUp.body)
			}
			forbidden := ssoOIDCExchange(t, auth, transport, http.MethodGet,
				"/sso/get-provider?providerId=managed-enterprise", nil, intruderCookies)
			if forbidden.status != http.StatusForbidden {
				t.Fatalf("foreign get status=%d body=%s", forbidden.status, forbidden.body)
			}
			foreignList := ssoOIDCExchange(t, auth, transport, http.MethodGet, "/sso/providers", nil, intruderCookies)
			if foreignList.status != http.StatusOK || !strings.Contains(string(foreignList.body), `"providers":[]`) {
				t.Fatalf("foreign list status=%d body=%s", foreignList.status, foreignList.body)
			}
			requested := ssoOIDCExchange(t, auth, transport, http.MethodPost,
				"/sso/request-domain-verification", []byte(`{"providerId":"managed-enterprise"}`), cookies)
			var requestedBody map[string]any
			_ = json.Unmarshal(requested.body, &requestedBody)
			if requested.status != http.StatusCreated || requestedBody["domainVerificationToken"] != token {
				t.Fatalf("request verification status=%d body=%s", requested.status, requested.body)
			}

			identifier := "_single-auth-token-managed-enterprise"
			failed := ssoOIDCExchange(t, auth, transport, http.MethodPost,
				"/sso/verify-domain", []byte(`{"providerId":"managed-enterprise"}`), cookies)
			if failed.status != http.StatusBadGateway || !strings.Contains(string(failed.body), "DOMAIN_VERIFICATION_FAILED") {
				t.Fatalf("missing DNS status=%d body=%s", failed.status, failed.body)
			}
			dns.set(identifier+".corp.example", identifier+"="+token)
			verified := ssoOIDCExchange(t, auth, transport, http.MethodPost,
				"/sso/verify-domain", []byte(`{"providerId":"managed-enterprise"}`), cookies)
			if verified.status != http.StatusNoContent {
				t.Fatalf("verify status=%d body=%s", verified.status, verified.body)
			}

			updated := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sso/update-provider",
				[]byte(`{"providerId":"managed-enterprise","domain":"new.corp.example"}`), cookies)
			var updatedBody map[string]any
			_ = json.Unmarshal(updated.body, &updatedBody)
			if updated.status != http.StatusOK || updatedBody["domain"] != "new.corp.example" || updatedBody["domainVerified"] != false {
				t.Fatalf("domain update status=%d body=%s", updated.status, updated.body)
			}
			blockedSignIn := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sign-in/sso",
				[]byte(`{"providerId":"managed-enterprise","callbackURL":"/done"}`), make(map[string]string))
			if blockedSignIn.status != http.StatusUnauthorized {
				t.Fatalf("unverified sign-in status=%d body=%s", blockedSignIn.status, blockedSignIn.body)
			}

			owner := findSSORecord(t, adapter, "user", "email", "owner@example.com")
			if _, err := auth.InternalAdapter().CreateAccount(t.Context(), storage.Record{
				"userId": owner["id"], "providerId": "managed-enterprise", "accountId": "linked-enterprise-user",
			}); err != nil {
				t.Fatal(err)
			}
			identityUpdate := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sso/update-provider",
				[]byte(`{"providerId":"managed-enterprise","oidcConfig":{"clientId":"other-client"}}`), cookies)
			if identityUpdate.status != http.StatusConflict {
				t.Fatalf("identity update status=%d body=%s", identityUpdate.status, identityUpdate.body)
			}
			secretRotation := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sso/update-provider",
				[]byte(`{"providerId":"managed-enterprise","oidcConfig":{"clientSecret":"rotated-secret"}}`), cookies)
			if secretRotation.status != http.StatusOK || strings.Contains(string(secretRotation.body), "rotated-secret") {
				t.Fatalf("secret rotation status=%d body=%s", secretRotation.status, secretRotation.body)
			}
			deleted := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sso/delete-provider",
				[]byte(`{"providerId":"managed-enterprise"}`), cookies)
			if deleted.status != http.StatusOK || strings.TrimSpace(string(deleted.body)) != `{"success":true}` {
				t.Fatalf("delete status=%d body=%s", deleted.status, deleted.body)
			}
			if findSSORecord(t, adapter, "account", "providerId", "managed-enterprise") != nil {
				t.Fatal("linked account survived provider deletion")
			}
			missing := ssoOIDCExchange(t, auth, transport, http.MethodGet,
				"/sso/get-provider?providerId=managed-enterprise", nil, cookies)
			if missing.status != http.StatusNotFound {
				t.Fatalf("get after delete status=%d body=%s", missing.status, missing.body)
			}
		})
	}
}

func newSSOManagementAuth(
	t *testing.T,
	server *ssoOIDCServer,
	lookupTXT func(context.Context, string) ([]string, error),
	providersLimit ...*int,
) (*singleauth.Auth, *memory.Adapter) {
	t.Helper()
	pluginOptions := ssoplugin.Options{
		OIDC: ssoplugin.OIDCRuntimeOptions{HTTPClient: server.server.Client()},
		DomainVerification: ssoplugin.DomainVerificationOptions{
			Enabled: true, LookupTXT: lookupTXT,
		},
	}
	if len(providersLimit) > 0 {
		pluginOptions.ProvidersLimit = providersLimit[0]
	}
	factory := ssoplugin.NewFactory(pluginOptions)
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
	adapter, err := memory.New(memory.WithSchema(schema))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: oidcAuthBaseURL, Secret: "sso-management-secret-at-least-32-bytes",
		Database: adapter, TrustedOrigins: []string{server.server.URL},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories:  []singleauth.PluginFactory{factory},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth, adapter
}

func TestSSOProvidersLimitCanDisableRegistration(t *testing.T) {
	server := newSSOOIDCServer(t)
	dns := &ssoTXTFixture{records: map[string][]string{}}
	zero := 0
	auth, adapter := newSSOManagementAuth(t, server, dns.lookup, &zero)
	cookies := make(map[string]string)
	if response := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sign-up/email",
		[]byte(`{"name":"Owner","email":"limited@example.com","password":"password123"}`), cookies); response.status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", response.status, response.body)
	}
	body, _ := json.Marshal(map[string]any{
		"issuer": server.server.URL, "domain": "corp.example", "providerId": "disabled-provider",
		"oidcConfig": map[string]any{"clientId": "client", "clientSecret": "secret"},
	})
	response := ssoOIDCExchange(t, auth, "net/http", http.MethodPost, "/sso/register", body, cookies)
	if response.status != http.StatusForbidden || !strings.Contains(string(response.body), "maximum number of SSO providers") {
		t.Fatalf("registration status=%d body=%s", response.status, response.body)
	}
	if providers := oidcRecords(t, adapter, "ssoProvider"); len(providers) != 0 {
		t.Fatalf("providers=%#v", providers)
	}
}

func findSSORecord(
	t *testing.T,
	adapter storage.TransactionAdapter,
	model, field string,
	value any,
) storage.Record {
	t.Helper()
	record, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: model, Where: []storage.Where{{Field: field, Value: value}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestSSOSAMLSignedAuthnRequestAdditionalParamsAndGETCallback(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})
	harness := newSAMLCallbackHarnessWithOptions(t, func(config *ssoplugin.SAMLConfig) {
		config.AuthnRequestsSigned = true
		config.PrivateKey = string(privatePEM)
		config.SignatureAlgorithm = samlprotocol.SignatureRSASHA256
		config.AdditionalParams = map[string]any{
			"tenant": "enterprise", "prompt": "login", "RelayState": "attacker",
		}
	}, func(options *singleauth.Options, _ *ssoplugin.Options) {
		options.TrustedOrigins = []string{oidcAuthBaseURL}
	})
	_, _, redirectURL := startSAMLCallbackFlowWithURL(t, harness.auth, "direct")
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("tenant") != "enterprise" || query.Get("prompt") != "login" ||
		query.Get("Signature") == "" || query.Get("SigAlg") != samlprotocol.SignatureRSASHA256 {
		t.Fatalf("signed AuthnRequest URL=%s", parsed)
	}
	if _, err := samlprotocol.ParseRedirectBinding(
		parsed.RawQuery, []crypto.PublicKey{&privateKey.PublicKey}, samlprotocol.AlgorithmValidationOptions{}, 0,
	); err != nil {
		t.Fatalf("AuthnRequest signature verification: %v", err)
	}

	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			cookies := make(map[string]string)
			signUp := ssoOIDCExchange(t, harness.auth, transport, http.MethodPost, "/sign-up/email",
				[]byte(`{"name":"SAML GET","email":"saml-get-`+strings.ReplaceAll(transport, "/", "-")+`@example.com","password":"password123"}`), cookies)
			if signUp.status != http.StatusOK {
				t.Fatalf("sign-up status=%d body=%s", signUp.status, signUp.body)
			}
			result := ssoOIDCExchange(t, harness.auth, transport, http.MethodGet,
				"/sso/saml2/callback/native-saml?RelayState=%2Fdashboard", nil, cookies)
			if result.status != http.StatusFound || result.header.Get("Location") != "/dashboard" {
				t.Fatalf("GET callback status=%d location=%q body=%s", result.status, result.header.Get("Location"), result.body)
			}
			unauthorized := ssoOIDCExchange(t, harness.auth, transport, http.MethodGet,
				"/sso/saml2/callback/native-saml?RelayState=%2Fdashboard", nil, make(map[string]string))
			location, _ := url.Parse(unauthorized.header.Get("Location"))
			if unauthorized.status != http.StatusFound || location.Path != "/error" || location.Query().Get("error") != "invalid_request" {
				t.Fatalf("unauthorized GET status=%d location=%q body=%s", unauthorized.status, unauthorized.header.Get("Location"), unauthorized.body)
			}
		})
	}
}

func TestSSOSAMLProvisionUserAndProviderOrganizationAssignment(t *testing.T) {
	privateKey, certificate := newSAMLCallbackKeyPair(t)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	config := ssoplugin.SAMLConfig{
		Issuer: samlCallbackSP, EntryPoint: "https://idp.example.com/sso",
		Certificate: string(certificatePEM),
		CallbackURL: samlCallbackBaseURL + "/api/auth/sso/saml2/callback/" + samlCallbackProvider,
		IDPMetadata: &ssoplugin.SAMLIDPMetadata{EntityID: samlCallbackIDP},
		SPMetadata:  &ssoplugin.SAMLSPMetadata{EntityID: samlCallbackSP},
	}
	var provisionCalls int
	var provisioned ssoplugin.ProvisionUserInput
	var roleCalls int
	ssoFactory := ssoplugin.NewFactory(ssoplugin.Options{
		ProvisionUser: func(_ context.Context, input ssoplugin.ProvisionUserInput) error {
			provisionCalls++
			provisioned = input
			return nil
		},
		OrganizationProvisioning: ssoplugin.OrganizationProvisioningOptions{
			GetRole: func(_ context.Context, input ssoplugin.OrganizationRoleInput) (string, error) {
				roleCalls++
				if input.UserInfo["email"] != "saml-org@corp.example.com" || input.Provider["organizationId"] != "org-saml" {
					t.Fatalf("role input=%#v", input)
				}
				return "admin", nil
			},
		},
	})
	organizationFactory := organizationplugin.NewFactory(organizationplugin.Options{})
	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	for _, factory := range []singleauth.PluginFactory{organizationFactory, ssoFactory} {
		extension, err := factory.Schema()
		if err != nil {
			t.Fatal(err)
		}
		schema, err = schema.Merge(extension)
		if err != nil {
			t.Fatal(err)
		}
	}
	adapter, err := memory.New(
		memory.WithSchema(schema), memory.WithClock(func() time.Time { return samlCallbackNow }),
	)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: samlCallbackBaseURL, Database: adapter,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Clock:            func() time.Time { return samlCallbackNow },
		PluginFactories:  []singleauth.PluginFactory{organizationFactory, ssoFactory},
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := auth.InternalAdapter().CreateUser(t.Context(), storage.Record{
		"name": "SSO Owner", "email": "owner@corp.example.com", "emailVerified": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Create(t.Context(), storage.CreateParams{Model: "organization", Data: storage.Record{
		"id": "org-saml", "name": "SAML Org", "slug": "saml-org", "createdAt": samlCallbackNow,
	}, ForceAllowID: true}); err != nil {
		t.Fatal(err)
	}
	encodedConfig, _ := json.Marshal(config)
	if _, err := adapter.Create(t.Context(), storage.CreateParams{Model: "ssoProvider", Data: storage.Record{
		"issuer": samlCallbackIDP, "domain": "corp.example.com", "samlConfig": string(encodedConfig),
		"oidcConfig": nil, "userId": owner["id"], "providerId": samlCallbackProvider,
		"organizationId": "org-saml",
	}}); err != nil {
		t.Fatal(err)
	}
	harness := samlCallbackHarness{
		auth: auth, adapter: adapter, privateKey: privateKey, cert: certificate, config: config,
	}
	for attempt := 1; attempt <= 2; attempt++ {
		relayState, requestID := startSAMLCallbackFlow(t, auth, "direct")
		response := harness.signedResponse(t, samlResponseFixture{
			AssertionID: "_saml-org-" + strconv.Itoa(attempt), RequestID: requestID,
			Recipient: config.CallbackURL, Audience: samlCallbackSP,
			Issuer: samlCallbackIDP, Email: "saml-org@corp.example.com",
		})
		result := invokeSAMLCallback(t, auth, "direct", false, response, relayState)
		if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/dashboard" {
			t.Fatalf("attempt %d status=%d location=%q body=%s", attempt, result.status, headerValue(result.headers, "Location"), result.body)
		}
	}
	if provisionCalls != 1 || provisioned.UserInfo["email"] != "saml-org@corp.example.com" ||
		provisioned.Provider.SAMLConfig == nil || roleCalls != 1 {
		t.Fatalf("provisionCalls=%d provisioned=%#v roleCalls=%d", provisionCalls, provisioned, roleCalls)
	}
	members, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "organizationId", Value: "org-saml"}},
	})
	if err != nil || len(members) != 1 || members[0]["role"] != "admin" {
		t.Fatalf("members=%#v err=%v", members, err)
	}
}

func TestSSOSAMLCallbackAppliesConfiguredMetadataLimit(t *testing.T) {
	harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
		_ *singleauth.Options,
		options *ssoplugin.Options,
	) {
		options.DefaultSSO = nil
		options.SAML.MaxMetadataSize = 64
	})
	owner, err := harness.auth.InternalAdapter().CreateUser(t.Context(), storage.Record{
		"name": "Metadata Owner", "email": "metadata-owner@example.com", "emailVerified": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := harness.config
	config.IDPMetadata = &ssoplugin.SAMLIDPMetadata{
		Metadata: strings.Repeat("x", 65), EntityID: samlCallbackIDP,
	}
	encodedConfig, _ := json.Marshal(config)
	if _, err := harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "ssoProvider", Data: storage.Record{
			"issuer": samlCallbackIDP, "domain": "corp.example.com", "samlConfig": string(encodedConfig),
			"oidcConfig": nil, "userId": owner["id"], "providerId": samlCallbackProvider,
			"domainVerified": true,
		},
	}); err != nil {
		t.Fatal(err)
	}
	result := invokeSAMLCallback(t, harness.auth, "direct", false, "not-a-saml-response", "")
	if result.status != http.StatusBadRequest || !strings.Contains(string(result.body), "Invalid SAML configuration") {
		t.Fatalf("callback status=%d body=%s", result.status, result.body)
	}
}
