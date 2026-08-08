package singleauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	organizationplugin "github.com/pers0na2dev/single-auth/plugins/organization"
	samlplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
	_ "modernc.org/sqlite"
)

var ssoSQLiteSAMLSequence atomic.Uint64

func TestSSOSQLiteSAMLOrganizationAndSingleLogoutLifecycle(t *testing.T) {
	var verificationTXT atomic.Value
	verificationTXT.Store("")
	harness, spKey, encryptionKey := newSSOSQLiteSAMLHarness(t, func(
		_ context.Context,
		_ string,
	) ([]string, error) {
		value, _ := verificationTXT.Load().(string)
		if value == "" {
			return nil, nil
		}
		return []string{value}, nil
	})
	if harness.auth.Adapter().ID() != "sqlite" {
		t.Fatalf("adapter=%q, want sqlite", harness.auth.Adapter().ID())
	}

	ownerCookies := make(map[string]string)
	signedUp := ssoSQLiteJSONExchange(t, harness.auth, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "SQLite SAML Owner", "email": "sqlite-owner@example.test", "password": "password123",
	}, ownerCookies)
	if signedUp.status != http.StatusOK {
		t.Fatalf("owner sign-up status=%d body=%s", signedUp.status, signedUp.body)
	}
	createdOrganization := ssoSQLiteJSONExchange(t, harness.auth, http.MethodPost, "/organization/create", map[string]any{
		"name": "SQLite Enterprise", "slug": "sqlite-enterprise",
	}, ownerCookies)
	if createdOrganization.status != http.StatusOK {
		t.Fatalf("organization create status=%d body=%s", createdOrganization.status, createdOrganization.body)
	}
	var organization struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createdOrganization.body, &organization); err != nil || organization.ID == "" {
		t.Fatalf("organization=%+v error=%v body=%s", organization, err, createdOrganization.body)
	}

	registered := ssoSQLiteJSONExchange(t, harness.auth, http.MethodPost, "/sso/register", map[string]any{
		"providerId":     samlCallbackProvider,
		"issuer":         samlCallbackIDP,
		"domain":         "corp.example.com",
		"organizationId": organization.ID,
		"samlConfig":     harness.config,
	}, ownerCookies)
	if registered.status != http.StatusOK {
		t.Fatalf("SAML provider register status=%d body=%s", registered.status, registered.body)
	}
	var provider struct {
		ProviderID              string `json:"providerId"`
		DomainVerificationToken string `json:"domainVerificationToken"`
		DomainVerified          bool   `json:"domainVerified"`
	}
	if err := json.Unmarshal(registered.body, &provider); err != nil ||
		provider.ProviderID != samlCallbackProvider || provider.DomainVerificationToken == "" ||
		provider.DomainVerified {
		t.Fatalf("registered provider=%+v error=%v body=%s", provider, err, registered.body)
	}
	verificationIdentifier := "_single-auth-token-" + samlCallbackProvider
	pendingVerification, err := harness.auth.InternalAdapter().FindVerificationValue(
		t.Context(), verificationIdentifier,
	)
	if err != nil || pendingVerification == nil ||
		recordTestString(pendingVerification, "value") != provider.DomainVerificationToken {
		t.Fatalf("pending domain verification=%#v error=%v", pendingVerification, err)
	}
	requested := ssoSQLiteJSONExchange(
		t, harness.auth, http.MethodPost, "/sso/request-domain-verification",
		map[string]any{"providerId": samlCallbackProvider}, ownerCookies,
	)
	if requested.status != http.StatusCreated ||
		!strings.Contains(string(requested.body), provider.DomainVerificationToken) {
		t.Fatalf("request verification status=%d body=%s", requested.status, requested.body)
	}
	verificationTXT.Store(verificationIdentifier + "=" + provider.DomainVerificationToken)
	verified := ssoSQLiteJSONExchange(
		t, harness.auth, http.MethodPost, "/sso/verify-domain",
		map[string]any{"providerId": samlCallbackProvider}, ownerCookies,
	)
	if verified.status != http.StatusNoContent {
		t.Fatalf("verify domain status=%d body=%s", verified.status, verified.body)
	}
	persistedProvider := findSSORecord(
		t, harness.adapter, "ssoProvider", "providerId", samlCallbackProvider,
	)
	if persistedProvider == nil || persistedProvider["domainVerified"] != true ||
		persistedProvider["organizationId"] != organization.ID {
		t.Fatalf("persisted verified provider=%#v", persistedProvider)
	}

	metadata := invokeSAMLMetadata(t, harness.auth, "direct", samlCallbackProvider, "xml")
	assertSAMLMetadataHeaders(t, metadata)
	metadataDocument, err := samlprotocol.ParseMetadata(metadata.body, 0)
	if err != nil || len(metadataDocument.Entities) != 1 ||
		metadataDocument.Entities[0].SP == nil ||
		metadataDocument.Entities[0].EntityID != samlCallbackSP {
		t.Fatalf("SQLite SAML metadata=%+v error=%v body=%s", metadataDocument, err, metadata.body)
	}
	services := metadataDocument.Entities[0].SP.SingleLogoutServices
	if len(services) != 2 || services[0].Binding != samlprotocol.HTTPPostBinding ||
		services[1].Binding != samlprotocol.HTTPRedirectBinding {
		t.Fatalf("SQLite SAML metadata SLO services=%+v", services)
	}

	signedOutOwner := ssoSQLiteJSONExchange(
		t, harness.auth, http.MethodPost, "/sign-out", map[string]any{}, ownerCookies,
	)
	if signedOutOwner.status != http.StatusOK {
		t.Fatalf("owner sign-out status=%d body=%s", signedOutOwner.status, signedOutOwner.body)
	}

	relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
	plainAssertion := harness.assertionSignedResponse(t, samlResponseFixture{
		AssertionID: "_sqlite-encrypted-assertion",
		RequestID:   requestID,
		Recipient:   harness.config.CallbackURL,
		Audience:    samlCallbackSP,
		Issuer:      samlCallbackIDP,
		Email:       "sqlite-user@corp.example.com",
	})
	encryptedResponse := encryptSAMLCallbackAssertion(t, plainAssertion, &encryptionKey.PublicKey)

	const callbackCallers = 8
	callbackResults := make(chan samlCallbackExchange, callbackCallers)
	var callbackGroup sync.WaitGroup
	for range callbackCallers {
		callbackGroup.Add(1)
		go func() {
			defer callbackGroup.Done()
			callbackResults <- invokeSAMLCallback(
				t, harness.auth, "direct", false, encryptedResponse, relayState,
			)
		}()
	}
	callbackGroup.Wait()
	close(callbackResults)
	callbackSuccesses := 0
	userCookie := ""
	for result := range callbackResults {
		location := headerValue(result.headers, "Location")
		if result.status != http.StatusFound {
			t.Fatalf("concurrent SQLite callback status=%d location=%q body=%s", result.status, location, result.body)
		}
		if location == "/dashboard" {
			callbackSuccesses++
			userCookie = cookies.ApplySetCookies(userCookie, result.headers.Values("Set-Cookie"))
			continue
		}
		parsed, parseErr := url.Parse(location)
		if parseErr != nil || parsed.Query().Get("error") != "invalid_saml_response" {
			t.Fatalf("concurrent SQLite replay location=%q error=%v", location, parseErr)
		}
	}
	if callbackSuccesses != 1 || userCookie == "" {
		t.Fatalf("concurrent SQLite callback successes=%d cookie=%q", callbackSuccesses, userCookie)
	}
	assertSAMLCallbackRows(t, harness.adapter, 2, 2, 1)
	user := findSSORecord(t, harness.adapter, "user", "email", "sqlite-user@corp.example.com")
	if user == nil {
		t.Fatal("SQLite SAML user was not persisted")
	}
	member, err := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "member",
		Where: []storage.Where{
			{Field: "organizationId", Value: organization.ID},
			{Field: "userId", Value: recordTestString(user, "id")},
		},
	})
	if err != nil || member == nil || member["role"] != "member" {
		t.Fatalf("SQLite SAML organization member=%#v error=%v", member, err)
	}
	assertSAMLSessionRecords(t, &harness, "sqlite-user@corp.example.com", true)
	sessions, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "session"})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("SQLite SAML sessions=%#v error=%v", sessions, err)
	}
	samlSessionID := recordTestString(sessions[0], "id")

	explicitReplay := invokeSAMLCallback(
		t, harness.auth, "direct", false, encryptedResponse, relayState,
	)
	replayLocation, err := url.Parse(headerValue(explicitReplay.headers, "Location"))
	if explicitReplay.status != http.StatusFound || err != nil ||
		replayLocation.Query().Get("error") != "invalid_saml_response" ||
		len(explicitReplay.headers.Values("Set-Cookie")) != 0 {
		t.Fatalf("SQLite encrypted replay status=%d location=%q cookies=%v error=%v",
			explicitReplay.status, headerValue(explicitReplay.headers, "Location"),
			explicitReplay.headers.Values("Set-Cookie"), err)
	}
	assertSAMLCallbackRows(t, harness.adapter, 2, 2, 1)

	logoutBody, err := json.Marshal(map[string]any{"callbackURL": "/sqlite-logged-out"})
	if err != nil {
		t.Fatal(err)
	}
	initiatedLogout := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
		Endpoint:    samlplugin.EndpointInitiateSLO,
		Method:      http.MethodPost,
		Route:       "/sso/saml2/logout/" + samlCallbackProvider,
		Body:        logoutBody,
		ContentType: "application/json",
		Cookie:      userCookie,
		Origin:      samlCallbackBaseURL,
	})
	logoutLocation, err := url.Parse(headerValue(initiatedLogout.headers, "Location"))
	if initiatedLogout.status != http.StatusFound || err != nil ||
		logoutLocation.Scheme+"://"+logoutLocation.Host+logoutLocation.Path != samlTestIDPSLO {
		t.Fatalf("SQLite initiate SLO status=%d location=%q error=%v body=%s",
			initiatedLogout.status, headerValue(initiatedLogout.headers, "Location"), err, initiatedLogout.body)
	}
	logoutBinding, err := samlprotocol.ParseRedirectBinding(
		logoutLocation.RawQuery, []crypto.PublicKey{&spKey.PublicKey},
		samlprotocol.AlgorithmValidationOptions{}, 0,
	)
	if err != nil || !logoutBinding.Signed ||
		logoutBinding.Parameter != samlprotocol.SAMLRequestParameter {
		t.Fatalf("SQLite LogoutRequest binding=%+v error=%v", logoutBinding, err)
	}
	logoutRequest, err := samlprotocol.ParseLogoutRequest(logoutBinding.XML, 0)
	if err != nil || logoutRequest.NameID != "sqlite-user@corp.example.com" ||
		len(logoutRequest.SessionIndexes) != 1 || logoutRequest.SessionIndexes[0] != "_session" {
		t.Fatalf("SQLite LogoutRequest=%+v error=%v", logoutRequest, err)
	}
	assertSAMLCallbackRows(t, harness.adapter, 2, 2, 0)
	assertSAMLSessionRecords(t, &harness, "sqlite-user@corp.example.com", false)
	reverseSession, err := harness.auth.InternalAdapter().FindVerificationValue(
		t.Context(), "saml-session-by-id:"+samlSessionID,
	)
	if err != nil || reverseSession != nil {
		t.Fatalf("SQLite reverse SAML session after logout=%#v error=%v", reverseSession, err)
	}

	currentSLO := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/slo/" + samlCallbackProvider
	logoutResponse, err := samlprotocol.NewLogoutResponse(samlprotocol.LogoutResponseOptions{
		ID:           "_sqlite-logout-response",
		Issuer:       samlCallbackIDP,
		Destination:  currentSLO,
		InResponseTo: logoutRequest.ID,
		IssueInstant: samlCallbackNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	responseURL, err := samlprotocol.BuildRedirectURL(
		t.Context(), currentSLO, samlprotocol.SAMLResponseParameter,
		logoutResponse.XML, "/sqlite-logged-out", harness.privateKey,
		samlprotocol.SignatureRSASHA256,
	)
	if err != nil {
		t.Fatal(err)
	}
	parsedResponseURL, err := url.Parse(responseURL)
	if err != nil {
		t.Fatal(err)
	}
	completedLogout := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
		Endpoint: samlplugin.EndpointSLO,
		Method:   http.MethodGet,
		Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
		RawQuery: parsedResponseURL.RawQuery,
	})
	if completedLogout.status != http.StatusFound ||
		headerValue(completedLogout.headers, "Location") != "/sqlite-logged-out" {
		t.Fatalf("SQLite complete SLO status=%d location=%q body=%s",
			completedLogout.status, headerValue(completedLogout.headers, "Location"), completedLogout.body)
	}
	replayedLogout := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
		Endpoint: samlplugin.EndpointSLO,
		Method:   http.MethodGet,
		Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
		RawQuery: parsedResponseURL.RawQuery,
	})
	if replayedLogout.status != http.StatusBadRequest ||
		!strings.Contains(string(replayedLogout.body), "Invalid LogoutResponse") {
		t.Fatalf("SQLite SLO replay status=%d body=%s", replayedLogout.status, replayedLogout.body)
	}
}

func newSSOSQLiteSAMLHarness(
	t *testing.T,
	lookupTXT func(context.Context, string) ([]string, error),
) (samlCallbackHarness, *rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	idpKey, idpCertificate := newSAMLCallbackKeyPair(t)
	idpCertificatePEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: idpCertificate.Raw,
	}))
	spKey, _ := newSAMLCallbackKeyPair(t)
	spPrivateKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(spKey),
	}))
	const encryptionPassword = "sqlite-encryption-password"
	encryptionKey, encryptionPrivateKeyPEM := encryptedCallbackPrivateKey(t, encryptionPassword)
	config := samlplugin.SAMLConfig{
		Issuer:               samlCallbackSP,
		EntryPoint:           "https://idp.example.com/sso",
		Certificate:          idpCertificatePEM,
		CallbackURL:          samlCallbackBaseURL + "/api/auth/sso/saml2/callback/" + samlCallbackProvider,
		WantAssertionsSigned: true,
		SignatureAlgorithm:   samlprotocol.SignatureRSASHA256,
		IDPMetadata: &samlplugin.SAMLIDPMetadata{
			Metadata:             sloIDPMetadata(t, idpCertificatePEM),
			EntityID:             samlCallbackIDP,
			IsAssertionEncrypted: true,
		},
		SPMetadata: &samlplugin.SAMLSPMetadata{
			EntityID:             samlCallbackSP,
			PrivateKey:           spPrivateKeyPEM,
			IsAssertionEncrypted: true,
			EncPrivateKey:        encryptionPrivateKeyPEM,
			EncPrivateKeyPass:    encryptionPassword,
		},
	}
	database, err := sql.Open(
		"sqlite",
		fmt.Sprintf("file:sso_saml_lifecycle_%d?mode=memory&cache=shared", ssoSQLiteSAMLSequence.Add(1)),
	)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close SSO SAML SQLite database: %v", closeErr)
		}
	})
	rateLimitEnabled := false
	auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
		BaseURL:   samlCallbackBaseURL,
		Secret:    "0123456789abcdef0123456789abcdef",
		Clock:     func() time.Time { return samlCallbackNow },
		RateLimit: singleauth.RateLimitOptions{Enabled: &rateLimitEnabled},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
				Verify: func(hash, value string) bool { return hash == "hashed:"+value },
			},
		},
		PluginFactories: []singleauth.PluginFactory{
			organizationplugin.NewFactory(organizationplugin.Options{}),
			samlplugin.NewFactory(samlplugin.Options{
				DomainVerification: samlplugin.DomainVerificationOptions{
					Enabled: true, LookupTXT: lookupTXT,
				},
				SAML: samlplugin.SAMLRuntimeOptions{
					EnableSingleLogout:       true,
					WantLogoutRequestSigned:  true,
					WantLogoutResponseSigned: true,
				},
			}),
		},
	}, database)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RunMigrationsContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	return samlCallbackHarness{
		auth: auth, adapter: auth.Adapter(), privateKey: idpKey,
		cert: idpCertificate, config: config,
	}, spKey, encryptionKey
}

func ssoSQLiteJSONExchange(
	t *testing.T,
	auth *singleauth.Auth,
	method string,
	target string,
	body any,
	cookieValues map[string]string,
) ssoOIDCResponse {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method, samlCallbackBaseURL+"/api/auth"+target, bytes.NewReader(encoded),
	)
	request.Header.Set("Origin", samlCallbackBaseURL)
	request.Header.Set("Content-Type", "application/json")
	if cookieHeader := serializeCookieValues(cookieValues); cookieHeader != "" {
		request.Header.Set("Cookie", cookieHeader)
	}
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, request)
	result := ssoOIDCResponse{
		status: recorder.Code,
		header: recorder.Header().Clone(),
		body:   append([]byte(nil), recorder.Body.Bytes()...),
	}
	applyOIDCSetCookies(cookieValues, result.header)
	return result
}
