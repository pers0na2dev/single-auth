package singleauth_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type samlMetadataExchange struct {
	status  int
	headers contract.Headers
	body    []byte
}

func TestSAMLSPMetadataGeneratedAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
				config.IdentifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
				config.AuthnRequestsSigned = true
				config.WantAssertionsSigned = true
			})
			result := invokeSAMLMetadata(t, harness.auth, transport, samlCallbackProvider, "")
			assertSAMLMetadataHeaders(t, result)
			document, err := samlprotocol.ParseMetadata(result.body, samlprotocol.DefaultMaxMetadataSize)
			if err != nil {
				t.Fatal(err)
			}
			if len(document.Entities) != 1 {
				t.Fatalf("metadata entities=%d body=%s", len(document.Entities), result.body)
			}
			entity := document.Entities[0]
			if entity.EntityID != samlCallbackSP || entity.SP == nil {
				t.Fatalf("SP entity=%+v", entity)
			}
			if !entity.SP.AuthnRequestsSigned || !entity.SP.WantAssertionsSigned {
				t.Fatalf("SP signature flags=%+v", entity.SP)
			}
			if len(entity.SP.Keys) != 0 {
				t.Fatalf("generated metadata advertised unconfigured keys: %+v", entity.SP.Keys)
			}
			if len(entity.SP.NameIDFormats) != 1 ||
				entity.SP.NameIDFormats[0] != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" {
				t.Fatalf("NameID formats=%v", entity.SP.NameIDFormats)
			}
			if len(entity.SP.AssertionConsumerServices) != 1 {
				t.Fatalf("ACS endpoints=%+v", entity.SP.AssertionConsumerServices)
			}
			acs := entity.SP.AssertionConsumerServices[0]
			if acs.Binding != samlprotocol.HTTPPostBinding || acs.Location != harness.config.CallbackURL ||
				!acs.HasIndex || !acs.IsDefault {
				t.Fatalf("ACS=%+v", acs)
			}
		})
	}
}

func TestSAMLSPMetadataConfiguredXMLAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, nil)
			raw := configuredSPMetadataXML(harness.cert, harness.config.CallbackURL)
			harness = newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
				config.SPMetadata = &samlplugin.SAMLSPMetadata{
					Metadata: raw, EntityID: samlCallbackSP,
				}
			})
			result := invokeSAMLMetadata(t, harness.auth, transport, samlCallbackProvider, "json")
			assertSAMLMetadataHeaders(t, result)
			if string(result.body) != raw {
				t.Fatalf("configured metadata changed\ngot:  %s\nwant: %s", result.body, raw)
			}
			document, err := samlprotocol.ParseMetadata(result.body, samlprotocol.DefaultMaxMetadataSize)
			if err != nil {
				t.Fatal(err)
			}
			if keys := document.Entities[0].SP.Keys; len(keys) != 2 ||
				keys[0].Use != "signing" || keys[1].Use != "encryption" {
				t.Fatalf("configured key descriptors=%+v", keys)
			}
		})
	}
}

func TestSAMLSPMetadataPersistedProviderAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
				_ *singleauth.Options,
				pluginOptions *samlplugin.Options,
			) {
				pluginOptions.DefaultSSO = nil
			})
			persistSAMLMetadataProvider(t, &harness, harness.config)
			result := invokeSAMLMetadata(t, harness.auth, transport, samlCallbackProvider, "xml")
			assertSAMLMetadataHeaders(t, result)
			document, err := samlprotocol.ParseMetadata(result.body, samlprotocol.DefaultMaxMetadataSize)
			if err != nil || len(document.Entities) != 1 || document.Entities[0].EntityID != samlCallbackSP {
				t.Fatalf("persisted metadata=%+v error=%v body=%s", document, err, result.body)
			}
		})
	}
}

func TestSAMLSPMetadataQueryAndProviderErrorsAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, nil)
			for _, test := range []struct {
				name       string
				providerID string
				format     string
				wantStatus int
				wantCode   string
				wantBody   string
			}{
				{name: "missing-provider", wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR", wantBody: "Invalid query parameters"},
				{name: "invalid-format", providerID: samlCallbackProvider, format: "yaml", wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR", wantBody: "Invalid query parameters"},
				{name: "unknown-provider", providerID: "missing", wantStatus: http.StatusNotFound, wantCode: "NOT_FOUND", wantBody: "No provider found for the given providerId"},
			} {
				t.Run(test.name, func(t *testing.T) {
					result := invokeSAMLMetadata(t, harness.auth, transport, test.providerID, test.format)
					if result.status != test.wantStatus || !strings.Contains(string(result.body), test.wantBody) {
						t.Fatalf("status=%d body=%s", result.status, result.body)
					}
					assertSAMLMetadataErrorCode(t, result, test.wantCode)
				})
			}
		})
	}
}

func TestSAMLSPMetadataRejectsMalformedAndAmbiguousConfiguredXML(t *testing.T) {
	for _, test := range []struct {
		name     string
		metadata string
	}{
		{name: "malformed", metadata: `<md:EntityDescriptor`},
		{name: "ambiguous", metadata: `<md:EntitiesDescriptor xmlns:md="` + samlprotocol.MetadataNamespace + `">` +
			`<md:EntityDescriptor entityID="https://sp-a.example.com"><md:SPSSODescriptor><md:AssertionConsumerService Binding="` + samlprotocol.HTTPPostBinding + `" Location="https://sp-a.example.com/acs"/></md:SPSSODescriptor></md:EntityDescriptor>` +
			`<md:EntityDescriptor entityID="https://sp-b.example.com"><md:SPSSODescriptor><md:AssertionConsumerService Binding="` + samlprotocol.HTTPPostBinding + `" Location="https://sp-b.example.com/acs"/></md:SPSSODescriptor></md:EntityDescriptor>` +
			`</md:EntitiesDescriptor>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, transport := range samlTestTransports() {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
						config.SPMetadata = &samlplugin.SAMLSPMetadata{Metadata: test.metadata}
					})
					result := invokeSAMLMetadata(t, harness.auth, transport, samlCallbackProvider, "")
					if result.status != http.StatusBadRequest || !strings.Contains(string(result.body), "Invalid SAML configuration") {
						t.Fatalf("status=%d body=%s", result.status, result.body)
					}
					assertSAMLMetadataErrorCode(t, result, "BAD_REQUEST")
				})
			}
		})
	}
}

func TestSAMLMetadataOnlyDefaultProviderAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
				config.IDPMetadata = &samlplugin.SAMLIDPMetadata{
					Metadata: idpMetadataXML(t, samlCallbackIDP, "https://metadata-idp.example.com/sso", pemCertificates(t, config.Certificate)...),
				}
				config.EntryPoint = ""
				config.Certificate = ""
			})
			relayState, requestID, redirectURL := startSAMLCallbackFlowWithURL(t, harness.auth, transport)
			parsedRedirect, err := url.Parse(redirectURL)
			if err != nil || parsedRedirect.Scheme+"://"+parsedRedirect.Host+parsedRedirect.Path != "https://metadata-idp.example.com/sso" {
				t.Fatalf("metadata SSO redirect=%q error=%v", redirectURL, err)
			}
			response := harness.signedResponse(t, samlResponseFixture{
				AssertionID: "_metadata-only-" + strings.ReplaceAll(transport, "/", "-"),
				RequestID:   requestID, Recipient: harness.config.CallbackURL,
				Audience: samlCallbackSP, Issuer: samlCallbackIDP,
				Email: "metadata-only@corp.example.com",
			})
			result := invokeSAMLCallback(t, harness.auth, transport, false, response, relayState)
			if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/dashboard" {
				t.Fatalf("status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
		})
	}
}

func TestSAMLMetadataOnlyMultipleSigningCertificates(t *testing.T) {
	secondKey, secondCertificate := newSAMLCallbackKeyPair(t)
	harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
		certificates := pemCertificates(t, config.Certificate)
		certificates = append(certificates, secondCertificate)
		config.IDPMetadata = &samlplugin.SAMLIDPMetadata{
			Metadata: idpMetadataXML(t, samlCallbackIDP, "https://metadata-idp.example.com/sso", certificates...),
		}
		config.EntryPoint = ""
		config.Certificate = ""
	})
	harness.privateKey = secondKey
	harness.cert = secondCertificate
	relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
	response := harness.signedResponse(t, samlResponseFixture{
		AssertionID: "_second-rotation-certificate", RequestID: requestID,
		Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
		Issuer: samlCallbackIDP, Email: "rotation@corp.example.com",
	})
	result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
	if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/dashboard" {
		t.Fatalf("status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
	}
	assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
}

func TestSAMLMetadataDoesNotFallbackToTopLevelCertificate(t *testing.T) {
	harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
		config.IDPMetadata = &samlplugin.SAMLIDPMetadata{
			Metadata: idpMetadataXML(t, samlCallbackIDP, "https://metadata-idp.example.com/sso"),
		}
		// A legacy certificate remains configured deliberately. Once metadata XML
		// is present it must not silently become a fallback trust anchor.
	})
	relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
	response := harness.signedResponse(t, samlResponseFixture{
		AssertionID: "_metadata-missing-signing-key", RequestID: requestID,
		Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
		Issuer: samlCallbackIDP, Email: "no-fallback@corp.example.com",
	})
	result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
	if result.status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", result.status, result.body)
	}
	assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
}

func TestSAMLMetadataOnlyPersistedCertificateRotation(t *testing.T) {
	_, oldCertificate := newSAMLCallbackKeyPair(t)
	newKey, newCertificate := newSAMLCallbackKeyPair(t)
	harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
		_ *singleauth.Options,
		pluginOptions *samlplugin.Options,
	) {
		pluginOptions.DefaultSSO = nil
	})
	oldConfig := harness.config
	oldConfig.EntryPoint = ""
	oldConfig.Certificate = ""
	oldConfig.IDPMetadata = &samlplugin.SAMLIDPMetadata{
		Metadata: idpMetadataXML(t, samlCallbackIDP, "https://metadata-idp.example.com/sso", oldCertificate),
	}
	persistSAMLMetadataProvider(t, &harness, oldConfig)

	relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
	harness.privateKey = newKey
	harness.cert = newCertificate
	response := harness.signedResponse(t, samlResponseFixture{
		AssertionID: "_rotated-persisted-certificate", RequestID: requestID,
		Recipient: oldConfig.CallbackURL, Audience: samlCallbackSP,
		Issuer: samlCallbackIDP, Email: "rotated@corp.example.com",
	})
	rejected := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
	if rejected.status != http.StatusBadRequest {
		t.Fatalf("pre-rotation status=%d body=%s", rejected.status, rejected.body)
	}

	newConfig := oldConfig
	newConfig.IDPMetadata = &samlplugin.SAMLIDPMetadata{
		Metadata: idpMetadataXML(t, samlCallbackIDP, "https://metadata-idp.example.com/sso", newCertificate),
	}
	encoded, err := json.Marshal(newConfig)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := harness.adapter.Update(t.Context(), storage.UpdateParams{
		Model:  "ssoProvider",
		Where:  []storage.Where{{Field: "providerId", Value: samlCallbackProvider}},
		Update: storage.Record{"samlConfig": string(encoded)},
	})
	if err != nil || updated == nil {
		t.Fatalf("rotate provider metadata: updated=%v error=%v", updated, err)
	}
	accepted := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
	if accepted.status != http.StatusFound || headerValue(accepted.headers, "Location") != "/dashboard" {
		t.Fatalf("post-rotation status=%d location=%q body=%s", accepted.status, headerValue(accepted.headers, "Location"), accepted.body)
	}
	assertSAMLCallbackRows(t, harness.adapter, 2, 1, 1)
}

func TestSAMLMetadataRejectsMalformedAndAmbiguousDocuments(t *testing.T) {
	_, secondCertificate := newSAMLCallbackKeyPair(t)
	for _, test := range []struct {
		name     string
		metadata func(*samlCallbackHarness) string
	}{
		{name: "malformed", metadata: func(*samlCallbackHarness) string { return `<md:EntityDescriptor` }},
		{name: "ambiguous", metadata: func(harness *samlCallbackHarness) string {
			return `<md:EntitiesDescriptor xmlns:md="` + samlprotocol.MetadataNamespace + `">` +
				idpEntityXML("https://idp-a.example.com", "https://idp-a.example.com/sso", harness.cert) +
				idpEntityXML("https://idp-b.example.com", "https://idp-b.example.com/sso", secondCertificate) +
				`</md:EntitiesDescriptor>`
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, transport := range samlTestTransports() {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					harness := newSAMLCallbackHarness(t, nil)
					metadata := test.metadata(&harness)
					harness = newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
						config.EntryPoint = ""
						config.Certificate = ""
						config.IDPMetadata = &samlplugin.SAMLIDPMetadata{Metadata: metadata}
					})
					body, err := json.Marshal(map[string]any{
						"providerId": samlCallbackProvider, "callbackURL": "/dashboard",
					})
					if err != nil {
						t.Fatal(err)
					}
					status, responseBody := invokeSAMLSignInResponse(t, harness.auth, transport, body)
					if status != http.StatusBadRequest || !strings.Contains(string(responseBody), "Invalid SAML configuration") {
						t.Fatalf("status=%d body=%s", status, responseBody)
					}
				})
			}
		})
	}

	t.Run("ambiguous-explicit-entity-selection", func(t *testing.T) {
		harness := newSAMLCallbackHarness(t, nil)
		metadata := `<md:EntitiesDescriptor xmlns:md="` + samlprotocol.MetadataNamespace + `">` +
			idpEntityXML("https://idp-a.example.com", "https://idp-a.example.com/sso", harness.cert) +
			idpEntityXML(samlCallbackIDP, "https://selected-idp.example.com/sso", harness.cert) +
			`</md:EntitiesDescriptor>`
		harness = newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
			config.EntryPoint = ""
			config.Certificate = ""
			config.IDPMetadata = &samlplugin.SAMLIDPMetadata{
				Metadata: metadata, EntityID: samlCallbackIDP,
			}
		})
		_, _, redirectURL := startSAMLCallbackFlowWithURL(t, harness.auth, "direct")
		parsed, err := url.Parse(redirectURL)
		if err != nil || parsed.Scheme+"://"+parsed.Host+parsed.Path != "https://selected-idp.example.com/sso" {
			t.Fatalf("selected metadata redirect=%q error=%v", redirectURL, err)
		}
	})
}

func TestSAMLSPMetadataConcurrentReadsAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, nil)
			const readers = 32
			results := make(chan samlMetadataExchange, readers)
			var waitGroup sync.WaitGroup
			for range readers {
				waitGroup.Add(1)
				go func() {
					defer waitGroup.Done()
					results <- invokeSAMLMetadata(t, harness.auth, transport, samlCallbackProvider, "")
				}()
			}
			waitGroup.Wait()
			close(results)
			var expected []byte
			for result := range results {
				assertSAMLMetadataHeaders(t, result)
				if expected == nil {
					expected = append([]byte(nil), result.body...)
					continue
				}
				if !bytes.Equal(result.body, expected) {
					t.Fatal("concurrent metadata response changed")
				}
			}
		})
	}
}

func persistSAMLMetadataProvider(
	t *testing.T,
	harness *samlCallbackHarness,
	config samlplugin.SAMLConfig,
) {
	t.Helper()
	owner, err := harness.auth.InternalAdapter().CreateUser(t.Context(), storage.Record{
		"name": "Metadata Owner", "email": "metadata-owner@corp.example.com", "emailVerified": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerID, _ := owner["id"].(string)
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.adapter.Create(t.Context(), storage.CreateParams{
		Model: "ssoProvider",
		Data: storage.Record{
			"issuer": samlCallbackIDP, "domain": "corp.example.com",
			"samlConfig": string(encodedConfig), "oidcConfig": nil,
			"userId": ownerID, "providerId": samlCallbackProvider,
			"domainVerified": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func idpMetadataXML(
	t *testing.T,
	entityID string,
	redirectSSO string,
	certificates ...*x509.Certificate,
) string {
	t.Helper()
	return `<md:EntityDescriptor xmlns:md="` + samlprotocol.MetadataNamespace + `" entityID="` + entityID + `">` +
		idpDescriptorXML(redirectSSO, certificates...) + `</md:EntityDescriptor>`
}

func idpEntityXML(entityID, redirectSSO string, certificate *x509.Certificate) string {
	return `<md:EntityDescriptor entityID="` + entityID + `">` +
		idpDescriptorXML(redirectSSO, certificate) + `</md:EntityDescriptor>`
}

func idpDescriptorXML(redirectSSO string, certificates ...*x509.Certificate) string {
	var keys strings.Builder
	for _, certificate := range certificates {
		keys.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="`)
		keys.WriteString(samlprotocol.XMLDSigNamespace)
		keys.WriteString(`"><ds:X509Data><ds:X509Certificate>`)
		keys.WriteString(base64.StdEncoding.EncodeToString(certificate.Raw))
		keys.WriteString(`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
	}
	return `<md:IDPSSODescriptor protocolSupportEnumeration="` + samlprotocol.ProtocolNamespace + `">` +
		keys.String() + `<md:SingleSignOnService Binding="` + samlprotocol.HTTPRedirectBinding +
		`" Location="` + redirectSSO + `"/></md:IDPSSODescriptor>`
}

func configuredSPMetadataXML(certificate *x509.Certificate, acs string) string {
	encodedCertificate := base64.StdEncoding.EncodeToString(certificate.Raw)
	keyDescriptor := func(use string) string {
		return `<md:KeyDescriptor use="` + use + `"><ds:KeyInfo xmlns:ds="` +
			samlprotocol.XMLDSigNamespace + `"><ds:X509Data><ds:X509Certificate>` +
			encodedCertificate + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
	}
	return `<md:EntityDescriptor xmlns:md="` + samlprotocol.MetadataNamespace + `" entityID="` + samlCallbackSP + `">` +
		`<md:SPSSODescriptor protocolSupportEnumeration="` + samlprotocol.ProtocolNamespace + `">` +
		keyDescriptor("signing") + keyDescriptor("encryption") +
		`<md:AssertionConsumerService Binding="` + samlprotocol.HTTPPostBinding + `" Location="` + acs + `" index="0"/>` +
		`</md:SPSSODescriptor></md:EntityDescriptor>`
}

func pemCertificates(t *testing.T, value string) []*x509.Certificate {
	t.Helper()
	certificates, err := samlprotocol.ParseCertificatesPEM([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return certificates
}

func assertSAMLMetadataHeaders(t *testing.T, result samlMetadataExchange) {
	t.Helper()
	if result.status != http.StatusOK {
		t.Fatalf("metadata status=%d body=%s", result.status, result.body)
	}
	if value := headerValue(result.headers, "Content-Type"); value != "application/xml" {
		t.Fatalf("Content-Type=%q", value)
	}
	if value := headerValue(result.headers, "Cache-Control"); value != "no-store" {
		t.Fatalf("Cache-Control=%q", value)
	}
	if value := headerValue(result.headers, "Pragma"); value != "no-cache" {
		t.Fatalf("Pragma=%q", value)
	}
	if value := headerValue(result.headers, "X-Content-Type-Options"); value != "nosniff" {
		t.Fatalf("X-Content-Type-Options=%q", value)
	}
}

func assertSAMLMetadataErrorCode(t *testing.T, result samlMetadataExchange, want string) {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(result.body, &body); err != nil || body.Code != want {
		t.Fatalf("metadata error code=%q want=%q parseError=%v body=%s", body.Code, want, err, result.body)
	}
}

func invokeSAMLMetadata(
	t *testing.T,
	auth *singleauth.Auth,
	transport string,
	providerID string,
	format string,
) samlMetadataExchange {
	t.Helper()
	query := url.Values{}
	if providerID != "" {
		query.Set("providerId", providerID)
	}
	if format != "" {
		query.Set("format", format)
	}
	path := "/api/auth/sso/saml2/sp/metadata"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	target := samlCallbackBaseURL + path
	switch transport {
	case "direct":
		request := contract.NewRequest(http.MethodGet, "/api/auth/sso/saml2/sp/metadata", contract.RequestOptions{
			Scheme: "http", Host: "localhost:3000", RawQuery: query.Encode(),
		})
		response, _ := auth.Invoke(samlplugin.EndpointSPMetadata, engine.DirectInput{Request: request})
		return samlMetadataExchange{status: response.Status(), headers: response.Headers(), body: response.Body()}
	case "net/http":
		request := httptest.NewRequest(http.MethodGet, target, nil)
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		return samlMetadataExchange{
			status: recorder.Code, headers: contractHeaders(recorder.Header()), body: recorder.Body.Bytes(),
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.SetRequestURI(target)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		headers := contract.Headers{}
		requestContext.Response.Header.VisitAll(func(key, value []byte) {
			headers.Add(string(key), string(value))
		})
		return samlMetadataExchange{
			status: requestContext.Response.StatusCode(), headers: headers,
			body: append([]byte(nil), requestContext.Response.Body()...),
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return samlMetadataExchange{
			status: response.StatusCode, headers: contractHeaders(response.Header), body: body,
		}
	default:
		t.Fatalf("unknown transport %q", transport)
		return samlMetadataExchange{}
	}
}
