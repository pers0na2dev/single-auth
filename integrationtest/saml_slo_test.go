package singleauth_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const samlTestIDPSLO = "https://idp.example.com/slo"

func TestSAMLSingleLogoutDisabledAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, nil)
			body := []byte(url.Values{
				"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(`<LogoutRequest/>`))},
			}.Encode())
			result := invokeSAMLSLO(t, harness.auth, transport, samlSLOInvocation{
				Endpoint: samlplugin.EndpointSLO, Method: http.MethodPost,
				Route: "/sso/saml2/sp/slo/" + samlCallbackProvider,
				Body:  body, ContentType: "application/x-www-form-urlencoded",
			})
			if result.status != http.StatusBadRequest ||
				!strings.Contains(string(result.body), "Single Logout is not enabled") {
				t.Fatalf("status=%d body=%s", result.status, result.body)
			}
		})
	}
}

func TestSAMLSingleLogoutErrorContracts(t *testing.T) {
	t.Run("missing logout data redirects safely", func(t *testing.T) {
		harness, _, _ := newSAMLSLOHarness(t, false)
		result := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
			Endpoint: samlplugin.EndpointSLO, Method: http.MethodGet,
			Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
			RawQuery: url.Values{"RelayState": {"https://evil.example/phish"}}.Encode(),
		})
		location, err := url.Parse(headerValue(result.headers, "Location"))
		if result.status != http.StatusFound || err != nil ||
			location.Scheme+"://"+location.Host != samlCallbackBaseURL ||
			location.Query().Get("error") != "invalid_request" ||
			location.Query().Get("error_description") != "missing_logout_data" {
			t.Fatalf("status=%d location=%q error=%v", result.status, headerValue(result.headers, "Location"), err)
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		harness, _, _ := newSAMLSLOHarness(t, false)
		result := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
			Endpoint: samlplugin.EndpointSLO, Method: http.MethodPost,
			Route: "/sso/saml2/sp/slo/missing-provider", ProviderID: "missing-provider",
			Body:        []byte(url.Values{"SAMLRequest": {"not-base64"}}.Encode()),
			ContentType: "application/x-www-form-urlencoded",
		})
		if result.status != http.StatusNotFound || !strings.Contains(string(result.body), "SAML provider not found") {
			t.Fatalf("status=%d body=%s", result.status, result.body)
		}
	})

	t.Run("IdP has no SLO service", func(t *testing.T) {
		harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
			_ *singleauth.Options,
			options *samlplugin.Options,
		) {
			options.SAML.EnableSingleLogout = true
		})
		cookieHeader := establishSAMLSLOSession(t, &harness, "direct", "no-slo@corp.example.com")
		body, _ := json.Marshal(map[string]any{"callbackURL": "/done"})
		result := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
			Endpoint: samlplugin.EndpointInitiateSLO, Method: http.MethodPost,
			Route: "/sso/saml2/logout/" + samlCallbackProvider,
			Body:  body, ContentType: "application/json", Cookie: cookieHeader,
		})
		if result.status != http.StatusBadRequest ||
			!strings.Contains(string(result.body), "IdP does not support Single Logout Service") {
			t.Fatalf("status=%d body=%s", result.status, result.body)
		}
		assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
	})
}

func TestSAMLSingleLogoutMetadataAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness, _, _ := newSAMLSLOHarness(t, false)
			result := invokeSAMLMetadata(t, harness.auth, transport, samlCallbackProvider, "")
			if result.status != http.StatusOK {
				t.Fatalf("status=%d body=%s", result.status, result.body)
			}
			document, err := samlprotocol.ParseMetadata(result.body, 0)
			if err != nil {
				t.Fatal(err)
			}
			services := document.Entities[0].SP.SingleLogoutServices
			if len(services) != 2 || services[0].Binding != samlprotocol.HTTPPostBinding ||
				services[1].Binding != samlprotocol.HTTPRedirectBinding {
				t.Fatalf("SLO services=%+v", services)
			}
			wantLocation := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/slo/" + samlCallbackProvider
			if services[0].Location != wantLocation || services[1].Location != wantLocation {
				t.Fatalf("SLO locations=%+v", services)
			}
		})
	}
}

func TestSAMLSPInitiatedSingleLogoutAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness, spKey, _ := newSAMLSLOHarness(t, true)
			cookieHeader := establishSAMLSLOSession(t, &harness, transport, "sp-user@corp.example.com")
			assertSAMLSessionRecords(t, &harness, "sp-user@corp.example.com", true)

			body, _ := json.Marshal(map[string]any{"callbackURL": "/logged-out"})
			initiated := invokeSAMLSLO(t, harness.auth, transport, samlSLOInvocation{
				Endpoint: samlplugin.EndpointInitiateSLO, Method: http.MethodPost,
				Route: "/sso/saml2/logout/" + samlCallbackProvider,
				Body:  body, ContentType: "application/json", Cookie: cookieHeader,
				Origin: samlCallbackBaseURL,
			})
			if initiated.status != http.StatusFound {
				t.Fatalf("initiate status=%d body=%s", initiated.status, initiated.body)
			}
			location, err := url.Parse(headerValue(initiated.headers, "Location"))
			if err != nil || location.Scheme+"://"+location.Host+location.Path != samlTestIDPSLO {
				t.Fatalf("initiate location=%q error=%v", headerValue(initiated.headers, "Location"), err)
			}
			message, err := samlprotocol.ParseRedirectBinding(
				location.RawQuery, []crypto.PublicKey{&spKey.PublicKey},
				samlprotocol.AlgorithmValidationOptions{}, 0,
			)
			if err != nil || !message.Signed || message.Parameter != samlprotocol.SAMLRequestParameter {
				t.Fatalf("LogoutRequest binding=%+v error=%v", message, err)
			}
			logoutRequest, err := samlprotocol.ParseLogoutRequest(message.XML, 0)
			if err != nil || logoutRequest.NameID != "sp-user@corp.example.com" ||
				len(logoutRequest.SessionIndexes) != 1 || logoutRequest.SessionIndexes[0] != "_session" {
				t.Fatalf("LogoutRequest=%+v error=%v", logoutRequest, err)
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 0)
			assertSAMLSessionRecords(t, &harness, "sp-user@corp.example.com", false)
			if !strings.Contains(strings.Join(initiated.headers.Values("Set-Cookie"), ";"), "session_token=;") {
				t.Fatalf("initiate Set-Cookie=%v", initiated.headers.Values("Set-Cookie"))
			}

			currentSLO := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/slo/" + samlCallbackProvider
			logoutResponse, err := samlprotocol.NewLogoutResponse(samlprotocol.LogoutResponseOptions{
				ID:     "_logout-response-" + strings.ReplaceAll(transport, "/", "-"),
				Issuer: samlCallbackIDP, Destination: currentSLO,
				InResponseTo: logoutRequest.ID, IssueInstant: samlCallbackNow,
			})
			if err != nil {
				t.Fatal(err)
			}
			responseURL, err := samlprotocol.BuildRedirectURL(
				t.Context(), currentSLO, samlprotocol.SAMLResponseParameter,
				logoutResponse.XML, "/logged-out", harness.privateKey,
				samlprotocol.SignatureRSASHA256,
			)
			if err != nil {
				t.Fatal(err)
			}
			parsedResponseURL, _ := url.Parse(responseURL)
			completed := invokeSAMLSLO(t, harness.auth, transport, samlSLOInvocation{
				Endpoint: samlplugin.EndpointSLO, Method: http.MethodGet,
				Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
				RawQuery: parsedResponseURL.RawQuery,
			})
			if completed.status != http.StatusFound || headerValue(completed.headers, "Location") != "/logged-out" {
				t.Fatalf("complete status=%d location=%q body=%s", completed.status, headerValue(completed.headers, "Location"), completed.body)
			}
			if !strings.Contains(strings.Join(completed.headers.Values("Set-Cookie"), ";"), "session_token=;") {
				t.Fatalf("complete Set-Cookie=%v", completed.headers.Values("Set-Cookie"))
			}
			replayed := invokeSAMLSLO(t, harness.auth, transport, samlSLOInvocation{
				Endpoint: samlplugin.EndpointSLO, Method: http.MethodGet,
				Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
				RawQuery: parsedResponseURL.RawQuery,
			})
			if replayed.status != http.StatusBadRequest || !strings.Contains(string(replayed.body), "Invalid LogoutResponse") {
				t.Fatalf("replay status=%d body=%s", replayed.status, replayed.body)
			}
		})
	}
}

func TestSAMLIDPInitiatedSingleLogoutAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness, spKey, _ := newSAMLSLOHarness(t, true)
			cookieHeader := establishSAMLSLOSession(t, &harness, transport, "idp-user@corp.example.com")
			currentSLO := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/slo/" + samlCallbackProvider
			request, err := samlprotocol.NewLogoutRequest(samlprotocol.LogoutRequestOptions{
				ID:     "_idp-request-" + strings.ReplaceAll(transport, "/", "-"),
				Issuer: samlCallbackIDP, Destination: currentSLO,
				NameID: "idp-user@corp.example.com", SessionIndex: "_session",
				IssueInstant: samlCallbackNow,
			})
			if err != nil {
				t.Fatal(err)
			}
			requestURL, err := samlprotocol.BuildRedirectURL(
				t.Context(), currentSLO, samlprotocol.SAMLRequestParameter,
				request.XML, "/idp-finished", harness.privateKey,
				samlprotocol.SignatureRSASHA256,
			)
			if err != nil {
				t.Fatal(err)
			}
			parsedRequestURL, _ := url.Parse(requestURL)
			result := invokeSAMLSLO(t, harness.auth, transport, samlSLOInvocation{
				Endpoint: samlplugin.EndpointSLO, Method: http.MethodGet,
				Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
				RawQuery: parsedRequestURL.RawQuery, Cookie: cookieHeader,
			})
			if result.status != http.StatusFound {
				t.Fatalf("status=%d body=%s", result.status, result.body)
			}
			responseURL, err := url.Parse(headerValue(result.headers, "Location"))
			if err != nil || responseURL.Scheme+"://"+responseURL.Host+responseURL.Path != samlTestIDPSLO {
				t.Fatalf("response location=%q error=%v", headerValue(result.headers, "Location"), err)
			}
			message, err := samlprotocol.ParseRedirectBinding(
				responseURL.RawQuery, []crypto.PublicKey{&spKey.PublicKey},
				samlprotocol.AlgorithmValidationOptions{}, 0,
			)
			if err != nil || !message.Signed || message.Parameter != samlprotocol.SAMLResponseParameter ||
				message.RelayState != "/idp-finished" {
				t.Fatalf("LogoutResponse binding=%+v error=%v", message, err)
			}
			response, err := samlprotocol.ParseLogoutResponse(message.XML, 0)
			if err != nil || response.InResponseTo != request.ID || response.StatusCode != samlprotocol.StatusSuccess {
				t.Fatalf("LogoutResponse=%+v error=%v", response, err)
			}
			if !strings.Contains(strings.Join(result.headers.Values("Set-Cookie"), ";"), "session_token=;") {
				t.Fatalf("Set-Cookie=%v", result.headers.Values("Set-Cookie"))
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 0)
			assertSAMLSessionRecords(t, &harness, "idp-user@corp.example.com", false)

			replay := invokeSAMLSLO(t, harness.auth, transport, samlSLOInvocation{
				Endpoint: samlplugin.EndpointSLO, Method: http.MethodGet,
				Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
				RawQuery: parsedRequestURL.RawQuery,
			})
			if replay.status != http.StatusBadRequest || !strings.Contains(string(replay.body), "Invalid LogoutRequest") {
				t.Fatalf("replay status=%d body=%s", replay.status, replay.body)
			}
		})
	}
}

func TestSAMLIDPLogoutSessionOwnershipAndExternalPOST(t *testing.T) {
	harness, _, spCertificate := newSAMLSLOHarness(t, true)
	cookieHeader := establishSAMLSLOSession(t, &harness, "direct", "owner@corp.example.com")
	currentSLO := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/slo/" + samlCallbackProvider
	request, err := samlprotocol.NewLogoutRequest(samlprotocol.LogoutRequestOptions{
		ID: "_wrong-session-index", Issuer: samlCallbackIDP, Destination: currentSLO,
		NameID: "owner@corp.example.com", SessionIndex: "_someone-else",
		IssueInstant: samlCallbackNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := samlprotocol.SignXMLMessage(request.XML, samlprotocol.XMLSigningOptions{
		Signer: harness.privateKey, Certificates: []*x509.Certificate{harness.cert},
		SignatureAlgorithm: samlprotocol.SignatureRSASHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(url.Values{
		"SAMLRequest": {samlprotocol.EncodePOSTMessage(signed)}, "RelayState": {"/done"},
	}.Encode())
	result := invokeSAMLSLO(t, harness.auth, "net/http", samlSLOInvocation{
		Endpoint: samlplugin.EndpointSLO, Method: http.MethodPost,
		Route: "/sso/saml2/sp/slo/" + samlCallbackProvider,
		Body:  body, ContentType: "application/x-www-form-urlencoded",
		Cookie: cookieHeader, Origin: "https://external-idp.example.com",
	})
	if result.status == http.StatusForbidden {
		t.Fatalf("external IdP POST was blocked by origin middleware: %s", result.body)
	}
	if result.status != http.StatusOK || !strings.Contains(string(result.body), "SAMLResponse") {
		t.Fatalf("status=%d body=%s", result.status, result.body)
	}
	match := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`).FindSubmatch(result.body)
	if len(match) != 2 {
		t.Fatalf("POST response form has no SAMLResponse: %s", result.body)
	}
	responseXML, err := samlprotocol.DecodePOSTMessage(html.UnescapeString(string(match[1])), 0)
	if err != nil {
		t.Fatal(err)
	}
	logoutResponse, err := samlprotocol.ParseLogoutResponse(responseXML, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := samlprotocol.ValidateLogoutResponse(t.Context(), logoutResponse, false, samlprotocol.LogoutValidationOptions{
		ExpectedIssuer: samlCallbackSP, ExpectedDestination: samlTestIDPSLO,
		RequireSignature: true, Certificates: []*x509.Certificate{spCertificate},
		Now: func() time.Time { return samlCallbackNow },
	}); err != nil {
		t.Fatalf("signed POST LogoutResponse failed validation: %v", err)
	}
	if len(result.headers.Values("Set-Cookie")) != 0 {
		t.Fatalf("mismatched SessionIndex cleared cookie: %v", result.headers.Values("Set-Cookie"))
	}
	assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
	assertSAMLSessionRecords(t, &harness, "owner@corp.example.com", true)
}

func TestSAMLSingleLogoutReplayIsAtomicUnderConcurrency(t *testing.T) {
	t.Run("LogoutResponse", func(t *testing.T) {
		harness, spKey, _ := newSAMLSLOHarness(t, true)
		cookieHeader := establishSAMLSLOSession(t, &harness, "direct", "response-race@corp.example.com")
		body, _ := json.Marshal(map[string]any{"callbackURL": "/race-complete"})
		initiated := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
			Endpoint: samlplugin.EndpointInitiateSLO, Method: http.MethodPost,
			Route: "/sso/saml2/logout/" + samlCallbackProvider,
			Body:  body, ContentType: "application/json", Cookie: cookieHeader,
		})
		location, err := url.Parse(headerValue(initiated.headers, "Location"))
		if initiated.status != http.StatusFound || err != nil {
			t.Fatalf("initiate status=%d location=%q error=%v body=%s", initiated.status, headerValue(initiated.headers, "Location"), err, initiated.body)
		}
		message, err := samlprotocol.ParseRedirectBinding(
			location.RawQuery, []crypto.PublicKey{&spKey.PublicKey},
			samlprotocol.AlgorithmValidationOptions{}, 0,
		)
		if err != nil {
			t.Fatal(err)
		}
		request, err := samlprotocol.ParseLogoutRequest(message.XML, 0)
		if err != nil {
			t.Fatal(err)
		}
		currentSLO := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/slo/" + samlCallbackProvider
		response, err := samlprotocol.NewLogoutResponse(samlprotocol.LogoutResponseOptions{
			ID: "_concurrent-response", Issuer: samlCallbackIDP,
			Destination: currentSLO, InResponseTo: request.ID, IssueInstant: samlCallbackNow,
		})
		if err != nil {
			t.Fatal(err)
		}
		responseURL, err := samlprotocol.BuildRedirectURL(
			t.Context(), currentSLO, samlprotocol.SAMLResponseParameter,
			response.XML, "/race-complete", harness.privateKey,
			samlprotocol.SignatureRSASHA256,
		)
		if err != nil {
			t.Fatal(err)
		}
		parsedURL, _ := url.Parse(responseURL)
		assertOneConcurrentSLOSuccess(t, func() samlCallbackExchange {
			return invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
				Endpoint: samlplugin.EndpointSLO, Method: http.MethodGet,
				Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
				RawQuery: parsedURL.RawQuery,
			})
		})
	})

	t.Run("LogoutRequest", func(t *testing.T) {
		harness, _, _ := newSAMLSLOHarness(t, true)
		_ = establishSAMLSLOSession(t, &harness, "direct", "request-race@corp.example.com")
		currentSLO := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/slo/" + samlCallbackProvider
		request, err := samlprotocol.NewLogoutRequest(samlprotocol.LogoutRequestOptions{
			ID: "_concurrent-request", Issuer: samlCallbackIDP, Destination: currentSLO,
			NameID: "request-race@corp.example.com", SessionIndex: "_session",
			IssueInstant: samlCallbackNow,
		})
		if err != nil {
			t.Fatal(err)
		}
		requestURL, err := samlprotocol.BuildRedirectURL(
			t.Context(), currentSLO, samlprotocol.SAMLRequestParameter,
			request.XML, "/race-complete", harness.privateKey,
			samlprotocol.SignatureRSASHA256,
		)
		if err != nil {
			t.Fatal(err)
		}
		parsedURL, _ := url.Parse(requestURL)
		assertOneConcurrentSLOSuccess(t, func() samlCallbackExchange {
			return invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
				Endpoint: samlplugin.EndpointSLO, Method: http.MethodGet,
				Route:    "/sso/saml2/sp/slo/" + samlCallbackProvider,
				RawQuery: parsedURL.RawQuery,
			})
		})
		assertSAMLCallbackRows(t, harness.adapter, 1, 1, 0)
	})
}

func TestSAMLPersistedMetadataOnlyProviderSingleLogout(t *testing.T) {
	harness, _, _ := newSAMLSLOHarnessMode(t, true, true)
	cookieHeader := establishSAMLSLOSession(t, &harness, "direct", "persisted-slo@corp.example.com")
	body, _ := json.Marshal(map[string]any{"callbackURL": "/persisted-complete"})
	result := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
		Endpoint: samlplugin.EndpointInitiateSLO, Method: http.MethodPost,
		Route: "/sso/saml2/logout/" + samlCallbackProvider,
		Body:  body, ContentType: "application/json", Cookie: cookieHeader,
	})
	if result.status != http.StatusFound || !strings.HasPrefix(headerValue(result.headers, "Location"), samlTestIDPSLO+"?") {
		t.Fatalf("persisted initiate status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
	}
}

func TestSAMLRegularSignOutCleansSessionIndexes(t *testing.T) {
	harness, _, _ := newSAMLSLOHarness(t, false)
	cookieHeader := establishSAMLSLOSession(t, &harness, "direct", "sign-out@corp.example.com")
	assertSAMLSessionRecords(t, &harness, "sign-out@corp.example.com", true)
	result := invokeSAMLSLO(t, harness.auth, "direct", samlSLOInvocation{
		Endpoint: "signOut", Method: http.MethodPost, Route: "/sign-out",
		Body: []byte(`{}`), ContentType: "application/json", Cookie: cookieHeader,
	})
	if result.status != http.StatusOK {
		t.Fatalf("sign-out status=%d body=%s", result.status, result.body)
	}
	assertSAMLSessionRecords(t, &harness, "sign-out@corp.example.com", false)
}

func assertOneConcurrentSLOSuccess(t *testing.T, invoke func() samlCallbackExchange) {
	t.Helper()
	const callers = 20
	results := make(chan samlCallbackExchange, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results <- invoke()
		}()
	}
	waitGroup.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result.status == http.StatusFound {
			successes++
			continue
		}
		if result.status != http.StatusBadRequest {
			t.Fatalf("concurrent status=%d body=%s", result.status, result.body)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successes=%d, want 1", successes)
	}
}

func newSAMLSLOHarness(t *testing.T, requireInboundSignatures bool) (samlCallbackHarness, *rsa.PrivateKey, *x509.Certificate) {
	return newSAMLSLOHarnessMode(t, requireInboundSignatures, false)
}

func newSAMLSLOHarnessMode(t *testing.T, requireInboundSignatures, persisted bool) (samlCallbackHarness, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	spKey, spCertificate := newSAMLCallbackKeyPair(t)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(spKey),
	})
	harness := newSAMLCallbackHarnessWithOptions(t, func(config *samlplugin.SAMLConfig) {
		config.IDPMetadata = &samlplugin.SAMLIDPMetadata{
			Metadata: sloIDPMetadata(t, config.Certificate), EntityID: samlCallbackIDP,
		}
		config.SPMetadata = &samlplugin.SAMLSPMetadata{
			EntityID: samlCallbackSP, PrivateKey: string(privateKeyPEM),
		}
		config.SignatureAlgorithm = samlprotocol.SignatureRSASHA256
	}, func(_ *singleauth.Options, options *samlplugin.Options) {
		options.SAML.EnableSingleLogout = true
		options.SAML.WantLogoutRequestSigned = requireInboundSignatures
		options.SAML.WantLogoutResponseSigned = requireInboundSignatures
		if persisted {
			options.DefaultSSO = nil
		}
	})
	if persisted {
		persistSAMLMetadataProvider(t, &harness, harness.config)
	}
	return harness, spKey, spCertificate
}

func sloIDPMetadata(t *testing.T, certificatePEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		t.Fatal("invalid test IdP certificate")
	}
	certificate := base64.StdEncoding.EncodeToString(block.Bytes)
	return `<md:EntityDescriptor xmlns:md="` + samlprotocol.MetadataNamespace + `" entityID="` + samlCallbackIDP + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="` + samlprotocol.ProtocolNamespace + `">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="` + samlprotocol.XMLDSigNamespace + `"><ds:X509Data><ds:X509Certificate>` + certificate + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleLogoutService Binding="` + samlprotocol.HTTPPostBinding + `" Location="` + samlTestIDPSLO + `"/>` +
		`<md:SingleLogoutService Binding="` + samlprotocol.HTTPRedirectBinding + `" Location="` + samlTestIDPSLO + `"/>` +
		`<md:SingleSignOnService Binding="` + samlprotocol.HTTPRedirectBinding + `" Location="https://idp.example.com/sso"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`
}

func establishSAMLSLOSession(t *testing.T, harness *samlCallbackHarness, transport, email string) string {
	t.Helper()
	relayState, requestID := startSAMLCallbackFlow(t, harness.auth, transport)
	response := harness.signedResponse(t, samlResponseFixture{
		AssertionID: "_slo-session-" + strings.ReplaceAll(transport, "/", "-"),
		RequestID:   requestID, Recipient: harness.config.CallbackURL,
		Audience: samlCallbackSP, Issuer: samlCallbackIDP, Email: email,
	})
	result := invokeSAMLCallback(t, harness.auth, transport, false, response, relayState)
	if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/dashboard" {
		t.Fatalf("callback status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
	}
	return cookies.ApplySetCookies("", result.headers.Values("Set-Cookie"))
}

func assertSAMLSessionRecords(t *testing.T, harness *samlCallbackHarness, nameID string, exists bool) {
	t.Helper()
	forwardKey := "saml-session:" + samlCallbackProvider + ":" + nameID
	forward, err := harness.auth.InternalAdapter().FindVerificationValue(t.Context(), forwardKey)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		if forward != nil {
			t.Fatalf("forward SAML session remains: %#v", forward)
		}
		return
	}
	if forward == nil || !strings.Contains(recordTestString(forward, "value"), `"sessionIndex":"_session"`) {
		t.Fatalf("forward SAML session=%#v", forward)
	}
	sessions, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "session"})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions=%#v error=%v", sessions, err)
	}
	sessionID := recordTestString(sessions[0], "id")
	reverse, err := harness.auth.InternalAdapter().FindVerificationValue(
		t.Context(), "saml-session-by-id:"+sessionID,
	)
	if err != nil || reverse == nil || recordTestString(reverse, "value") != forwardKey {
		t.Fatalf("reverse SAML session=%#v error=%v", reverse, err)
	}
}

func recordTestString(record storage.Record, key string) string {
	value, _ := record[key].(string)
	return value
}

type samlSLOInvocation struct {
	Endpoint    string
	Method      string
	Route       string
	RawQuery    string
	Body        []byte
	ContentType string
	Cookie      string
	Origin      string
	ProviderID  string
}

func invokeSAMLSLO(
	t *testing.T,
	auth *singleauth.Auth,
	transport string,
	input samlSLOInvocation,
) samlCallbackExchange {
	t.Helper()
	target := samlCallbackBaseURL + "/api/auth" + input.Route
	if input.RawQuery != "" {
		target += "?" + input.RawQuery
	}
	headers := contract.Headers{}
	for name, value := range map[string]string{
		"Content-Type": input.ContentType, "Cookie": input.Cookie, "Origin": input.Origin,
	} {
		if value != "" {
			headers.Add(name, value)
		}
	}
	switch transport {
	case "direct":
		providerID := input.ProviderID
		if providerID == "" {
			providerID = samlCallbackProvider
		}
		request := contract.NewRequest(input.Method, "/api/auth"+input.Route, contract.RequestOptions{
			Scheme: "http", Host: "localhost:3000", RawQuery: input.RawQuery,
			Headers: headers, Body: input.Body,
		})
		response, _ := auth.Invoke(input.Endpoint, engine.DirectInput{
			Request: request, Params: map[string]string{"providerId": providerID},
		})
		return samlCallbackExchange{status: response.Status(), headers: response.Headers(), body: response.Body()}
	case "net/http":
		request := httptest.NewRequest(input.Method, target, bytes.NewReader(input.Body))
		for _, field := range headers.Fields() {
			request.Header.Add(field.Name, field.Value)
		}
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		return samlCallbackExchange{status: recorder.Code, headers: contractHeaders(recorder.Header()), body: recorder.Body.Bytes()}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(input.Method)
		for _, field := range headers.Fields() {
			request.Header.Add(field.Name, field.Value)
		}
		request.SetRequestURI(target)
		request.SetBody(input.Body)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		responseHeaders := contract.Headers{}
		requestContext.Response.Header.VisitAll(func(key, value []byte) {
			responseHeaders.Add(string(key), string(value))
		})
		return samlCallbackExchange{
			status: requestContext.Response.StatusCode(), headers: responseHeaders,
			body: append([]byte(nil), requestContext.Response.Body()...),
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(input.Method, target, bytes.NewReader(input.Body))
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range headers.Fields() {
			request.Header.Add(field.Name, field.Value)
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
		return samlCallbackExchange{status: response.StatusCode, headers: contractHeaders(response.Header), body: body}
	default:
		t.Fatalf("unknown transport %q", transport)
		return samlCallbackExchange{}
	}
}
