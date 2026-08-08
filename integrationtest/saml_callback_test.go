package singleauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	fiberframework "github.com/gofiber/fiber/v3"
	dsig "github.com/russellhaering/goxmldsig"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const (
	samlCallbackBaseURL  = "http://localhost:3000"
	samlCallbackProvider = "native-saml"
	samlCallbackIDP      = "https://idp.example.com/metadata"
	samlCallbackSP       = "https://sp.example.com/metadata"
)

var samlCallbackNow = time.Date(2026, time.August, 10, 8, 0, 0, 0, time.UTC)

type samlCallbackHarness struct {
	auth       *singleauth.Auth
	adapter    storage.TransactionAdapter
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate
	config     samlplugin.SAMLConfig
}

type samlCallbackExchange struct {
	status  int
	headers contract.Headers
	body    []byte
}

func TestSAMLUnauthenticatedGETHonorsConfiguredErrorURLAcrossTransports(t *testing.T) {
	const configuredErrorURL = "https://errors.example.test/sso-failure?source=saml"
	harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
		authOptions *singleauth.Options,
		_ *samlplugin.Options,
	) {
		authOptions.OnAPIError.ErrorURL = configuredErrorURL
	})
	assertRedirect := func(t *testing.T, status int, location string, setCookies []string) {
		t.Helper()
		parsed, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusFound || parsed.Scheme != "https" ||
			parsed.Host != "errors.example.test" || parsed.Path != "/sso-failure" ||
			parsed.Query().Get("source") != "saml" ||
			parsed.Query().Get("error") != "invalid_request" {
			t.Fatalf("status=%d location=%q", status, location)
		}
		if len(setCookies) != 0 {
			t.Fatalf("unauthenticated GET issued cookies: %#v", setCookies)
		}
	}

	t.Run("direct", func(t *testing.T) {
		route := "/sso/saml2/callback/" + samlCallbackProvider
		request := contract.NewRequest(http.MethodGet, "/api/auth"+route, contract.RequestOptions{
			Scheme: "http", Host: "localhost:3000",
		})
		response, err := harness.auth.Invoke(samlplugin.EndpointSAMLCallback, engine.DirectInput{
			Request: request, Params: map[string]string{"providerId": samlCallbackProvider},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertRedirect(t, response.Status(), headerValue(response.Headers(), "Location"),
			response.Headers().Values("Set-Cookie"))
	})
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			response := ssoOIDCExchange(t, harness.auth, transport, http.MethodGet,
				"/sso/saml2/callback/"+samlCallbackProvider, nil, make(map[string]string))
			assertRedirect(t, response.status, response.header.Get("Location"),
				response.header.Values("Set-Cookie"))
		})
	}
}

func TestSAMLCallbackSPInitiatedAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, nil)
			relayState, requestID := startSAMLCallbackFlow(t, harness.auth, transport)
			response := harness.signedResponse(t, samlResponseFixture{
				AssertionID: "_assertion-" + strings.ReplaceAll(transport, "/", "-"),
				RequestID:   requestID,
				Recipient:   harness.config.CallbackURL,
				Audience:    samlCallbackSP,
				Issuer:      samlCallbackIDP,
				Email:       "Alice@Corp.Example.com",
			})
			first := invokeSAMLCallback(t, harness.auth, transport, false, response, relayState)
			if first.status != http.StatusFound || headerValue(first.headers, "Location") != "/dashboard" {
				t.Fatalf("first callback status=%d location=%q body=%s", first.status, headerValue(first.headers, "Location"), first.body)
			}
			if len(first.headers.Values("Set-Cookie")) == 0 {
				t.Fatal("successful callback did not issue a session cookie")
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)

			replay := invokeSAMLCallback(t, harness.auth, transport, false, response, relayState)
			if replay.status != http.StatusFound {
				t.Fatalf("replay status=%d body=%s", replay.status, replay.body)
			}
			replayURL, err := url.Parse(headerValue(replay.headers, "Location"))
			if err != nil || replayURL.Query().Get("error") != "invalid_saml_response" {
				t.Fatalf("replay location=%q error=%v", headerValue(replay.headers, "Location"), err)
			}
			if len(replay.headers.Values("Set-Cookie")) != 0 {
				t.Fatal("replayed callback issued cookies")
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
		})
	}
}

func TestSAMLACSIdPInitiatedAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			override := func(config *samlplugin.SAMLConfig) {
				config.IDPInitiatedCallbackURL = "/idp-complete"
			}
			harness := newSAMLCallbackHarness(t, override)
			acsURL := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/acs/" + samlCallbackProvider
			response := harness.signedResponse(t, samlResponseFixture{
				AssertionID: "_idp-assertion-" + strings.ReplaceAll(transport, "/", "-"),
				Recipient:   acsURL,
				Audience:    samlCallbackSP,
				Issuer:      samlCallbackIDP,
				Email:       "idp@corp.example.com",
			})
			result := invokeSAMLCallback(t, harness.auth, transport, true, response, "https://evil.example/phish")
			if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/idp-complete" {
				t.Fatalf("ACS status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
			}
			if len(result.headers.Values("Set-Cookie")) == 0 {
				t.Fatal("successful ACS did not issue a session cookie")
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
		})
	}
}

func TestSAMLCallbackPersistedProviderAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
				_ *singleauth.Options,
				pluginOptions *samlplugin.Options,
			) {
				pluginOptions.DefaultSSO = nil
			})
			owner, err := harness.auth.InternalAdapter().CreateUser(t.Context(), storage.Record{
				"name": "Provider Owner", "email": "owner@corp.example.com", "emailVerified": true,
			})
			if err != nil {
				t.Fatal(err)
			}
			ownerID, _ := owner["id"].(string)
			encodedConfig, err := json.Marshal(harness.config)
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

			relayState, requestID := startSAMLCallbackFlow(t, harness.auth, transport)
			response := harness.signedResponse(t, samlResponseFixture{
				AssertionID: "_persisted-" + strings.ReplaceAll(transport, "/", "-"),
				RequestID:   requestID,
				Recipient:   harness.config.CallbackURL,
				Audience:    samlCallbackSP,
				Issuer:      samlCallbackIDP,
				Email:       "persisted-user@corp.example.com",
			})
			result := invokeSAMLCallback(t, harness.auth, transport, false, response, relayState)
			if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/dashboard" {
				t.Fatalf("callback status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
			}
			if len(result.headers.Values("Set-Cookie")) == 0 {
				t.Fatal("persisted-provider callback did not issue a session cookie")
			}
			assertSAMLCallbackRows(t, harness.adapter, 2, 1, 1)
		})
	}
}

func TestSAMLCallbackRejectsMalformedAndUntrustedResponsesAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			t.Run("invalid-signature", func(t *testing.T) {
				harness := newSAMLCallbackHarness(t, nil)
				relayState, requestID := startSAMLCallbackFlow(t, harness.auth, transport)
				response := harness.signedResponse(t, samlResponseFixture{
					AssertionID: "_tampered", RequestID: requestID,
					Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
					Issuer: samlCallbackIDP, Email: "alice@corp.example.com",
				})
				decoded, err := base64.StdEncoding.DecodeString(response)
				if err != nil {
					t.Fatal(err)
				}
				decoded = bytes.Replace(decoded, []byte("alice@corp.example.com"), []byte("mallory@evil.example"), 1)
				result := invokeSAMLCallback(t, harness.auth, transport, false, base64.StdEncoding.EncodeToString(decoded), relayState)
				if result.status != http.StatusBadRequest || len(result.headers.Values("Set-Cookie")) != 0 {
					t.Fatalf("tampered response status=%d cookies=%v body=%s", result.status, result.headers.Values("Set-Cookie"), result.body)
				}
				assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
			})

			t.Run("wrong-recipient", func(t *testing.T) {
				harness := newSAMLCallbackHarness(t, nil)
				relayState, requestID := startSAMLCallbackFlow(t, harness.auth, transport)
				response := harness.signedResponse(t, samlResponseFixture{
					AssertionID: "_wrong-recipient", RequestID: requestID,
					Recipient: "https://evil.example/acs", Audience: samlCallbackSP,
					Issuer: samlCallbackIDP, Email: "alice@corp.example.com",
				})
				result := invokeSAMLCallback(t, harness.auth, transport, false, response, relayState)
				location, err := url.Parse(headerValue(result.headers, "Location"))
				if result.status != http.StatusFound || err != nil || location.Query().Get("error") != "invalid_saml_response" {
					t.Fatalf("wrong-recipient status=%d location=%q error=%v", result.status, headerValue(result.headers, "Location"), err)
				}
				assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
			})
		})
	}
}

func TestSAMLCallbackConcurrentConsumeAndReplayAreOneTime(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, nil)
			relayState, requestID := startSAMLCallbackFlow(t, harness.auth, transport)
			response := harness.signedResponse(t, samlResponseFixture{
				AssertionID: "_concurrent-assertion", RequestID: requestID,
				Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
				Issuer: samlCallbackIDP, Email: "racer@corp.example.com",
			})

			const callers = 24
			results := make(chan samlCallbackExchange, callers)
			var waitGroup sync.WaitGroup
			for range callers {
				waitGroup.Add(1)
				go func() {
					defer waitGroup.Done()
					results <- invokeSAMLCallback(t, harness.auth, transport, false, response, relayState)
				}()
			}
			waitGroup.Wait()
			close(results)

			successes := 0
			locations := make(map[string]int)
			for result := range results {
				location := headerValue(result.headers, "Location")
				locations[location]++
				if result.status != http.StatusFound {
					t.Fatalf("concurrent callback status=%d body=%s", result.status, result.body)
				}
				if location == "/dashboard" {
					successes++
					continue
				}
				_, err := url.Parse(location)
				if err != nil {
					t.Fatalf("concurrent loser location=%q error=%v", location, err)
				}
			}
			if successes != 1 {
				t.Fatalf("successful callbacks=%d, want 1; locations=%v", successes, locations)
			}
			for location, count := range locations {
				if location == "/dashboard" {
					continue
				}
				parsed, _ := url.Parse(location)
				if parsed.Query().Get("error") != "invalid_saml_response" {
					t.Fatalf("concurrent loser location=%q count=%d", location, count)
				}
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
		})
	}
}

func TestSAMLACSConcurrentAssertionReplayIsOneTime(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
				config.IDPInitiatedCallbackURL = "/idp-complete"
			})
			acsURL := samlCallbackBaseURL + "/api/auth/sso/saml2/sp/acs/" + samlCallbackProvider
			response := harness.signedResponse(t, samlResponseFixture{
				AssertionID: "_concurrent-idp-assertion",
				Recipient:   acsURL,
				Audience:    samlCallbackSP,
				Issuer:      samlCallbackIDP,
				Email:       "idp-racer@corp.example.com",
			})

			const callers = 24
			results := make(chan samlCallbackExchange, callers)
			var waitGroup sync.WaitGroup
			for range callers {
				waitGroup.Add(1)
				go func() {
					defer waitGroup.Done()
					results <- invokeSAMLCallback(t, harness.auth, transport, true, response, "")
				}()
			}
			waitGroup.Wait()
			close(results)

			successes := 0
			replayed := 0
			for result := range results {
				location := headerValue(result.headers, "Location")
				if result.status != http.StatusFound {
					t.Fatalf("concurrent ACS status=%d body=%s", result.status, result.body)
				}
				if location == "/idp-complete" {
					successes++
					continue
				}
				parsed, err := url.Parse(location)
				if err == nil && parsed.Query().Get("error") == "replay_detected" {
					replayed++
					continue
				}
				t.Fatalf("concurrent ACS loser location=%q error=%v", location, err)
			}
			if successes != 1 || replayed != callers-1 {
				t.Fatalf("successful ACS=%d replayed=%d", successes, replayed)
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
		})
	}
}

func TestSAMLCallbackFailsClosedOnIssuerAudienceCertificateAndMalformedInput(t *testing.T) {
	for _, test := range []struct {
		name       string
		mutate     func(*testing.T, *samlCallbackHarness, *samlResponseFixture)
		response   func(*testing.T, *samlCallbackHarness, samlResponseFixture) string
		wantStatus int
		wantError  string
	}{
		{
			name: "issuer",
			mutate: func(_ *testing.T, _ *samlCallbackHarness, fixture *samlResponseFixture) {
				fixture.Issuer = "https://attacker.example/metadata"
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "audience",
			mutate: func(_ *testing.T, _ *samlCallbackHarness, fixture *samlResponseFixture) {
				fixture.Audience = "https://attacker.example/sp"
			},
			wantStatus: http.StatusFound,
			wantError:  "invalid_saml_response",
		},
		{
			name: "certificate",
			mutate: func(t *testing.T, harness *samlCallbackHarness, _ *samlResponseFixture) {
				harness.privateKey, harness.cert = newSAMLCallbackKeyPair(t)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "malformed-base64",
			response: func(_ *testing.T, _ *samlCallbackHarness, _ samlResponseFixture) string {
				return "%%%not-base64%%%"
			},
			wantStatus: http.StatusBadRequest,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newSAMLCallbackHarness(t, nil)
			relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
			fixture := samlResponseFixture{
				AssertionID: "_closed-" + test.name,
				RequestID:   requestID,
				Recipient:   harness.config.CallbackURL,
				Audience:    samlCallbackSP,
				Issuer:      samlCallbackIDP,
				Email:       "closed@corp.example.com",
			}
			if test.mutate != nil {
				test.mutate(t, &harness, &fixture)
			}
			response := ""
			if test.response != nil {
				response = test.response(t, &harness, fixture)
			} else {
				response = harness.signedResponse(t, fixture)
			}
			result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
			if result.status != test.wantStatus {
				t.Fatalf("status=%d, want %d body=%s", result.status, test.wantStatus, result.body)
			}
			if test.wantError != "" {
				parsed, err := url.Parse(headerValue(result.headers, "Location"))
				if err != nil || parsed.Query().Get("error") != test.wantError {
					t.Fatalf("location=%q error=%v", headerValue(result.headers, "Location"), err)
				}
			}
			if len(result.headers.Values("Set-Cookie")) != 0 {
				t.Fatal("rejected SAML response issued cookies")
			}
			assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
		})
	}
}

func TestSAMLCallbackDoesNotTrustAnUnverifiedDefaultProviderDomain(t *testing.T) {
	for _, providerNamedTrusted := range []bool{false, true} {
		name := "not-named-trusted"
		if providerNamedTrusted {
			name = "named-trusted"
		}
		t.Run(name, func(t *testing.T) {
			harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
				authOptions *singleauth.Options,
				pluginOptions *samlplugin.Options,
			) {
				pluginOptions.DomainVerification.Enabled = false
				if providerNamedTrusted {
					authOptions.Account.AccountLinking.TrustedProviders = []string{samlCallbackProvider}
				}
			})
			_, err := harness.auth.InternalAdapter().CreateUser(t.Context(), storage.Record{
				"name":          "Existing Local User",
				"email":         "existing@corp.example.com",
				"emailVerified": true,
			})
			if err != nil {
				t.Fatal(err)
			}

			relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
			response := harness.signedResponse(t, samlResponseFixture{
				AssertionID: "_unverified-domain-" + name,
				RequestID:   requestID,
				Recipient:   harness.config.CallbackURL,
				Audience:    samlCallbackSP,
				Issuer:      samlCallbackIDP,
				Email:       "existing@corp.example.com",
			})
			result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
			location, err := url.Parse(headerValue(result.headers, "Location"))
			if result.status != http.StatusFound || err != nil || location.Query().Get("error") != "account_not_linked" {
				t.Fatalf("callback status=%d location=%q error=%v", result.status, headerValue(result.headers, "Location"), err)
			}
			if len(result.headers.Values("Set-Cookie")) != 0 {
				t.Fatal("untrusted default provider issued a session cookie")
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 0, 0)
		})
	}
}

func TestSAMLCallbackSecureValidationDefaults(t *testing.T) {
	t.Run("signature-is-required", func(t *testing.T) {
		harness := newSAMLCallbackHarness(t, nil)
		relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
		response := harness.unsignedResponse(t, samlResponseFixture{
			AssertionID: "_unsigned-default", RequestID: requestID,
			Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
			Issuer: samlCallbackIDP, Email: "unsigned@corp.example.com",
		})
		result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
		if result.status != http.StatusBadRequest {
			t.Fatalf("unsigned response status=%d body=%s", result.status, result.body)
		}
		assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
	})

	t.Run("timestamps-are-optional-by-upstream-default", func(t *testing.T) {
		harness := newSAMLCallbackHarness(t, nil)
		relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
		response := harness.signedResponse(t, samlResponseFixture{
			AssertionID: "_timestamp-optional", RequestID: requestID,
			Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
			Issuer: samlCallbackIDP, Email: "optional-time@corp.example.com",
			OmitTimestamps: true,
		})
		result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
		if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/dashboard" {
			t.Fatalf("timestamp-optional status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
		}
		assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
	})

	t.Run("timestamps-can-be-required", func(t *testing.T) {
		harness := newSAMLCallbackHarnessWithOptions(t, nil, func(
			_ *singleauth.Options,
			pluginOptions *samlplugin.Options,
		) {
			pluginOptions.SAML.RequireTimestamps = true
		})
		relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
		response := harness.signedResponse(t, samlResponseFixture{
			AssertionID: "_timestamp-required", RequestID: requestID,
			Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
			Issuer: samlCallbackIDP, Email: "required-time@corp.example.com",
			OmitTimestamps: true,
		})
		result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
		if result.status != http.StatusBadRequest {
			t.Fatalf("timestamp-required status=%d body=%s", result.status, result.body)
		}
		assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
	})
}

type samlResponseFixture struct {
	AssertionID    string
	RequestID      string
	Recipient      string
	Audience       string
	Issuer         string
	Email          string
	OmitTimestamps bool
}

func newSAMLCallbackHarness(
	t *testing.T,
	override func(*samlplugin.SAMLConfig),
) samlCallbackHarness {
	return newSAMLCallbackHarnessWithOptions(t, override, nil)
}

func newSAMLCallbackHarnessWithOptions(
	t *testing.T,
	override func(*samlplugin.SAMLConfig),
	overrideOptions func(*singleauth.Options, *samlplugin.Options),
) samlCallbackHarness {
	t.Helper()
	privateKey, certificate := newSAMLCallbackKeyPair(t)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	config := samlplugin.SAMLConfig{
		Issuer:      samlCallbackSP,
		EntryPoint:  "https://idp.example.com/sso",
		Certificate: string(certificatePEM),
		CallbackURL: samlCallbackBaseURL + "/api/auth/sso/saml2/callback/" + samlCallbackProvider,
		IDPMetadata: &samlplugin.SAMLIDPMetadata{EntityID: samlCallbackIDP},
		SPMetadata:  &samlplugin.SAMLSPMetadata{EntityID: samlCallbackSP},
	}
	if override != nil {
		override(&config)
	}
	pluginOptions := samlplugin.Options{
		DefaultSSO: []samlplugin.DefaultProvider{{
			ProviderID: samlCallbackProvider, Domain: "corp.example.com", SAMLConfig: config,
		}},
		DomainVerification: samlplugin.DomainVerificationOptions{Enabled: true},
	}
	authOptions := singleauth.Options{
		BaseURL:          samlCallbackBaseURL,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Clock:            func() time.Time { return samlCallbackNow },
	}
	if overrideOptions != nil {
		overrideOptions(&authOptions, &pluginOptions)
	}
	factory := samlplugin.NewFactory(pluginOptions)
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
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithClock(func() time.Time { return samlCallbackNow }),
	)
	if err != nil {
		t.Fatal(err)
	}
	authOptions.Database = adapter
	authOptions.PluginFactories = []singleauth.PluginFactory{factory}
	auth, err := singleauth.New(authOptions)
	if err != nil {
		t.Fatal(err)
	}
	return samlCallbackHarness{
		auth: auth, adapter: adapter, privateKey: privateKey, cert: certificate, config: config,
	}
}

func startSAMLCallbackFlow(t *testing.T, auth *singleauth.Auth, transport string) (string, string) {
	relayState, requestID, _ := startSAMLCallbackFlowWithURL(t, auth, transport)
	return relayState, requestID
}

func startSAMLCallbackFlowWithURL(
	t *testing.T,
	auth *singleauth.Auth,
	transport string,
) (string, string, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"providerId":       samlCallbackProvider,
		"callbackURL":      "/dashboard",
		"errorCallbackURL": "/sso-error",
	})
	if err != nil {
		t.Fatal(err)
	}
	status, responseBody := invokeSAMLSignInResponse(t, auth, transport, body)
	if status != http.StatusOK {
		t.Fatalf("sign-in status=%d body=%s", status, responseBody)
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	relayState := parsed.Query().Get("RelayState")
	decoded, err := samlprotocol.DecodeRedirectMessage(parsed.Query().Get("SAMLRequest"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var request decodedAuthnRequest
	if err := xml.Unmarshal(decoded, &request); err != nil {
		t.Fatal(err)
	}
	if relayState == "" || request.ID == "" {
		t.Fatalf("relayState=%q requestID=%q", relayState, request.ID)
	}
	return relayState, request.ID, result.URL
}

func (h samlCallbackHarness) signedResponse(t *testing.T, fixture samlResponseFixture) string {
	t.Helper()
	notBefore := samlCallbackNow.Add(-time.Minute).Format(time.RFC3339Nano)
	notOnOrAfter := samlCallbackNow.Add(5 * time.Minute).Format(time.RFC3339Nano)
	conditionAttributes := ` NotBefore="` + notBefore + `" NotOnOrAfter="` + notOnOrAfter + `"`
	subjectConfirmationAttributes := ` NotOnOrAfter="` + notOnOrAfter + `"`
	if fixture.OmitTimestamps {
		conditionAttributes = ""
		subjectConfirmationAttributes = ""
	}
	requestAttributes := ""
	if fixture.RequestID != "" {
		requestAttributes = ` InResponseTo="` + fixture.RequestID + `"`
	}
	xmlValue := fmt.Sprintf(`<samlp:Response xmlns:samlp="%s" xmlns:saml="%s" ID="_response-%s" Version="2.0" IssueInstant="%s" Destination="%s"%s>
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>
  <saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject><saml:NameID>%s</saml:NameID><saml:SubjectConfirmation Method="%s"><saml:SubjectConfirmationData Recipient="%s"%s%s/></saml:SubjectConfirmation></saml:Subject>
    <saml:Conditions%s><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement SessionIndex="_session"/>
    <saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		samlprotocol.ProtocolNamespace, samlprotocol.AssertionNamespace,
		strings.TrimPrefix(fixture.AssertionID, "_"), samlCallbackNow.Add(-time.Minute).Format(time.RFC3339Nano),
		fixture.Recipient, requestAttributes, fixture.Issuer, samlprotocol.StatusSuccess,
		fixture.AssertionID, samlCallbackNow.Add(-time.Minute).Format(time.RFC3339Nano), fixture.Issuer,
		fixture.Email, samlprotocol.BearerConfirmation, fixture.Recipient, requestAttributes,
		subjectConfirmationAttributes, conditionAttributes, fixture.Audience, fixture.Email,
	)
	document := etree.NewDocument()
	if err := document.ReadFromString(xmlValue); err != nil {
		t.Fatal(err)
	}
	signingContext, err := dsig.NewSigningContext(h.privateKey, [][]byte{h.cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signingContext.SetSignatureMethod(samlprotocol.SignatureRSASHA256); err != nil {
		t.Fatal(err)
	}
	signed, err := signingContext.SignEnveloped(document.Root())
	if err != nil {
		t.Fatal(err)
	}
	document.SetRoot(signed)
	encoded, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func (h samlCallbackHarness) unsignedResponse(t *testing.T, fixture samlResponseFixture) string {
	t.Helper()
	signed, err := base64.StdEncoding.DecodeString(h.signedResponse(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	root := document.Root()
	for _, child := range root.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == samlprotocol.XMLDSigNamespace {
			root.RemoveChild(child)
		}
	}
	encoded, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func newSAMLCallbackKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "Native SAML callback test IdP"},
		NotBefore:    samlCallbackNow.Add(-24 * time.Hour),
		NotAfter:     samlCallbackNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, certificate
}

func invokeSAMLCallback(
	t *testing.T,
	auth *singleauth.Auth,
	transport string,
	acs bool,
	samlResponse string,
	relayState string,
) samlCallbackExchange {
	t.Helper()
	values := url.Values{"SAMLResponse": {samlResponse}}
	if relayState != "" {
		values.Set("RelayState", relayState)
	}
	body := []byte(values.Encode())
	endpointName := samlplugin.EndpointSAMLCallback
	route := "/sso/saml2/callback/" + samlCallbackProvider
	if acs {
		endpointName = samlplugin.EndpointSAMLACS
		route = "/sso/saml2/sp/acs/" + samlCallbackProvider
	}
	target := samlCallbackBaseURL + "/api/auth" + route
	switch transport {
	case "direct":
		request := contract.NewRequest(http.MethodPost, "/api/auth"+route, contract.RequestOptions{
			Scheme: "http", Host: "localhost:3000", Body: body,
			Headers: contract.NewHeaders(contract.HeaderField{
				Name: "Content-Type", Value: "application/x-www-form-urlencoded",
			}),
		})
		response, _ := auth.Invoke(endpointName, engine.DirectInput{
			Request: request, Params: map[string]string{"providerId": samlCallbackProvider},
		})
		return samlCallbackExchange{status: response.Status(), headers: response.Headers(), body: response.Body()}
	case "net/http":
		request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		return samlCallbackExchange{
			status: recorder.Code, headers: contractHeaders(recorder.Header()), body: recorder.Body.Bytes(),
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.Header.SetContentType("application/x-www-form-urlencoded")
		request.SetRequestURI(target)
		request.SetBody(body)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		headers := contract.Headers{}
		requestContext.Response.Header.VisitAll(func(key, value []byte) {
			headers.Add(string(key), string(value))
		})
		return samlCallbackExchange{
			status: requestContext.Response.StatusCode(), headers: headers,
			body: append([]byte(nil), requestContext.Response.Body()...),
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return samlCallbackExchange{
			status: response.StatusCode, headers: contractHeaders(response.Header), body: responseBody,
		}
	default:
		t.Fatalf("unknown transport %q", transport)
		return samlCallbackExchange{}
	}
}

func contractHeaders(input http.Header) contract.Headers {
	result := contract.Headers{}
	for name, values := range input {
		for _, value := range values {
			result.Add(name, value)
		}
	}
	return result
}

func headerValue(headers contract.Headers, name string) string {
	value, _ := headers.Get(name)
	return value
}

func assertSAMLCallbackRows(
	t *testing.T,
	adapter storage.TransactionAdapter,
	wantUsers int,
	wantAccounts int,
	wantSessions int,
) {
	t.Helper()
	for model, want := range map[string]int{
		"user": wantUsers, "account": wantAccounts, "session": wantSessions,
	} {
		rows, err := adapter.FindMany(context.Background(), storage.FindManyParams{Model: model})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != want {
			t.Fatalf("%s rows=%d, want %d: %#v", model, len(rows), want, rows)
		}
	}
}
