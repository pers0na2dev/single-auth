package singleauth_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const samlSmokeEntryPoint = "https://idp.example.com/saml2/sso"

type samlSmokeCaseDefinition struct {
	Title       string
	FactoryOnly bool
	Expected    samlSmokeObservation
}

type samlSmokeObservation struct {
	HasSSOExport  bool              `json:"hasSSOExport,omitempty"`
	SSOExportType string            `json:"ssoExportType,omitempty"`
	HasURL        bool              `json:"hasURL,omitempty"`
	Redirect      bool              `json:"redirect,omitempty"`
	PointsToIDP   bool              `json:"pointsToEntryPoint,omitempty"`
	HasRequest    bool              `json:"hasSAMLRequest,omitempty"`
	URL           *samlSmokeURL     `json:"url,omitempty"`
	Request       *samlSmokeRequest `json:"request,omitempty"`
}

type samlSmokeURL struct {
	Origin        string   `json:"origin"`
	Pathname      string   `json:"pathname"`
	QueryKeys     []string `json:"queryKeys"`
	HasRelayState bool     `json:"hasRelayState"`
}

type samlSmokeRequest struct {
	Root                        bool   `json:"root"`
	IDPresent                   bool   `json:"idPresent"`
	IssueInstantValid           bool   `json:"issueInstantValid"`
	Version                     string `json:"version"`
	Destination                 string `json:"destination"`
	AssertionConsumerServiceURL string `json:"assertionConsumerServiceURL"`
	ProtocolBinding             string `json:"protocolBinding"`
	Issuer                      string `json:"issuer"`
}

type decodedAuthnRequest struct {
	XMLName                     xml.Name `xml:"AuthnRequest"`
	ID                          string   `xml:"ID,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	Version                     string   `xml:"Version,attr"`
	Destination                 string   `xml:"Destination,attr"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string   `xml:"ProtocolBinding,attr"`
	Issuer                      string   `xml:"Issuer"`
}

func TestSAMLSSOSmokeBehavior(t *testing.T) {
	for _, scenario := range samlSmokeCases() {
		scenario := scenario
		t.Run(scenario.Title, func(t *testing.T) {
			if scenario.FactoryOnly {
				factoryType := reflect.TypeOf(samlplugin.NewFactory)
				actual := samlSmokeObservation{HasSSOExport: factoryType != nil}
				if factoryType != nil && factoryType.Kind() == reflect.Func {
					actual.SSOExportType = "function"
				}
				if !reflect.DeepEqual(actual, scenario.Expected) {
					t.Fatalf("Go SSO package observation=%#v, want %#v", actual, scenario.Expected)
				}
				return
			}

			options, body := samlSmokeCase(t, scenario.Title)
			for _, transport := range []string{"direct", "net/http", "fasthttp", "fiber"} {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					auth, err := singleauth.New(singleauth.Options{
						BaseURL:          "http://localhost:3000",
						Database:         memory.MustNew(),
						EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
						PluginFactories:  []singleauth.PluginFactory{samlplugin.NewFactory(options)},
						Clock: func() time.Time {
							return time.Date(2026, time.August, 9, 7, 30, 0, 0, time.UTC)
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					responseBody := invokeSAMLSignIn(t, auth, transport, body)
					actual := observeSAMLSignIn(t, responseBody)
					if !reflect.DeepEqual(actual, scenario.Expected) {
						t.Fatalf("%s SAML smoke observation=%#v, want %#v", transport, actual, scenario.Expected)
					}
				})
			}
		})
	}
}

func samlSmokeCase(t *testing.T, title string) (samlplugin.Options, []byte) {
	t.Helper()
	provider := samlplugin.DefaultProvider{
		ProviderID: "test-saml", Domain: "example.com",
		SAMLConfig: samlplugin.SAMLConfig{
			Issuer: "https://idp.example.com", EntryPoint: samlSmokeEntryPoint,
			Certificate: "single-auth-test-certificate",
			CallbackURL: "http://localhost:3000/api/auth/sso/saml2/callback/test-saml",
		},
	}
	body := map[string]any{"providerId": provider.ProviderID, "callbackURL": "/dashboard"}
	if strings.Contains(title, "email domain lookup") {
		provider = samlplugin.DefaultProvider{
			ProviderID: "domain-saml", Domain: "corp.example.com",
			SAMLConfig: samlplugin.SAMLConfig{
				Issuer: "https://idp.corp.example.com", EntryPoint: samlSmokeEntryPoint,
				Certificate: "single-auth-test-certificate",
				CallbackURL: "http://localhost:3000/api/auth/sso/saml2/callback/domain-saml",
			},
		}
		body = map[string]any{"email": "user@corp.example.com", "callbackURL": "/dashboard"}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return samlplugin.Options{DefaultSSO: []samlplugin.DefaultProvider{provider}}, encoded
}

func invokeSAMLSignIn(t *testing.T, auth *singleauth.Auth, transport string, body []byte) []byte {
	t.Helper()
	status, responseBody := invokeSAMLSignInResponse(t, auth, transport, body)
	if status != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", transport, status, responseBody)
	}
	return responseBody
}

func invokeSAMLSignInResponse(t *testing.T, auth *singleauth.Auth, transport string, body []byte) (int, []byte) {
	t.Helper()
	const target = "http://localhost:3000/api/auth/sign-in/sso"
	switch transport {
	case "direct":
		request := contract.NewRequest(http.MethodPost, "/api/auth/sign-in/sso", contract.RequestOptions{
			Scheme: "http", Host: "localhost:3000", Body: body,
			Headers: contract.NewHeaders(
				contract.HeaderField{Name: "Content-Type", Value: "application/json"},
				contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"},
			),
		})
		response, err := auth.Invoke("signInSSO", engine.DirectInput{Request: request})
		if err != nil && response.Status() == 0 {
			t.Fatal(err)
		}
		return response.Status(), response.Body()
	case "net/http":
		request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://localhost:3000")
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		return recorder.Code, append([]byte(nil), recorder.Body.Bytes()...)
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodPost)
		request.Header.SetContentType("application/json")
		request.Header.Set("Origin", "http://localhost:3000")
		request.SetRequestURI(target)
		request.SetBody(body)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		return requestContext.Response.StatusCode(), append([]byte(nil), requestContext.Response.Body()...)
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://localhost:3000")
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, encoded
	default:
		t.Fatalf("unknown transport %q", transport)
		return 0, nil
	}
}

func observeSAMLSignIn(t *testing.T, body []byte) samlSmokeObservation {
	t.Helper()
	var result struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	decoded, err := samlprotocol.DecodeRedirectMessage(query.Get("SAMLRequest"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var request decodedAuthnRequest
	if err := xml.Unmarshal(decoded, &request); err != nil {
		t.Fatal(err)
	}
	queryKeys := make([]string, 0, len(query))
	for key := range query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	_, instantErr := time.Parse(time.RFC3339Nano, request.IssueInstant)
	return samlSmokeObservation{
		HasURL: result.URL != "", Redirect: result.Redirect,
		PointsToIDP: strings.Contains(result.URL, samlSmokeEntryPoint),
		HasRequest:  strings.Contains(result.URL, "SAMLRequest"),
		URL: &samlSmokeURL{
			Origin: parsed.Scheme + "://" + parsed.Host, Pathname: parsed.Path,
			QueryKeys: queryKeys, HasRelayState: query.Has("RelayState"),
		},
		Request: &samlSmokeRequest{
			Root: request.XMLName.Local == "AuthnRequest", IDPresent: request.ID != "",
			IssueInstantValid: instantErr == nil, Version: request.Version,
			Destination:                 request.Destination,
			AssertionConsumerServiceURL: request.AssertionConsumerServiceURL,
			ProtocolBinding:             request.ProtocolBinding, Issuer: request.Issuer,
		},
	}
}

func samlSmokeCases() []samlSmokeCaseDefinition {
	return []samlSmokeCaseDefinition{
		{
			Title: "generates a SAML login request URL with the default provider",
			Expected: samlSmokeObservation{
				HasURL: true, Redirect: true, PointsToIDP: true, HasRequest: true,
				URL: &samlSmokeURL{
					Origin: "https://idp.example.com", Pathname: "/saml2/sso",
					QueryKeys: []string{"RelayState", "SAMLRequest"}, HasRelayState: true,
				},
				Request: &samlSmokeRequest{
					Root: true, IDPresent: true, IssueInstantValid: true, Version: "2.0",
					Destination:                 samlSmokeEntryPoint,
					AssertionConsumerServiceURL: "http://localhost:3000/api/auth/sso/saml2/callback/test-saml",
					ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Issuer:                      "https://idp.example.com",
				},
			},
		},
		{
			Title: "generates a SAML login request URL through email domain lookup",
			Expected: samlSmokeObservation{
				HasURL: true, Redirect: true, PointsToIDP: true, HasRequest: true,
				URL: &samlSmokeURL{
					Origin: "https://idp.example.com", Pathname: "/saml2/sso",
					QueryKeys: []string{"RelayState", "SAMLRequest"}, HasRelayState: true,
				},
				Request: &samlSmokeRequest{
					Root: true, IDPresent: true, IssueInstantValid: true, Version: "2.0",
					Destination:                 samlSmokeEntryPoint,
					AssertionConsumerServiceURL: "http://localhost:3000/api/auth/sso/saml2/callback/domain-saml",
					ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Issuer:                      "https://idp.corp.example.com",
				},
			},
		},
		{
			Title:       "exposes the SSO plugin factory from the Go package",
			FactoryOnly: true,
			Expected:    samlSmokeObservation{HasSSOExport: true, SSOExportType: "function"},
		},
	}
}
