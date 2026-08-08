package saml

import (
	"context"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestBuildPOSTForm(t *testing.T) {
	t.Parallel()
	form, err := BuildPOSTForm(
		"https://idp.example.com/sso?tenant=a&next=\"quoted\"",
		SAMLRequestParameter,
		`base64\"/><script>alert(1)</script>`,
		`state\"><img src=x>`,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{
		`<script>alert(1)</script>`,
		`state\"><img src=x>`,
	} {
		if strings.Contains(form, unsafe) {
			t.Fatalf("form contains unescaped value %q: %s", unsafe, form)
		}
	}
	if !strings.Contains(form, `method="POST"`) ||
		!strings.Contains(form, `name="SAMLRequest"`) ||
		!strings.Contains(form, `name="RelayState"`) {
		t.Fatalf("form missing binding fields: %s", form)
	}
	for _, action := range []string{"javascript:alert(1)", "data:text/html,x", "/relative"} {
		if _, err := BuildPOSTForm(action, SAMLRequestParameter, "x", ""); !IsErrorCode(err, "SAML_POST_BINDING_LOCATION_INVALID") {
			t.Fatalf("action %q error = %v", action, err)
		}
	}
}

func TestAuthnRequest(t *testing.T) {
	t.Parallel()
	allowCreate := true
	request, err := NewAuthnRequest(AuthnRequestOptions{
		ID:                          "_fixed",
		Destination:                 "https://idp.example.com/sso?a=1&b=2",
		AssertionConsumerServiceURL: fixtureRecipient,
		Issuer:                      fixtureAudience,
		IssueInstant:                fixtureNow,
		NameIDPolicyFormat:          "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		AllowCreate:                 &allowCreate,
		ForceAuthn:                  true,
		IsPassive:                   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(request.XML); err != nil {
		t.Fatalf("AuthnRequest XML invalid: %v\n%s", err, request.XML)
	}
	root := document.Root()
	if request.ID != "_fixed" || root.Tag != "AuthnRequest" ||
		root.NamespaceURI() != ProtocolNamespace ||
		root.SelectAttrValue("Version", "") != "2.0" ||
		root.SelectAttrValue("ProtocolBinding", "") != HTTPPostBinding ||
		root.SelectAttrValue("Destination", "") != "https://idp.example.com/sso?a=1&b=2" ||
		root.SelectAttrValue("ForceAuthn", "") != "true" ||
		root.SelectAttrValue("IsPassive", "") != "true" {
		t.Fatalf("unexpected AuthnRequest: %s", request.XML)
	}
	issuer := firstDirectChild(root, "Issuer", AssertionNamespace)
	policy := firstDirectChild(root, "NameIDPolicy", ProtocolNamespace)
	if trimmedText(issuer) != fixtureAudience || policy == nil ||
		policy.SelectAttrValue("AllowCreate", "") != "true" {
		t.Fatalf("unexpected AuthnRequest children: %s", request.XML)
	}
	generated, err := NewAuthnRequest(AuthnRequestOptions{
		Destination: "https://idp.example.com/sso",
		Issuer:      fixtureAudience,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.ID) != 41 || !strings.HasPrefix(generated.ID, "_") {
		t.Fatalf("generated ID = %q", generated.ID)
	}
}

func TestRedirectBindingSignatureAndTamper(t *testing.T) {
	t.Parallel()
	privateKey, certificate := testKeyPair(t)
	request, err := NewAuthnRequest(AuthnRequestOptions{
		ID:           "_redirect",
		Destination:  "https://idp.example.com/sso",
		Issuer:       fixtureAudience,
		IssueInstant: fixtureNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	redirectURL, err := BuildRedirectURL(
		context.Background(),
		"https://idp.example.com/sso?tenant=one",
		SAMLRequestParameter,
		request.XML,
		"state~value",
		privateKey,
		"sha256",
	)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(parsedURL.RawQuery, "RelayState=state%7Evalue") {
		t.Fatalf("WHATWG query escaping mismatch: %s", parsedURL.RawQuery)
	}
	message, err := ParseRedirectBinding(
		parsedURL.RawQuery,
		PublicKeys([]*x509.Certificate{certificate}),
		AlgorithmValidationOptions{},
		DefaultMaxResponseSize,
	)
	if err != nil {
		t.Fatal(err)
	}
	if message.Parameter != SAMLRequestParameter || !message.Signed ||
		message.SigAlg != SignatureRSASHA256 || message.RelayState != "state~value" ||
		string(message.XML) != string(request.XML) {
		t.Fatalf("decoded message = %+v", message)
	}

	tampered := strings.Replace(parsedURL.RawQuery, "RelayState=state%7Evalue", "RelayState=evil", 1)
	if _, err := ParseRedirectBinding(
		tampered,
		PublicKeys([]*x509.Certificate{certificate}),
		AlgorithmValidationOptions{},
		DefaultMaxResponseSize,
	); !IsErrorCode(err, "SAML_SIGNATURE_INVALID") {
		t.Fatalf("tamper error = %v", err)
	}

	withoutSignature := parsedURL.RawQuery[:strings.LastIndex(parsedURL.RawQuery, "&Signature=")]
	if _, err := ParseRedirectBinding(
		withoutSignature,
		nil,
		AlgorithmValidationOptions{},
		DefaultMaxResponseSize,
	); !IsErrorCode(err, "SAML_REDIRECT_SIGNATURE_PARAMETERS_INVALID") {
		t.Fatalf("partial signature error = %v", err)
	}
	duplicate := parsedURL.RawQuery + "&SAMLRequest=duplicate"
	if _, err := ParseRedirectBinding(
		duplicate,
		PublicKeys([]*x509.Certificate{certificate}),
		AlgorithmValidationOptions{},
		DefaultMaxResponseSize,
	); !IsErrorCode(err, "SAML_REDIRECT_DUPLICATE_PARAMETER") {
		t.Fatalf("duplicate parameter error = %v", err)
	}
}

func TestRedirectBindingBoundsAndCancellation(t *testing.T) {
	t.Parallel()
	large := []byte("<Response>" + strings.Repeat("a", 4096) + "</Response>")
	encoded, err := EncodeRedirectMessage(large)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRedirectMessage(encoded, 128); !IsErrorCode(err, "SAML_RESPONSE_TOO_LARGE") {
		t.Fatalf("inflate bound error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildRedirectURL(
		ctx,
		"https://idp.example.com/sso",
		SAMLRequestParameter,
		[]byte("<AuthnRequest/>"),
		"",
		nil,
		"",
	); !IsErrorCode(err, "SAML_REQUEST_CANCELLED") {
		t.Fatalf("cancel error = %v", err)
	}

	request, err := NewAuthnRequest(AuthnRequestOptions{
		Destination:  "https://idp.example.com/sso",
		Issuer:       fixtureAudience,
		IssueInstant: time.Now(),
	})
	if err != nil || len(request.XML) == 0 {
		t.Fatalf("request = %+v, error = %v", request, err)
	}
}

func TestRedirectBindingECDSADefault(t *testing.T) {
	t.Parallel()
	privateKey, certificate := testECDSAKeyPair(t)
	redirectURL, err := BuildRedirectURL(
		context.Background(),
		"https://idp.example.com/sso",
		SAMLRequestParameter,
		[]byte("<AuthnRequest/>"),
		"",
		privateKey,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	message, err := ParseRedirectBinding(
		parsedURL.RawQuery,
		PublicKeys([]*x509.Certificate{certificate}),
		AlgorithmValidationOptions{},
		DefaultMaxResponseSize,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !message.Signed || message.SigAlg != SignatureECDSASHA256 {
		t.Fatalf("message = %+v", message)
	}
}
