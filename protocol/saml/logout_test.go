package saml

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestLogoutRequestPOSTSignatureAndEnvelopeValidation(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	now := time.Date(2026, time.August, 10, 9, 0, 0, 0, time.UTC)
	request, err := NewLogoutRequest(LogoutRequestOptions{
		ID: "_logout-request", Issuer: "https://idp.example.com/metadata",
		Destination: "https://sp.example.com/slo", NameID: "user@example.com",
		SessionIndex: "_session", IssueInstant: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignXMLMessage(request.XML, XMLSigningOptions{
		Signer: privateKey, Certificates: []*x509.Certificate{certificate},
		SignatureAlgorithm: SignatureRSASHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLogoutRequest(signed, 0)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.NameID != "user@example.com" || len(parsed.SessionIndexes) != 1 ||
		parsed.SessionIndexes[0] != "_session" {
		t.Fatalf("parsed request=%+v", parsed)
	}
	options := LogoutValidationOptions{
		ExpectedIssuer:      "https://idp.example.com/metadata",
		ExpectedDestination: "https://sp.example.com/slo",
		RequireSignature:    true, Certificates: []*x509.Certificate{certificate},
		Now: func() time.Time { return now },
	}
	if err := ValidateLogoutRequest(t.Context(), parsed, false, options); err != nil {
		t.Fatal(err)
	}

	tamperedXML := bytes.Replace(signed, []byte("user@example.com"), []byte("attacker@evil.test"), 1)
	tampered, err := ParseLogoutRequest(tamperedXML, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLogoutRequest(t.Context(), tampered, false, options); !IsErrorCode(err, "SAML_SIGNATURE_INVALID") {
		t.Fatalf("tampered error=%v", err)
	}
}

func TestLogoutRedirectBindingAndResponseValidation(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	now := time.Date(2026, time.August, 10, 9, 0, 0, 0, time.UTC)
	response, err := NewLogoutResponse(LogoutResponseOptions{
		ID: "_logout-response", Issuer: "https://idp.example.com/metadata",
		Destination: "https://sp.example.com/slo", InResponseTo: "_logout-request",
		IssueInstant: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	location, err := BuildRedirectURL(
		t.Context(), "https://sp.example.com/slo", SAMLResponseParameter,
		response.XML, "/complete", privateKey, SignatureRSASHA256,
	)
	if err != nil {
		t.Fatal(err)
	}
	rawQuery := strings.SplitN(location, "?", 2)[1]
	message, err := ParseRedirectBinding(
		rawQuery, []crypto.PublicKey{certificate.PublicKey}, AlgorithmValidationOptions{}, 0,
	)
	if err != nil || !message.Signed || message.RelayState != "/complete" {
		t.Fatalf("message=%+v error=%v", message, err)
	}
	parsed, err := ParseLogoutResponse(message.XML, 0)
	if err != nil {
		t.Fatal(err)
	}
	options := LogoutValidationOptions{
		ExpectedIssuer:      "https://idp.example.com/metadata",
		ExpectedDestination: "https://sp.example.com/slo", RequireSignature: true,
		Certificates: []*x509.Certificate{certificate}, Now: func() time.Time { return now },
	}
	if err := ValidateLogoutResponse(t.Context(), parsed, message.Signed, options); err != nil {
		t.Fatal(err)
	}
	parsed.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	if parsed.StatusCode == StatusSuccess {
		t.Fatal("non-success status was normalized")
	}
}

func TestLogoutEnvelopeRejectsMalformedAndWrongTrustBoundary(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	now := time.Date(2026, time.August, 10, 9, 0, 0, 0, time.UTC)
	request, err := NewLogoutRequest(LogoutRequestOptions{
		ID: "_logout", Issuer: "https://idp.example.com/metadata",
		Destination: "https://sp.example.com/slo", NameID: "user@example.com",
		IssueInstant: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignXMLMessage(request.XML, XMLSigningOptions{Signer: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLogoutRequest(signed, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := LogoutValidationOptions{
		ExpectedIssuer:      "https://idp.example.com/metadata",
		ExpectedDestination: "https://sp.example.com/slo", RequireSignature: true,
		Certificates: []*x509.Certificate{certificate}, Now: func() time.Time { return now },
	}
	for _, test := range []struct {
		name string
		edit func(*LogoutValidationOptions)
		code string
	}{
		{name: "issuer", edit: func(options *LogoutValidationOptions) { options.ExpectedIssuer = "https://other-idp.example.com" }, code: "SAML_ISSUER_MISMATCH"},
		{name: "destination", edit: func(options *LogoutValidationOptions) {
			options.ExpectedDestination = "https://other-sp.example.com/slo"
		}, code: "SAML_DESTINATION_MISMATCH"},
		{name: "expired", edit: func(options *LogoutValidationOptions) {
			options.Now = func() time.Time { return now.Add(DefaultClockSkew + time.Second) }
		}, code: "SAML_ISSUE_INSTANT_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.edit(&options)
			if err := ValidateLogoutRequest(t.Context(), parsed, false, options); !IsErrorCode(err, test.code) {
				t.Fatalf("error=%v, want %s", err, test.code)
			}
		})
	}
	for _, malformed := range [][]byte{
		[]byte(`<Response/>`),
		[]byte(`<samlp:LogoutRequest xmlns:samlp="` + ProtocolNamespace + `" ID="_same"><Wrapper ID="_same"/></samlp:LogoutRequest>`),
		[]byte(`<!DOCTYPE x><samlp:LogoutRequest xmlns:samlp="` + ProtocolNamespace + `"/>`),
	} {
		if _, err := ParseLogoutRequest(malformed, 0); err == nil {
			t.Fatalf("malformed XML accepted: %s", malformed)
		}
	}
}
