package saml

import (
	"crypto/x509"
	"testing"
)

func TestSignAuthnRequestForPOSTBinding(t *testing.T) {
	t.Parallel()
	privateKey, certificate := testKeyPair(t)
	request, err := NewAuthnRequest(AuthnRequestOptions{
		ID:                          "_post-request",
		Destination:                 "https://idp.example.com/sso",
		AssertionConsumerServiceURL: fixtureRecipient,
		Issuer:                      fixtureAudience,
		IssueInstant:                fixtureNow,
		NameIDPolicyFormat:          "urn:test:nameid",
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignAuthnRequest(request, XMLSigningOptions{
		Signer:       privateKey,
		Certificates: []*x509.Certificate{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := parseXML(signed.XML, DefaultMaxResponseSize)
	if err != nil {
		t.Fatal(err)
	}
	root := document.Root()
	issuer := firstDirectChild(root, "Issuer", AssertionNamespace)
	signature := firstDirectChild(root, "Signature", XMLDSigNamespace)
	policy := firstDirectChild(root, "NameIDPolicy", ProtocolNamespace)
	if issuer == nil || signature == nil || policy == nil ||
		!(issuer.Index() < signature.Index() && signature.Index() < policy.Index()) {
		t.Fatalf("invalid AuthnRequest signature placement: %s", signed.XML)
	}
	info, err := inspectDirectSignature(root, AlgorithmValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !info.present || info.signatureAlgorithm != SignatureRSASHA256 {
		t.Fatalf("signature info = %+v", info)
	}
	if err := verifyElementSignature(root, []*x509.Certificate{certificate}, SignatureVerificationOptions{}); err != nil {
		t.Fatalf("signed AuthnRequest verification failed: %v", err)
	}

	if _, err := SignAuthnRequest(signed, XMLSigningOptions{
		Signer: privateKey,
	}); !IsErrorCode(err, "SAML_SIGNATURE_INVALID") {
		t.Fatalf("second signature error = %v", err)
	}
}

func TestSignAuthnRequestWithoutEmbeddedCertificate(t *testing.T) {
	t.Parallel()
	privateKey, certificate := testKeyPair(t)
	request, err := NewAuthnRequest(AuthnRequestOptions{
		ID:           "_post-request-no-key-info",
		Destination:  "https://idp.example.com/sso",
		Issuer:       fixtureAudience,
		IssueInstant: fixtureNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignAuthnRequest(request, XMLSigningOptions{Signer: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	document, err := parseXML(signed.XML, DefaultMaxResponseSize)
	if err != nil {
		t.Fatal(err)
	}
	signature := firstDirectChild(document.Root(), "Signature", XMLDSigNamespace)
	if signature == nil || firstDirectChild(signature, "KeyInfo", XMLDSigNamespace) != nil {
		t.Fatalf("unexpected KeyInfo: %s", signed.XML)
	}
	if err := verifyElementSignature(
		document.Root(),
		[]*x509.Certificate{certificate},
		SignatureVerificationOptions{},
	); err != nil {
		t.Fatal(err)
	}
}

func TestSignAuthnRequestWithECDSA(t *testing.T) {
	t.Parallel()
	privateKey, certificate := testECDSAKeyPair(t)
	request, err := NewAuthnRequest(AuthnRequestOptions{
		ID:           "_post-request-ecdsa",
		Destination:  "https://idp.example.com/sso",
		Issuer:       fixtureAudience,
		IssueInstant: fixtureNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignAuthnRequest(request, XMLSigningOptions{
		Signer:       privateKey,
		Certificates: []*x509.Certificate{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := parseXML(signed.XML, DefaultMaxResponseSize)
	if err != nil {
		t.Fatal(err)
	}
	info, err := inspectDirectSignature(document.Root(), AlgorithmValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.signatureAlgorithm != SignatureECDSASHA256 {
		t.Fatalf("signature algorithm = %s", info.signatureAlgorithm)
	}
	if err := verifyElementSignature(
		document.Root(),
		[]*x509.Certificate{certificate},
		SignatureVerificationOptions{},
	); err != nil {
		t.Fatal(err)
	}
}

func TestSignAuthnRequestPolicyAndKeyErrors(t *testing.T) {
	t.Parallel()
	privateKey, _ := testKeyPair(t)
	request, err := NewAuthnRequest(AuthnRequestOptions{
		ID:           "_post-request-errors",
		Destination:  "https://idp.example.com/sso",
		Issuer:       fixtureAudience,
		IssueInstant: fixtureNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignAuthnRequest(request, XMLSigningOptions{}); !IsErrorCode(err, "SAML_SIGNING_KEY_MISSING") {
		t.Fatalf("missing key error = %v", err)
	}
	if _, err := SignAuthnRequest(request, XMLSigningOptions{
		Signer:             privateKey,
		SignatureAlgorithm: SignatureRSASHA1,
		Algorithms: AlgorithmValidationOptions{
			OnDeprecated: DeprecatedReject,
		},
	}); !IsErrorCode(err, "SAML_DEPRECATED_ALGORITHM") {
		t.Fatalf("SHA-1 policy error = %v", err)
	}
	if _, err := SignAuthnRequest(request, XMLSigningOptions{
		Signer:             privateKey,
		SignatureAlgorithm: SignatureECDSASHA256,
	}); !IsErrorCode(err, "SAML_SIGNING_KEY_INVALID") {
		t.Fatalf("key/algorithm mismatch error = %v", err)
	}
}
