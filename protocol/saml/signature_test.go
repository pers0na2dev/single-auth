package saml

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestVerifyResponseSignatures(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	_, wrongCertificate := testKeyPair(t)

	tests := []struct {
		name          string
		signResponse  bool
		signAssertion bool
		requirement   SignatureRequirement
	}{
		{name: "response satisfies any", signResponse: true},
		{name: "assertion satisfies any", signAssertion: true},
		{name: "response required", signResponse: true, requirement: SignatureResponse},
		{name: "assertion required", signAssertion: true, requirement: SignatureAssertion},
		{name: "both required", signResponse: true, signAssertion: true, requirement: SignatureBoth},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signedXML := signFixture(
				t,
				validResponseFixture(),
				privateKey,
				certificate,
				test.signResponse,
				test.signAssertion,
			)
			response, err := ParseResponse(signedXML)
			if err != nil {
				t.Fatal(err)
			}
			result, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
				Certificates: []*x509.Certificate{wrongCertificate, certificate},
				Requirement:  test.requirement,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.ResponseSigned != test.signResponse ||
				result.AssertionSigned != test.signAssertion {
				t.Fatalf("signature result = %+v", result)
			}
		})
	}
}

func TestVerifyResponseSignatureNegativeCases(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	_, wrongCertificate := testKeyPair(t)
	signedXML := signFixture(t, validResponseFixture(), privateKey, certificate, true, false)

	t.Run("unsigned response rejected by default", func(t *testing.T) {
		response, err := ParseResponse(validResponseFixture())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{}); !IsErrorCode(err, "SAML_SIGNATURE_MISSING") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong certificate", func(t *testing.T) {
		response, err := ParseResponse(signedXML)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates: []*x509.Certificate{wrongCertificate},
		}); !IsErrorCode(err, "SAML_SIGNATURE_INVALID") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("signed content tamper", func(t *testing.T) {
		tampered := bytes.Replace(
			signedXML,
			[]byte("user@example.com"),
			[]byte("attacker@evil.test"),
			1,
		)
		response, err := ParseResponse(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
		}); !IsErrorCode(err, "SAML_SIGNATURE_INVALID") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("reference must target signed element", func(t *testing.T) {
		tampered := bytes.Replace(signedXML, []byte(`URI="#_response"`), []byte(`URI="#other"`), 1)
		response, err := ParseResponse(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
		}); !IsErrorCode(err, "SAML_SIGNATURE_REFERENCE_INVALID") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("SHA-1 policy is applied before crypto", func(t *testing.T) {
		tampered := bytes.Replace(
			signedXML,
			[]byte(SignatureRSASHA256),
			[]byte(SignatureRSASHA1),
			1,
		)
		response, err := ParseResponse(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
			Algorithms: AlgorithmValidationOptions{
				OnDeprecated: DeprecatedReject,
			},
		}); !IsErrorCode(err, "SAML_DEPRECATED_ALGORITHM") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("digest allow-list", func(t *testing.T) {
		response, err := ParseResponse(signedXML)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
			Algorithms: AlgorithmValidationOptions{
				AllowedDigestAlgorithms: []string{DigestSHA512},
			},
		}); !IsErrorCode(err, "SAML_ALGORITHM_NOT_ALLOWED") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestSignatureCertificateValidityAndKeyInfo(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	signedXML := signFixture(t, validResponseFixture(), privateKey, certificate, true, false)

	t.Run("configured certificate validity ignored by default", func(t *testing.T) {
		response, err := ParseResponse(signedXML)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
			Now:          func() time.Time { return fixtureNow.Add(10 * 365 * 24 * time.Hour) },
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("certificate validity can be enforced", func(t *testing.T) {
		response, err := ParseResponse(signedXML)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates:             []*x509.Certificate{certificate},
			CheckCertificateValidity: true,
			Now:                      func() time.Time { return fixtureNow.Add(10 * 365 * 24 * time.Hour) },
		}); !IsErrorCode(err, "SAML_SIGNATURE_INVALID") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("signature without KeyInfo uses configured trust anchor", func(t *testing.T) {
		document, err := parseXML(signedXML, DefaultMaxResponseSize)
		if err != nil {
			t.Fatal(err)
		}
		signatures := descendantsByTag(document.Root(), "Signature")
		if len(signatures) != 1 {
			t.Fatalf("signatures = %d", len(signatures))
		}
		keyInfo := firstDirectChild(signatures[0], "KeyInfo", XMLDSigNamespace)
		if keyInfo == nil {
			t.Fatal("signed fixture missing KeyInfo")
		}
		signatures[0].RemoveChild(keyInfo)
		withoutKeyInfo, err := document.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		response, err := ParseResponse(withoutKeyInfo)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSignatureWrappingGuards(t *testing.T) {
	t.Parallel()
	privateKey, certificate := testKeyPair(t)
	signedXML := signFixture(t, validResponseFixture(), privateKey, certificate, true, false)

	duplicateID := strings.Replace(
		string(signedXML),
		`<saml:NameID>`,
		`<saml:NameID ID="_response">`,
		1,
	)
	if _, err := ParseResponse([]byte(duplicateID)); !IsErrorCode(err, "SAML_DUPLICATE_ID") {
		t.Fatalf("duplicate ID error = %v", err)
	}
	ambiguousID := strings.Replace(
		string(signedXML),
		`<saml:NameID>`,
		`<saml:NameID ID="_one" Id="_two">`,
		1,
	)
	if _, err := ParseResponse([]byte(ambiguousID)); !IsErrorCode(err, "SAML_AMBIGUOUS_ID") {
		t.Fatalf("ambiguous ID error = %v", err)
	}

	document, err := parseXML(signedXML, DefaultMaxResponseSize)
	if err != nil {
		t.Fatal(err)
	}
	signatures := directXMLDSigChildren(document.Root(), "Signature")
	if len(signatures) != 1 {
		t.Fatalf("signatures = %d", len(signatures))
	}
	document.Root().AddChild(signatures[0].Copy())
	duplicateSignatureXML, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	response, err := ParseResponse(duplicateSignatureXML)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResponseSignatures(response, SignatureVerificationOptions{
		Certificates: []*x509.Certificate{certificate},
	}); !IsErrorCode(err, "SAML_SIGNATURE_INVALID") {
		t.Fatalf("duplicate signature error = %v", err)
	}
}
