package saml

import (
	"strings"
	"testing"
)

const encryptedAssertionFixture = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
      </xenc:EncryptedKey></ds:KeyInfo>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

const deprecatedEncryptionFixture = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
      </xenc:EncryptedKey></ds:KeyInfo>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

// Compatibility cases cover the frozen reference implementation behavior.
func TestValidateResponseAlgorithmsOracle(t *testing.T) {
	t.Parallel()
	plain := []byte(`<Response><Assertion/></Response>`)
	if err := ValidateResponseAlgorithms(SignatureRSASHA256, plain, AlgorithmValidationOptions{}); err != nil {
		t.Fatalf("secure signature rejected: %v", err)
	}

	var warnings []string
	err := ValidateResponseAlgorithms(SignatureRSASHA1, plain, AlgorithmValidationOptions{
		Warn: func(message string) { warnings = append(warnings, message) },
	})
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "SAML Security Warning") {
		t.Fatalf("default SHA-1 warning = %v, warnings = %v", err, warnings)
	}
	if err := ValidateResponseAlgorithms(SignatureRSASHA1, plain, AlgorithmValidationOptions{
		OnDeprecated: DeprecatedReject,
	}); !IsErrorCode(err, "SAML_DEPRECATED_ALGORITHM") {
		t.Fatalf("SHA-1 reject error = %v", err)
	}
	warnings = nil
	if err := ValidateResponseAlgorithms(SignatureRSASHA1, plain, AlgorithmValidationOptions{
		OnDeprecated: DeprecatedAllow,
		Warn:         func(message string) { warnings = append(warnings, message) },
	}); err != nil || len(warnings) != 0 {
		t.Fatalf("SHA-1 allow = %v, warnings = %v", err, warnings)
	}
	if err := ValidateResponseAlgorithms(SignatureRSASHA256, plain, AlgorithmValidationOptions{
		AllowedSignatureAlgorithms: []string{SignatureRSASHA512},
	}); !IsErrorCode(err, "SAML_ALGORITHM_NOT_ALLOWED") {
		t.Fatalf("signature allow-list error = %v", err)
	}
	if err := ValidateResponseAlgorithms("", plain, AlgorithmValidationOptions{}); err != nil {
		t.Fatalf("empty signature algorithm rejected: %v", err)
	}
	if err := ValidateResponseAlgorithms("https://example.com/unknown", plain, AlgorithmValidationOptions{}); !IsErrorCode(err, "SAML_UNKNOWN_ALGORITHM") {
		t.Fatalf("unknown signature error = %v", err)
	}

	if err := ValidateResponseAlgorithms(SignatureRSASHA256, []byte(encryptedAssertionFixture), AlgorithmValidationOptions{}); err != nil {
		t.Fatalf("secure encryption rejected: %v", err)
	}
	warnings = nil
	if err := ValidateResponseAlgorithms(SignatureRSASHA256, []byte(deprecatedEncryptionFixture), AlgorithmValidationOptions{
		Warn: func(message string) { warnings = append(warnings, message) },
	}); err != nil || len(warnings) != 2 {
		t.Fatalf("deprecated encryption warnings: err = %v, warnings = %v", err, warnings)
	}
	if err := ValidateResponseAlgorithms(SignatureRSASHA256, []byte(deprecatedEncryptionFixture), AlgorithmValidationOptions{
		OnDeprecated: DeprecatedReject,
	}); !IsErrorCode(err, "SAML_DEPRECATED_ALGORITHM") {
		t.Fatalf("deprecated encryption reject error = %v", err)
	}
	if err := ValidateResponseAlgorithms(SignatureRSASHA256, []byte("not XML"), AlgorithmValidationOptions{}); err != nil {
		t.Fatalf("malformed XML should defer to parser stage: %v", err)
	}
}

func TestValidateConfigAlgorithmsOracle(t *testing.T) {
	t.Parallel()
	accepted := []ConfigAlgorithms{
		{},
		{SignatureAlgorithm: SignatureRSASHA256},
		{SignatureAlgorithm: "rsa-sha256"},
		{SignatureAlgorithm: "sha256"},
		{DigestAlgorithm: DigestSHA256},
		{DigestAlgorithm: "sha256"},
	}
	for _, config := range accepted {
		if err := ValidateConfigAlgorithms(config, AlgorithmValidationOptions{}); err != nil {
			t.Fatalf("config %+v rejected: %v", config, err)
		}
	}

	rejected := []ConfigAlgorithms{
		{SignatureAlgorithm: "rsa-sha257"},
		{SignatureAlgorithm: "https://example.com/unknown"},
		{DigestAlgorithm: "sha257"},
		{DigestAlgorithm: "https://example.com/unknown"},
	}
	for _, config := range rejected {
		if err := ValidateConfigAlgorithms(config, AlgorithmValidationOptions{}); !IsErrorCode(err, "SAML_UNKNOWN_ALGORITHM") {
			t.Fatalf("config %+v error = %v", config, err)
		}
	}

	if err := ValidateConfigAlgorithms(
		ConfigAlgorithms{SignatureAlgorithm: "rsa-sha256"},
		AlgorithmValidationOptions{AllowedSignatureAlgorithms: []string{"rsa-sha256", "rsa-sha512"}},
	); err != nil {
		t.Fatalf("short signature allow-list rejected: %v", err)
	}
	if err := ValidateConfigAlgorithms(
		ConfigAlgorithms{DigestAlgorithm: "sha256"},
		AlgorithmValidationOptions{AllowedDigestAlgorithms: []string{"sha512"}},
	); !IsErrorCode(err, "SAML_ALGORITHM_NOT_ALLOWED") {
		t.Fatalf("digest allow-list error = %v", err)
	}
	if err := ValidateConfigAlgorithms(
		ConfigAlgorithms{SignatureAlgorithm: "rsa-sha1", DigestAlgorithm: "sha1"},
		AlgorithmValidationOptions{OnDeprecated: DeprecatedReject},
	); !IsErrorCode(err, "SAML_DEPRECATED_CONFIG_ALGORITHM") {
		t.Fatalf("deprecated config error = %v", err)
	}
}

func TestValidateDigestAlgorithm(t *testing.T) {
	t.Parallel()
	for _, algorithm := range []string{DigestSHA256, DigestSHA384, DigestSHA512} {
		if err := ValidateDigestAlgorithm(algorithm, AlgorithmValidationOptions{}); err != nil {
			t.Fatalf("digest %s rejected: %v", algorithm, err)
		}
	}
	if err := ValidateDigestAlgorithm("", AlgorithmValidationOptions{}); !IsErrorCode(err, "SAML_DIGEST_ALGORITHM_MISSING") {
		t.Fatalf("missing digest error = %v", err)
	}
	if err := ValidateDigestAlgorithm(DigestSHA1, AlgorithmValidationOptions{
		OnDeprecated: DeprecatedReject,
	}); !IsErrorCode(err, "SAML_DEPRECATED_ALGORITHM") {
		t.Fatalf("SHA-1 digest error = %v", err)
	}
}
