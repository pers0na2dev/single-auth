package saml

import (
	"errors"
	"reflect"
	"testing"
)

const samlAlgorithmsEncryptedAssertionXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
        </xenc:EncryptedKey>
      </ds:KeyInfo>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

const samlAlgorithmsDeprecatedEncryptionXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
        </xenc:EncryptedKey>
      </ds:KeyInfo>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

const samlAlgorithmsPlainAssertionXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>test</saml:Subject>
  </saml:Assertion>
</samlp:Response>`

type samlAlgorithmsErrorObservation struct {
	Status     string `json:"status"`
	StatusCode int    `json:"statusCode"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

type samlAlgorithmsObservation struct {
	ID       string                          `json:"id"`
	Suite    string                          `json:"suite"`
	Title    string                          `json:"title"`
	Result   string                          `json:"result"`
	Error    *samlAlgorithmsErrorObservation `json:"error"`
	Warnings []string                        `json:"warnings"`
	Values   map[string]string               `json:"values"`
}

type samlAlgorithmsVector struct {
	ID          string
	Suite       string
	Title       string
	Observation samlAlgorithmsObservation
}

type samlAlgorithmsOracle struct {
	Tests []samlAlgorithmsVector
}

type samlAlgorithmsAction func() (map[string]string, error)

func samlAlgorithmsID(suite, title string) string {
	return samlCompatibilityKey(suite, title)
}

func samlAlgorithmsCases(warn func(string)) map[string]samlAlgorithmsAction {
	responseSignatureSuite := "validateSAMLAlgorithms > signature validation"
	responseEncryptionSuite := "validateSAMLAlgorithms > encryption validation"
	configSignatureSuite := "validateConfigAlgorithms > signature algorithm validation"
	configDigestSuite := "validateConfigAlgorithms > digest algorithm validation"
	configCombinedSuite := "validateConfigAlgorithms > combined validation"
	options := func() AlgorithmValidationOptions {
		return AlgorithmValidationOptions{Warn: warn}
	}

	return map[string]samlAlgorithmsAction{
		samlAlgorithmsID(responseSignatureSuite, "should accept secure signature algorithms"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms(SignatureRSASHA256, []byte(samlAlgorithmsPlainAssertionXML), options())
		},
		samlAlgorithmsID(responseSignatureSuite, "should warn by default for deprecated signature algorithms"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms(SignatureRSASHA1, []byte(samlAlgorithmsPlainAssertionXML), options())
		},
		samlAlgorithmsID(responseSignatureSuite, "should reject deprecated signature with onDeprecated: reject"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedReject
			return nil, ValidateResponseAlgorithms(SignatureRSASHA1, []byte(samlAlgorithmsPlainAssertionXML), configured)
		},
		samlAlgorithmsID(responseSignatureSuite, "should silently allow deprecated with onDeprecated: allow"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedAllow
			return nil, ValidateResponseAlgorithms(SignatureRSASHA1, []byte(samlAlgorithmsPlainAssertionXML), configured)
		},
		samlAlgorithmsID(responseSignatureSuite, "should enforce custom signature allow-list"): func() (map[string]string, error) {
			configured := options()
			configured.AllowedSignatureAlgorithms = []string{SignatureRSASHA512}
			return nil, ValidateResponseAlgorithms(SignatureRSASHA256, []byte(samlAlgorithmsPlainAssertionXML), configured)
		},
		samlAlgorithmsID(responseSignatureSuite, "should pass null/undefined sigAlg without error"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms("", []byte(samlAlgorithmsPlainAssertionXML), options())
		},
		samlAlgorithmsID(responseSignatureSuite, "should reject unknown signature algorithms"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms("http://example.com/unknown-algo", []byte(samlAlgorithmsPlainAssertionXML), options())
		},

		samlAlgorithmsID(responseEncryptionSuite, "should accept secure encryption algorithms"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms(SignatureRSASHA256, []byte(samlAlgorithmsEncryptedAssertionXML), options())
		},
		samlAlgorithmsID(responseEncryptionSuite, "should warn by default for deprecated encryption algorithms"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms(SignatureRSASHA256, []byte(samlAlgorithmsDeprecatedEncryptionXML), options())
		},
		samlAlgorithmsID(responseEncryptionSuite, "should reject deprecated encryption with onDeprecated: reject"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedReject
			return nil, ValidateResponseAlgorithms(SignatureRSASHA256, []byte(samlAlgorithmsDeprecatedEncryptionXML), configured)
		},
		samlAlgorithmsID(responseEncryptionSuite, "should skip encryption validation for plain assertions"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms(SignatureRSASHA256, []byte(samlAlgorithmsPlainAssertionXML), options())
		},
		samlAlgorithmsID(responseEncryptionSuite, "should handle malformed XML gracefully"): func() (map[string]string, error) {
			return nil, ValidateResponseAlgorithms(SignatureRSASHA256, []byte("not valid xml"), options())
		},

		samlAlgorithmsID("algorithm constants", "should export signature algorithm constants"): func() (map[string]string, error) {
			return map[string]string{
				"RSA_SHA256": SignatureRSASHA256,
				"RSA_SHA1":   SignatureRSASHA1,
			}, nil
		},
		samlAlgorithmsID("algorithm constants", "should export encryption algorithm constants"): func() (map[string]string, error) {
			return map[string]string{
				"RSA_OAEP":    KeyEncryptionRSAOAEP,
				"AES_256_GCM": DataEncryptionAES256GCM,
			}, nil
		},

		samlAlgorithmsID(configSignatureSuite, "should accept secure signature algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: SignatureRSASHA256}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should warn by default for deprecated signature algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: SignatureRSASHA1}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should reject deprecated signature with onDeprecated: reject"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedReject
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: SignatureRSASHA1}, configured)
		},
		samlAlgorithmsID(configSignatureSuite, "should silently allow deprecated with onDeprecated: allow"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedAllow
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: SignatureRSASHA1}, configured)
		},
		samlAlgorithmsID(configSignatureSuite, "should enforce custom signature allow-list"): func() (map[string]string, error) {
			configured := options()
			configured.AllowedSignatureAlgorithms = []string{SignatureRSASHA512}
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: SignatureRSASHA256}, configured)
		},
		samlAlgorithmsID(configSignatureSuite, "should reject unknown signature algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: "http://example.com/unknown-algo"}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should pass undefined signatureAlgorithm without error"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should accept short-form signature algorithm names"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: "rsa-sha256"}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should accept digest-style short-form for signature (backward compat)"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: "sha256"}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should reject typos in short-form signature algorithm names"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: "rsa-sha257"}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should warn for deprecated short-form signature algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: "rsa-sha1"}, options())
		},
		samlAlgorithmsID(configSignatureSuite, "should support short-form names in signature allow-list"): func() (map[string]string, error) {
			configured := options()
			configured.AllowedSignatureAlgorithms = []string{"rsa-sha256", "rsa-sha512"}
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{SignatureAlgorithm: "rsa-sha256"}, configured)
		},

		samlAlgorithmsID(configDigestSuite, "should accept secure digest algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: DigestSHA256}, options())
		},
		samlAlgorithmsID(configDigestSuite, "should warn by default for deprecated digest algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: DigestSHA1}, options())
		},
		samlAlgorithmsID(configDigestSuite, "should reject deprecated digest with onDeprecated: reject"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedReject
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: DigestSHA1}, configured)
		},
		samlAlgorithmsID(configDigestSuite, "should enforce custom digest allow-list"): func() (map[string]string, error) {
			configured := options()
			configured.AllowedDigestAlgorithms = []string{DigestSHA512}
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: DigestSHA256}, configured)
		},
		samlAlgorithmsID(configDigestSuite, "should reject unknown digest algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: "http://example.com/unknown-digest"}, options())
		},
		samlAlgorithmsID(configDigestSuite, "should accept short-form digest algorithm names"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: "sha256"}, options())
		},
		samlAlgorithmsID(configDigestSuite, "should reject typos in short-form digest algorithm names"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: "sha257"}, options())
		},
		samlAlgorithmsID(configDigestSuite, "should warn for deprecated short-form digest algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: "sha1"}, options())
		},
		samlAlgorithmsID(configDigestSuite, "should support short-form names in digest allow-list"): func() (map[string]string, error) {
			configured := options()
			configured.AllowedDigestAlgorithms = []string{"sha256", "sha512"}
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{DigestAlgorithm: "sha256"}, configured)
		},

		samlAlgorithmsID(configCombinedSuite, "should validate both signature and digest algorithms"): func() (map[string]string, error) {
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{
				SignatureAlgorithm: SignatureRSASHA256,
				DigestAlgorithm:    DigestSHA256,
			}, options())
		},
		samlAlgorithmsID(configCombinedSuite, "should reject if signature is deprecated even if digest is secure"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedReject
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{
				SignatureAlgorithm: SignatureRSASHA1,
				DigestAlgorithm:    DigestSHA256,
			}, configured)
		},
		samlAlgorithmsID(configCombinedSuite, "should reject if digest is deprecated even if signature is secure"): func() (map[string]string, error) {
			configured := options()
			configured.OnDeprecated = DeprecatedReject
			return nil, ValidateConfigAlgorithms(ConfigAlgorithms{
				SignatureAlgorithm: SignatureRSASHA256,
				DigestAlgorithm:    DigestSHA1,
			}, configured)
		},
	}
}

func TestSAMLAlgorithmsBehavior(t *testing.T) {
	oracle := loadSAMLAlgorithmsOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			warnings := make([]string, 0)
			cases := samlAlgorithmsCases(func(message string) {
				warnings = append(warnings, message)
			})
			action, exists := cases[samlAlgorithmsID(vector.Suite, vector.Title)]
			if !exists {
				t.Fatalf("unhandled SAML algorithms ID %q", vector.ID)
			}
			values, err := action()
			actual := samlAlgorithmsObservation{
				ID: vector.ID, Suite: vector.Suite, Title: vector.Title,
				Result: "success", Warnings: warnings, Values: values,
			}
			if err != nil {
				actual.Result = "error"
				actual.Error = samlAlgorithmsObservedError(err)
			}
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("SAML algorithms observation mismatch\nactual: %#v\nwant:   %#v", actual, vector.Observation)
			}
		})
	}
}

func samlAlgorithmsObservedError(err error) *samlAlgorithmsErrorObservation {
	result := &samlAlgorithmsErrorObservation{Message: err.Error()}
	var apiError *APIError
	if errors.As(err, &apiError) {
		result.Status = apiError.Status
		result.StatusCode = apiError.StatusCode
		if code, ok := apiError.Body["code"].(string); ok {
			result.Code = code
		}
		if message, ok := apiError.Body["message"].(string); ok {
			result.Message = message
		}
	}
	return result
}

func TestSAMLAlgorithmsOracleInventoryHasNoUnhandledIDs(t *testing.T) {
	oracle := loadSAMLAlgorithmsOracle(t)
	cases := samlAlgorithmsCases(func(string) {})
	if len(cases) != 38 || len(oracle.Tests) != 38 {
		t.Fatalf("SAML algorithms inventory cases=%d oracle=%d", len(cases), len(oracle.Tests))
	}
	for _, vector := range oracle.Tests {
		key := samlAlgorithmsID(vector.Suite, vector.Title)
		if _, exists := cases[key]; !exists {
			t.Fatalf("oracle ID has no executable Go case: %s", vector.ID)
		}
		delete(cases, key)
	}
	if len(cases) != 0 {
		t.Fatalf("executable Go cases missing from oracle: %#v", cases)
	}
}

func loadSAMLAlgorithmsOracle(t *testing.T) samlAlgorithmsOracle {
	t.Helper()
	return samlAlgorithmsOracle{Tests: samlAlgorithmCases}
}
