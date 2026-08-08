package saml

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const samlAssertionsSingleXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion ID="123">
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>`

const samlAssertionsEncryptedXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:EncryptedAssertion>
    <xenc:EncryptedData>...</xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>`

type samlAssertionsErrorObservation struct {
	Status     string `json:"status"`
	StatusCode int    `json:"statusCode"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

type samlAssertionsValue struct {
	Assertions          int `json:"assertions"`
	EncryptedAssertions int `json:"encryptedAssertions"`
	Total               int `json:"total"`
}

type samlAssertionsObservation struct {
	ID     string                          `json:"id"`
	Suite  string                          `json:"suite"`
	Title  string                          `json:"title"`
	Result string                          `json:"result"`
	Error  *samlAssertionsErrorObservation `json:"error"`
	Value  *samlAssertionsValue            `json:"value"`
}

type samlAssertionsVector struct {
	ID          string
	Suite       string
	Title       string
	Observation samlAssertionsObservation
}

type samlAssertionsOracle struct {
	Tests []samlAssertionsVector
}

type samlAssertionsAction func() (*samlAssertionsValue, error)

func samlAssertionsID(suite, title string) string {
	return samlCompatibilityKey(suite, title)
}

func samlAssertionsEncode(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func samlAssertionsValidateXML(value string) error {
	_, err := ValidateSingleAssertion(samlAssertionsEncode(value))
	return err
}

func samlAssertionsWrapEvery(value string, size int, separator string) string {
	var builder strings.Builder
	for len(value) > size {
		builder.WriteString(value[:size])
		builder.WriteString(separator)
		value = value[size:]
	}
	builder.WriteString(value)
	return builder.String()
}

func samlAssertionsCases() map[string]samlAssertionsAction {
	validSuite := "validateSingleAssertion > valid responses (exactly 1 assertion)"
	whitespaceSuite := "validateSingleAssertion > base64 whitespace handling"
	noAssertionsSuite := "validateSingleAssertion > no assertions"
	multipleSuite := "validateSingleAssertion > multiple assertions"
	xswSuite := "validateSingleAssertion > XSW attack patterns"
	namespaceSuite := "validateSingleAssertion > namespace handling"

	return map[string]samlAssertionsAction{
		samlAssertionsID(validSuite, "should accept response with single assertion"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(samlAssertionsSingleXML)
		},
		samlAssertionsID(validSuite, "should accept response with single encrypted assertion"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(samlAssertionsEncryptedXML)
		},
		samlAssertionsID(whitespaceSuite, "should accept base64 with embedded whitespace from line-wrapping IDPs"): func() (*samlAssertionsValue, error) {
			encoded := samlAssertionsEncode(samlAssertionsSingleXML)
			for _, wrapped := range []string{
				samlAssertionsWrapEvery(encoded, 76, "\n"),
				samlAssertionsWrapEvery(encoded, 76, "\r\n"),
				samlAssertionsWrapEvery(encoded, 20, " \t "),
			} {
				if _, err := ValidateSingleAssertion(wrapped); err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
		samlAssertionsID(noAssertionsSuite, "should reject response with no assertions"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`)
		},
		samlAssertionsID(multipleSuite, "should reject response with multiple unencrypted assertions"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="assertion1"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion><saml:Assertion ID="assertion2"><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`)
		},
		samlAssertionsID(multipleSuite, "should reject response with multiple encrypted assertions"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:EncryptedAssertion><xenc:EncryptedData>...</xenc:EncryptedData></saml:EncryptedAssertion><saml:EncryptedAssertion><xenc:EncryptedData>...</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`)
		},
		samlAssertionsID(multipleSuite, "should reject response with mixed assertion types"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="plain-assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion><saml:EncryptedAssertion><xenc:EncryptedData>...</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`)
		},
		samlAssertionsID(xswSuite, "should reject assertion injected in Extensions element"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><samlp:Extensions><saml:Assertion ID="injected-assertion"><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Extensions><saml:Assertion ID="legitimate-assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`)
		},
		samlAssertionsID(xswSuite, "should reject assertion wrapped in arbitrary element"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><Wrapper><saml:Assertion ID="wrapped-assertion"><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion></Wrapper><saml:Assertion ID="legitimate-assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`)
		},
		samlAssertionsID(xswSuite, "should reject deeply nested injected assertion"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><Level1><Level2><Level3><saml:Assertion ID="deep-injected"><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion></Level3></Level2></Level1><saml:Assertion ID="legitimate-assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`)
		},
		samlAssertionsID(namespaceSuite, "should handle assertion without namespace prefix"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<Response><Assertion ID="123"><Subject><NameID>user@example.com</NameID></Subject></Assertion></Response>`)
		},
		samlAssertionsID(namespaceSuite, "should handle assertion with saml2: prefix"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Assertion ID="123"><saml2:Subject><saml2:NameID>user@example.com</saml2:NameID></saml2:Subject></saml2:Assertion></saml2p:Response>`)
		},
		samlAssertionsID(namespaceSuite, "should handle assertion with custom prefix"): func() (*samlAssertionsValue, error) {
			return nil, samlAssertionsValidateXML(`<custom:Response xmlns:custom="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:myprefix="urn:oasis:names:tc:SAML:2.0:assertion"><myprefix:Assertion ID="123"><myprefix:Subject><myprefix:NameID>user@example.com</myprefix:NameID></myprefix:Subject></myprefix:Assertion></custom:Response>`)
		},
		samlAssertionsID("countAssertions", "should return separate counts for assertions and encrypted assertions"): func() (*samlAssertionsValue, error) {
			counts, err := CountAssertions([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="plain"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion><saml:EncryptedAssertion><xenc:EncryptedData>...</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`))
			return &samlAssertionsValue{
				Assertions: counts.Assertions, EncryptedAssertions: counts.EncryptedAssertions, Total: counts.Total,
			}, err
		},
		samlAssertionsID("countAssertions", "should not count AssertionConsumerService as assertion"): func() (*samlAssertionsValue, error) {
			counts, err := CountAssertions([]byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:SPSSODescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://example.com/acs"/></md:SPSSODescriptor></md:EntityDescriptor>`))
			return &samlAssertionsValue{
				Assertions: counts.Assertions, EncryptedAssertions: counts.EncryptedAssertions, Total: counts.Total,
			}, err
		},
		samlAssertionsID("error handling", "should reject invalid base64 input"): func() (*samlAssertionsValue, error) {
			_, err := ValidateSingleAssertion("not-valid-base64!!!")
			return nil, err
		},
		samlAssertionsID("error handling", "should reject non-XML content"): func() (*samlAssertionsValue, error) {
			_, err := ValidateSingleAssertion(samlAssertionsEncode("this is not xml at all"))
			return nil, err
		},
	}
}

func TestSAMLAssertionsBehavior(t *testing.T) {
	oracle := loadSAMLAssertionsOracle(t)
	cases := samlAssertionsCases()
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			action, exists := cases[samlAssertionsID(vector.Suite, vector.Title)]
			if !exists {
				t.Fatalf("unhandled SAML assertions ID %q", vector.ID)
			}
			value, err := action()
			actual := samlAssertionsObservation{
				ID: vector.ID, Suite: vector.Suite, Title: vector.Title,
				Result: "success", Value: value,
			}
			if err != nil {
				actual.Result = "error"
				actual.Error = samlAssertionsObservedError(err)
				actual.Value = nil
			}
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("SAML assertions observation mismatch\nactual: %#v\nwant:   %#v", actual, vector.Observation)
			}
		})
	}
}

func samlAssertionsObservedError(err error) *samlAssertionsErrorObservation {
	result := &samlAssertionsErrorObservation{Message: err.Error()}
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

func TestSAMLAssertionsOracleInventoryHasNoUnhandledIDs(t *testing.T) {
	oracle := loadSAMLAssertionsOracle(t)
	cases := samlAssertionsCases()
	if len(cases) != 17 || len(oracle.Tests) != 17 {
		t.Fatalf("SAML assertions inventory cases=%d oracle=%d", len(cases), len(oracle.Tests))
	}
	for _, vector := range oracle.Tests {
		key := samlAssertionsID(vector.Suite, vector.Title)
		if _, exists := cases[key]; !exists {
			t.Fatalf("oracle ID has no executable Go case: %s", vector.ID)
		}
		delete(cases, key)
	}
	if len(cases) != 0 {
		t.Fatalf("executable Go cases missing from oracle: %#v", cases)
	}
}

func loadSAMLAssertionsOracle(t *testing.T) samlAssertionsOracle {
	t.Helper()
	return samlAssertionsOracle{Tests: samlAssertionCases}
}
