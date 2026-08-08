package saml

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	samlResponseBindingEntityID = "https://sp.example.com/metadata"
	samlResponseBindingACSURL   = "https://sp.example.com/sso/acs"
	samlResponseBindingOtherSP  = "https://other.example.com/metadata"
)

type samlResponseBindingErrorObservation struct {
	Status     string `json:"status"`
	StatusCode int    `json:"statusCode"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

type samlResponseBindingValue struct {
	Locations        []string `json:"locations,omitempty"`
	EmptyLocations   []string `json:"emptyLocations,omitempty"`
	InvalidLocations []string `json:"invalidLocations,omitempty"`
	Encrypted        *bool    `json:"encrypted,omitempty"`
	PlainEncrypted   *bool    `json:"plainEncrypted,omitempty"`
}

type samlResponseBindingObservation struct {
	ID     string                               `json:"id"`
	Suite  string                               `json:"suite"`
	Title  string                               `json:"title"`
	Result string                               `json:"result"`
	Error  *samlResponseBindingErrorObservation `json:"error"`
	Value  *samlResponseBindingValue            `json:"value"`
}

type samlResponseBindingVector struct {
	ID          string
	Suite       string
	Title       string
	Observation samlResponseBindingObservation
}

type samlResponseBindingOracle struct {
	Tests []samlResponseBindingVector
}

type samlResponseBindingAction func() (*samlResponseBindingValue, error)

func samlResponseBindingID(suite, title string) string {
	return samlCompatibilityKey(suite, title)
}

func samlResponseBindingString(value string) *string {
	return &value
}

func samlResponseBindingBool(value bool) *bool {
	return &value
}

func buildSAMLResponseBindingXML(
	audienceGroups [][]string,
	destination *string,
	recipient *string,
) []byte {
	var builder strings.Builder
	builder.WriteString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`)
	if destination != nil {
		builder.WriteString(` Destination="`)
		builder.WriteString(*destination)
		builder.WriteString(`"`)
	}
	builder.WriteString(`><saml:Assertion><saml:Subject><saml:NameID>user@example.com</saml:NameID><saml:SubjectConfirmation Method="`)
	builder.WriteString(BearerConfirmation)
	builder.WriteString(`"><saml:SubjectConfirmationData`)
	if recipient != nil {
		builder.WriteString(` Recipient="`)
		builder.WriteString(*recipient)
		builder.WriteString(`"`)
	}
	builder.WriteString(` NotOnOrAfter="2030-01-01T00:00:00.000Z" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions>`)
	for _, group := range audienceGroups {
		builder.WriteString(`<saml:AudienceRestriction>`)
		for _, audience := range group {
			builder.WriteString(`<saml:Audience>`)
			builder.WriteString(audience)
			builder.WriteString(`</saml:Audience>`)
		}
		builder.WriteString(`</saml:AudienceRestriction>`)
	}
	builder.WriteString(`</saml:Conditions></saml:Assertion></samlp:Response>`)
	return []byte(builder.String())
}

func validateSAMLResponseBindingCase(xmlData []byte, expectedAudiences ...string) error {
	if len(expectedAudiences) == 0 {
		expectedAudiences = []string{samlResponseBindingEntityID}
	}
	return ValidateResponseBindingXML(xmlData, ResponseBindingValidationOptions{
		ExpectedAudiences:  expectedAudiences,
		ExpectedRecipients: []string{samlResponseBindingACSURL},
	})
}

func samlResponseBindingCases() map[string]samlResponseBindingAction {
	validationSuite := "validateSAMLResponseBinding"
	metadataSuite := "getSAMLPostAssertionConsumerServiceUrls"
	encryptedSuite := "hasSAMLEncryptedAssertion"
	defaultDestination := samlResponseBindingString(samlResponseBindingACSURL)
	defaultRecipient := samlResponseBindingString(samlResponseBindingACSURL)

	return map[string]samlResponseBindingAction{
		samlResponseBindingID(validationSuite, "accepts an assertion addressed to this Service Provider"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingEntityID}}, defaultDestination, defaultRecipient,
			))
		},
		samlResponseBindingID(validationSuite, "accepts an explicitly configured audience alias"): func() (*samlResponseBindingValue, error) {
			const audienceAlias = "https://app.example.com/saml"
			return nil, validateSAMLResponseBindingCase(
				buildSAMLResponseBindingXML([][]string{{audienceAlias}}, defaultDestination, defaultRecipient),
				samlResponseBindingEntityID, audienceAlias,
			)
		},
		samlResponseBindingID(validationSuite, "accepts multiple audiences in one AudienceRestriction when one matches"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingOtherSP, samlResponseBindingEntityID}}, defaultDestination, defaultRecipient,
			))
		},
		samlResponseBindingID(validationSuite, "rejects an assertion with no AudienceRestriction"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{}, defaultDestination, defaultRecipient,
			))
		},
		samlResponseBindingID(validationSuite, "rejects an assertion whose AudienceRestriction does not include this Service Provider"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingOtherSP}}, defaultDestination, defaultRecipient,
			))
		},
		samlResponseBindingID(validationSuite, "rejects multiple AudienceRestriction conditions unless every condition matches"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingEntityID}, {samlResponseBindingOtherSP}}, defaultDestination, defaultRecipient,
			))
		},
		samlResponseBindingID(validationSuite, "rejects a bearer confirmation without Recipient"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingEntityID}}, defaultDestination, nil,
			))
		},
		samlResponseBindingID(validationSuite, "rejects a bearer Recipient for another Service Provider"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingEntityID}}, defaultDestination,
				samlResponseBindingString("https://other.example.com/sso/acs"),
			))
		},
		samlResponseBindingID(validationSuite, "rejects a response Destination for another Service Provider"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingEntityID}},
				samlResponseBindingString("https://other.example.com/sso/acs"), defaultRecipient,
			))
		},
		samlResponseBindingID(validationSuite, "accepts a response without Destination"): func() (*samlResponseBindingValue, error) {
			return nil, validateSAMLResponseBindingCase(buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingEntityID}}, nil, defaultRecipient,
			))
		},
		samlResponseBindingID(metadataSuite, "extracts only POST AssertionConsumerService locations from SP metadata"): func() (*samlResponseBindingValue, error) {
			metadata := []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:SPSSODescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" /><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/saml/redirect" /><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" /></md:SPSSODescriptor></md:EntityDescriptor>`)
			return &samlResponseBindingValue{Locations: PostAssertionConsumerServiceURLs(metadata)}, nil
		},
		samlResponseBindingID(metadataSuite, "returns no locations for empty or invalid metadata"): func() (*samlResponseBindingValue, error) {
			return &samlResponseBindingValue{
				EmptyLocations:   PostAssertionConsumerServiceURLs(nil),
				InvalidLocations: PostAssertionConsumerServiceURLs([]byte("<")),
			}, nil
		},
		samlResponseBindingID(encryptedSuite, "detects encrypted assertions without treating plain assertions as encrypted"): func() (*samlResponseBindingValue, error) {
			encrypted := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:EncryptedAssertion /></samlp:Response>`)
			plain := buildSAMLResponseBindingXML(
				[][]string{{samlResponseBindingEntityID}}, defaultDestination, defaultRecipient,
			)
			return &samlResponseBindingValue{
				Encrypted:      samlResponseBindingBool(HasEncryptedAssertion(encrypted)),
				PlainEncrypted: samlResponseBindingBool(HasEncryptedAssertion(plain)),
			}, nil
		},
	}
}

func TestSAMLResponseBindingBehavior(t *testing.T) {
	oracle := loadSAMLResponseBindingOracle(t)
	cases := samlResponseBindingCases()
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			action, exists := cases[samlResponseBindingID(vector.Suite, vector.Title)]
			if !exists {
				t.Fatalf("unhandled SAML response-binding ID %q", vector.ID)
			}
			value, err := action()
			actual := samlResponseBindingObservation{
				ID: vector.ID, Suite: vector.Suite, Title: vector.Title,
				Result: "success", Value: value,
			}
			if err != nil {
				actual.Result = "error"
				actual.Error = samlResponseBindingObservedError(err)
				actual.Value = nil
			}
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("SAML response-binding observation mismatch\nactual: %#v\nwant:   %#v", actual, vector.Observation)
			}
		})
	}
}

func samlResponseBindingObservedError(err error) *samlResponseBindingErrorObservation {
	result := &samlResponseBindingErrorObservation{Message: err.Error()}
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

func TestSAMLResponseBindingOracleInventoryHasNoUnhandledIDs(t *testing.T) {
	oracle := loadSAMLResponseBindingOracle(t)
	cases := samlResponseBindingCases()
	if len(cases) != 13 || len(oracle.Tests) != 13 {
		t.Fatalf("SAML response-binding inventory cases=%d oracle=%d", len(cases), len(oracle.Tests))
	}
	for _, vector := range oracle.Tests {
		key := samlResponseBindingID(vector.Suite, vector.Title)
		if _, exists := cases[key]; !exists {
			t.Fatalf("oracle ID has no executable Go case: %s", vector.ID)
		}
		delete(cases, key)
	}
	if len(cases) != 0 {
		t.Fatalf("executable Go cases missing from oracle: %#v", cases)
	}
}

func loadSAMLResponseBindingOracle(t *testing.T) samlResponseBindingOracle {
	t.Helper()
	return samlResponseBindingOracle{Tests: samlResponseBindingCasesData}
}
