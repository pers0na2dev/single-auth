package saml

import (
	"strings"
	"testing"
)

const otherAudience = "https://other.example.com/metadata"

// Compatibility cases cover the frozen reference implementation behavior.
func TestValidateResponseBindingOracle(t *testing.T) {
	t.Parallel()
	alias := "https://app.example.com/saml"
	missing := (*string)(nil)
	recipient := fixtureRecipient
	destination := fixtureRecipient
	otherRecipient := "https://other.example.com/sso/acs"

	tests := []struct {
		name              string
		audienceGroups    [][]string
		destination       *string
		recipient         *string
		expectedAudiences []string
		wantCode          string
	}{
		{
			name:              "addressed to SP",
			audienceGroups:    [][]string{{fixtureAudience}},
			destination:       &destination,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience},
		},
		{
			name:              "configured audience alias",
			audienceGroups:    [][]string{{alias}},
			destination:       &destination,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience, alias},
		},
		{
			name:              "one matching audience in group",
			audienceGroups:    [][]string{{otherAudience, fixtureAudience}},
			destination:       &destination,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience},
		},
		{
			name:              "no audience restriction",
			audienceGroups:    nil,
			destination:       &destination,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience},
			wantCode:          "SAML_AUDIENCE_MISSING",
		},
		{
			name:              "wrong audience",
			audienceGroups:    [][]string{{otherAudience}},
			destination:       &destination,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience},
			wantCode:          "SAML_AUDIENCE_MISMATCH",
		},
		{
			name:              "every restriction must match",
			audienceGroups:    [][]string{{fixtureAudience}, {otherAudience}},
			destination:       &destination,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience},
			wantCode:          "SAML_AUDIENCE_MISMATCH",
		},
		{
			name:              "missing recipient",
			audienceGroups:    [][]string{{fixtureAudience}},
			destination:       &destination,
			recipient:         missing,
			expectedAudiences: []string{fixtureAudience},
			wantCode:          "SAML_RECIPIENT_MISSING",
		},
		{
			name:              "wrong recipient",
			audienceGroups:    [][]string{{fixtureAudience}},
			destination:       &destination,
			recipient:         &otherRecipient,
			expectedAudiences: []string{fixtureAudience},
			wantCode:          "SAML_RECIPIENT_MISMATCH",
		},
		{
			name:              "wrong destination",
			audienceGroups:    [][]string{{fixtureAudience}},
			destination:       &otherRecipient,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience},
			wantCode:          "SAML_DESTINATION_MISMATCH",
		},
		{
			name:              "destination optional",
			audienceGroups:    [][]string{{fixtureAudience}},
			destination:       missing,
			recipient:         &recipient,
			expectedAudiences: []string{fixtureAudience},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := ParseResponse(buildBindingResponse(
				test.audienceGroups,
				test.destination,
				test.recipient,
			))
			if err != nil {
				t.Fatalf("ParseResponse() error = %v", err)
			}
			err = ValidateResponseBinding(response, ResponseBindingValidationOptions{
				ExpectedAudiences:  test.expectedAudiences,
				ExpectedRecipients: []string{fixtureRecipient},
			})
			if test.wantCode == "" && err != nil {
				t.Fatalf("ValidateResponseBinding() error = %v", err)
			}
			if test.wantCode != "" && !IsErrorCode(err, test.wantCode) {
				t.Fatalf("error = %v, want code %s", err, test.wantCode)
			}
		})
	}
}

func TestResponseBindingHelpersOracle(t *testing.T) {
	t.Parallel()
	metadata := []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:SPSSODescriptor>
  <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post"/>
  <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/saml/redirect"/>
  <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post"/>
</md:SPSSODescriptor></md:EntityDescriptor>`)
	locations := PostAssertionConsumerServiceURLs(metadata)
	if len(locations) != 1 || locations[0] != "https://sp.example.com/saml/post" {
		t.Fatalf("POST ACS locations = %v", locations)
	}
	if locations := PostAssertionConsumerServiceURLs([]byte("<")); len(locations) != 0 {
		t.Fatalf("invalid metadata locations = %v", locations)
	}
	encrypted := []byte(`<Response><EncryptedAssertion/></Response>`)
	if !HasEncryptedAssertion(encrypted) || HasEncryptedAssertion(buildBindingResponse(
		[][]string{{fixtureAudience}},
		stringPointer(fixtureRecipient),
		stringPointer(fixtureRecipient),
	)) {
		t.Fatal("encrypted assertion detection mismatch")
	}
}

func buildBindingResponse(
	audienceGroups [][]string,
	destination *string,
	recipient *string,
) []byte {
	var builder strings.Builder
	builder.WriteString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`)
	if destination != nil {
		builder.WriteString(` Destination="` + *destination + `"`)
	}
	builder.WriteString(`><saml:Assertion><saml:Subject><saml:NameID>user@example.com</saml:NameID><saml:SubjectConfirmation Method="`)
	builder.WriteString(BearerConfirmation)
	builder.WriteString(`"><saml:SubjectConfirmationData`)
	if recipient != nil {
		builder.WriteString(` Recipient="` + *recipient + `"`)
	}
	builder.WriteString(` NotOnOrAfter="2030-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions>`)
	for _, group := range audienceGroups {
		builder.WriteString(`<saml:AudienceRestriction>`)
		for _, audience := range group {
			builder.WriteString(`<saml:Audience>` + audience + `</saml:Audience>`)
		}
		builder.WriteString(`</saml:AudienceRestriction>`)
	}
	builder.WriteString(`</saml:Conditions></saml:Assertion></samlp:Response>`)
	return []byte(builder.String())
}

func stringPointer(value string) *string {
	return &value
}
