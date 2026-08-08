package saml

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Compatibility cases cover the frozen reference implementation behavior.
func TestValidateSingleAssertionOracle(t *testing.T) {
	t.Parallel()
	encode := func(value string) string {
		return base64.StdEncoding.EncodeToString([]byte(value))
	}
	single := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="123"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`
	encrypted := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:EncryptedAssertion><xenc:EncryptedData>...</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`

	for name, xmlData := range map[string]string{
		"plain":            single,
		"encrypted":        encrypted,
		"no namespace":     `<Response><Assertion ID="123"/></Response>`,
		"alternate prefix": `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Assertion ID="123"/></saml2p:Response>`,
		"custom prefix":    `<custom:Response xmlns:custom="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:myprefix="urn:oasis:names:tc:SAML:2.0:assertion"><myprefix:Assertion ID="123"/></custom:Response>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateSingleAssertion(encode(xmlData)); err != nil {
				t.Fatalf("ValidateSingleAssertion() error = %v", err)
			}
		})
	}

	base64Value := encode(single)
	for name, wrapped := range map[string]string{
		"LF":     wrapEvery(base64Value, 76, "\n"),
		"CRLF":   wrapEvery(base64Value, 76, "\r\n"),
		"spaces": wrapEvery(base64Value, 20, " \t "),
	} {
		t.Run("wrapped "+name, func(t *testing.T) {
			if _, err := ValidateSingleAssertion(wrapped); err != nil {
				t.Fatalf("wrapped input rejected: %v", err)
			}
		})
	}

	rejections := []struct {
		name string
		xml  string
		code string
	}{
		{
			name: "none",
			xml:  `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status/></samlp:Response>`,
			code: "SAML_NO_ASSERTION",
		},
		{
			name: "two plain",
			xml:  `<Response><Assertion ID="one"/><Assertion ID="two"/></Response>`,
			code: "SAML_MULTIPLE_ASSERTIONS",
		},
		{
			name: "two encrypted",
			xml:  `<Response><EncryptedAssertion/><EncryptedAssertion/></Response>`,
			code: "SAML_MULTIPLE_ASSERTIONS",
		},
		{
			name: "mixed",
			xml:  `<Response><Assertion/><EncryptedAssertion/></Response>`,
			code: "SAML_MULTIPLE_ASSERTIONS",
		},
		{
			name: "extensions XSW",
			xml:  `<Response><Extensions><Assertion ID="attacker"/></Extensions><Assertion ID="legitimate"/></Response>`,
			code: "SAML_MULTIPLE_ASSERTIONS",
		},
		{
			name: "arbitrary wrapper XSW",
			xml:  `<Response><Wrapper><Assertion ID="attacker"/></Wrapper><Assertion ID="legitimate"/></Response>`,
			code: "SAML_MULTIPLE_ASSERTIONS",
		},
		{
			name: "deep XSW",
			xml:  `<Response><One><Two><Assertion ID="attacker"/></Two></One><Assertion ID="legitimate"/></Response>`,
			code: "SAML_MULTIPLE_ASSERTIONS",
		},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateSingleAssertion(encode(test.xml))
			if !IsErrorCode(err, test.code) {
				t.Fatalf("error = %v, want code %s", err, test.code)
			}
		})
	}

	if _, err := ValidateSingleAssertion("not-valid-base64!!!"); !IsErrorCode(err, "SAML_INVALID_ENCODING") {
		t.Fatalf("invalid base64 error = %v", err)
	}
	if _, err := ValidateSingleAssertion(encode("this is not xml at all")); !IsErrorCode(err, "SAML_INVALID_ENCODING") {
		t.Fatalf("non-XML error = %v", err)
	}
}

func TestCountAssertionsOracle(t *testing.T) {
	t.Parallel()
	counts, err := CountAssertions([]byte(
		`<Response><Assertion/><EncryptedAssertion/></Response>`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if counts.Assertions != 1 || counts.EncryptedAssertions != 1 || counts.Total != 2 {
		t.Fatalf("counts = %+v", counts)
	}
	counts, err = CountAssertions([]byte(
		`<EntityDescriptor><SPSSODescriptor><AssertionConsumerService/></SPSSODescriptor></EntityDescriptor>`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if counts.Total != 0 {
		t.Fatalf("AssertionConsumerService counted as assertion: %+v", counts)
	}
}

func TestXMLStructuralGuards(t *testing.T) {
	t.Parallel()
	for name, xmlData := range map[string]string{
		"doctype": `<!DOCTYPE Response><Response><Assertion/></Response>`,
		"entity":  `<!ENTITY x "value"><Response><Assertion/></Response>`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CountAssertions([]byte(xmlData))
			if !IsErrorCode(err, "SAML_INVALID_XML") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func wrapEvery(value string, size int, separator string) string {
	var builder strings.Builder
	for len(value) > size {
		builder.WriteString(value[:size])
		builder.WriteString(separator)
		value = value[size:]
	}
	builder.WriteString(value)
	return builder.String()
}
