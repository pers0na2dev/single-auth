package saml

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
)

// AssertionCounts reports plain and encrypted assertion elements anywhere in
// the document. Counting the complete tree prevents common XML signature
// wrapping layouts from smuggling an additional assertion into Extensions or
// an arbitrary wrapper.
type AssertionCounts struct {
	Assertions          int
	EncryptedAssertions int
	Total               int
}

// CountAssertions parses XML and counts every Assertion and
// EncryptedAssertion local name, matching the reference implementation's namespace-insensitive
// structural guard.
func CountAssertions(xmlData []byte) (AssertionCounts, error) {
	counts, err := countAssertions(xmlData, 0)
	if err != nil {
		return AssertionCounts{}, newAssertionBadRequest(
			"SAML_INVALID_XML",
			"Failed to parse SAML response XML",
			err,
		)
	}
	return counts, nil
}

func countAssertions(xmlData []byte, maxBytes int) (AssertionCounts, error) {
	document, err := parseXML(xmlData, maxBytes)
	if err != nil {
		return AssertionCounts{}, newError(
			"SAML_INVALID_XML",
			"Failed to parse SAML response XML",
			err,
		)
	}
	assertions := len(descendantsByTag(document.Root(), "Assertion"))
	encryptedAssertions := len(descendantsByTag(document.Root(), "EncryptedAssertion"))
	return AssertionCounts{
		Assertions:          assertions,
		EncryptedAssertions: encryptedAssertions,
		Total:               assertions + encryptedAssertions,
	}, nil
}

// DecodePOSTMessage removes line-wrapping whitespace and decodes one base64
// SAMLRequest or SAMLResponse value.
func DecodePOSTMessage(encoded string, maxDecodedBytes int) ([]byte, error) {
	if maxDecodedBytes <= 0 {
		maxDecodedBytes = DefaultMaxResponseSize
	}
	if len(encoded) > maxDecodedBytes*8+4096 {
		return nil, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", maxDecodedBytes),
		)
	}
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, encoded)
	if compact == "" {
		return nil, newError(
			"SAML_INVALID_ENCODING",
			"Invalid base64-encoded SAML response",
		)
	}
	if len(compact) > base64.StdEncoding.EncodedLen(maxDecodedBytes)+4 {
		return nil, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", maxDecodedBytes),
		)
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err != nil || len(decoded) == 0 || !strings.Contains(string(decoded), "<") {
		return nil, newError(
			"SAML_INVALID_ENCODING",
			"Invalid base64-encoded SAML response",
			err,
		)
	}
	if len(decoded) > maxDecodedBytes {
		return nil, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", maxDecodedBytes),
		)
	}
	return decoded, nil
}

// ValidateSingleAssertion applies the reference implementation's structural assertion guard to
// a base64 HTTP-POST binding value and returns the decoded XML.
func ValidateSingleAssertion(encoded string) ([]byte, error) {
	xmlData, err := decodeReferenceBase64SAML(encoded)
	if err != nil {
		return nil, newAssertionBadRequest(
			"SAML_INVALID_ENCODING",
			"Invalid base64-encoded SAML response",
			err,
		)
	}
	counts, err := CountAssertions(xmlData)
	if err != nil {
		return nil, err
	}
	switch {
	case counts.Total == 0:
		return nil, newAssertionBadRequest(
			"SAML_NO_ASSERTION",
			"SAML response contains no assertions",
		)
	case counts.Total > 1:
		return nil, newAssertionBadRequest(
			"SAML_MULTIPLE_ASSERTIONS",
			fmt.Sprintf(
				"SAML response contains %d assertions, expected exactly 1",
				counts.Total,
			),
		)
	default:
		return xmlData, nil
	}
}

func decodeReferenceBase64SAML(encoded string) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '\uFEFF' {
			return -1
		}
		return r
	}, encoded)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if strings.ContainsAny(compact, "-_") {
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	}
	decoded := make([]byte, 0, len(compact)*3/4)
	var buffer uint32
	bitsCollected := 0
	for _, character := range compact {
		if character == '=' {
			break
		}
		value := strings.IndexRune(alphabet, character)
		if value < 0 {
			return nil, fmt.Errorf("invalid Base64 character: %c", character)
		}
		buffer = buffer<<6 | uint32(value)
		bitsCollected += 6
		if bitsCollected >= 8 {
			bitsCollected -= 8
			decoded = append(decoded, byte(buffer>>bitsCollected&0xff))
		}
	}
	if !strings.Contains(string(decoded), "<") {
		return nil, fmt.Errorf("decoded SAML response is not XML")
	}
	return decoded, nil
}

func newAssertionBadRequest(code, message string, cause ...error) *APIError {
	err := newBadRequest(code, message, cause...)
	err.Body["code"] = code
	return err
}

func validateSingleAssertionXML(xmlData []byte) error {
	return validateSingleAssertionXMLWithLimit(xmlData, DefaultMaxResponseSize)
}

func validateSingleAssertionXMLWithLimit(xmlData []byte, maxBytes int) error {
	counts, err := countAssertions(xmlData, maxBytes)
	if err != nil {
		return err
	}
	if counts.Total == 0 {
		return newError("SAML_NO_ASSERTION", "SAML response contains no assertions")
	}
	if counts.Total > 1 {
		return newError(
			"SAML_MULTIPLE_ASSERTIONS",
			fmt.Sprintf(
				"SAML response contains %d assertions, expected exactly 1",
				counts.Total,
			),
		)
	}
	return nil
}
