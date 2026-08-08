package saml

import (
	"encoding/base64"
	"testing"
)

func FuzzParseResponseDoesNotPanic(fuzz *testing.F) {
	fuzz.Add(validResponseFixture())
	fuzz.Add([]byte(`<Response><Assertion/></Response>`))
	fuzz.Add([]byte(`<!DOCTYPE Response><Response/>`))
	fuzz.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseResponseWithLimit(input, 16*1024)
	})
}

func FuzzPOSTBindingDecoderDoesNotPanic(fuzz *testing.F) {
	fuzz.Add(base64.StdEncoding.EncodeToString(validResponseFixture()))
	fuzz.Add("not-base64")
	fuzz.Fuzz(func(t *testing.T, input string) {
		_, _ = DecodePOSTMessage(input, 16*1024)
	})
}

func FuzzRedirectBindingDecoderDoesNotPanic(fuzz *testing.F) {
	encoded, err := EncodeRedirectMessage(validResponseFixture())
	if err != nil {
		fuzz.Fatalf("encode seed: %v", err)
	}
	fuzz.Add(encoded)
	fuzz.Add("not-base64")
	fuzz.Fuzz(func(t *testing.T, input string) {
		_, _ = DecodeRedirectMessage(input, 16*1024)
	})
}
