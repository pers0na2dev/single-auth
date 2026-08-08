package siwe

import (
	"reflect"
	"testing"
)

func TestParseMessageMatchesFrozenTolerantParser(t *testing.T) {
	message := "https://Example.COM/path wants you to sign in with your Ethereum account:\r\n" +
		testWalletAddress + "\r\n\r\n" +
		"A statement: with punctuation\r\n\r\n" +
		"URI: https://example.com\r\n" +
		"Version: 1\r\n" +
		"Chain ID: 137\r\n" +
		"Nonce: nonce-1\r\n" +
		"Issued At: 2024-01-01T00:00:00.000Z\r\n" +
		"Expiration Time: 2030-01-01T00:00:00.000Z\r\n" +
		"Not Before: 2023-01-01T00:00:00.000Z\r\n" +
		"Request ID: request-1"
	want := ParsedMessage{
		Scheme: "https", Domain: "Example.COM/path", Address: testWalletAddress,
		URI: "https://example.com", Version: "1", ChainID: 137, HasChainID: true,
		Nonce: "nonce-1", IssuedAt: "2024-01-01T00:00:00.000Z",
		ExpirationTime: "2030-01-01T00:00:00.000Z",
		NotBefore:      "2023-01-01T00:00:00.000Z", RequestID: "request-1",
	}
	if got := ParseMessage(message); !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed message = %#v, want %#v", got, want)
	}
}

func TestParseMessageNeverPanicsAndSuffixFieldsWin(t *testing.T) {
	malformed := []string{"", "not siwe", "x\n0xno", "\r\n", "Chain ID: Infinity"}
	for _, message := range malformed {
		_ = ParseMessage(message)
	}
	message := "example.com wants you to sign in with your Ethereum account:\n" +
		testWalletAddress + "\n\nNonce: first\nNonce: second\nChain ID: 1\nChain ID: 137"
	parsed := ParseMessage(message)
	if parsed.Nonce != "second" || parsed.ChainID != 137 || !parsed.HasChainID {
		t.Fatalf("suffix fields did not win: %#v", parsed)
	}
}

func TestNormalizeDomainMatchesFrozenParser(t *testing.T) {
	tests := map[string]string{
		"https://Example.COM/path":            "example.com",
		"EXAMPLE.com:3000/resource":           "example.com:3000",
		"  wss://Wallet.Example/anything  ":   "wallet.example",
		"http://localhost:3000/api/auth/siwe": "localhost:3000",
	}
	for input, expected := range tests {
		if got := NormalizeDomain(input); got != expected {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", input, got, expected)
		}
	}
}
