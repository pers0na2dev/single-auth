package siwe

import "testing"

func TestChecksumAddressEIP55Vectors(t *testing.T) {
	tests := map[string]string{
		"0x000000000000000000000000000000000000dead": "0x000000000000000000000000000000000000dEaD",
		"0x52908400098527886e0f7030069857d2e4169ee7": "0x52908400098527886E0F7030069857D2E4169EE7",
		"0xde709f2102306220921060314715629080e2fb77": "0xde709f2102306220921060314715629080e2fb77",
		"0x27b1fdb04752bbc536007a920d24acb045561c26": "0x27b1fdb04752bbc536007a920d24acb045561c26",
	}
	for input, expected := range tests {
		if actual := ChecksumAddress(input); actual != expected {
			t.Fatalf("ChecksumAddress(%q) = %q, want %q", input, actual, expected)
		}
		if actual := ChecksumAddress(expected); actual != expected {
			t.Fatalf("checksummed input changed: %q", actual)
		}
	}
}

func TestChecksumAddressAcceptsUppercasePrefix(t *testing.T) {
	input := "0X000000000000000000000000000000000000DEAD"
	if actual := ChecksumAddress(input); actual != testWalletAddress {
		t.Fatalf("ChecksumAddress(%q) = %q", input, actual)
	}
}
