package siwe

import (
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ChecksumAddress implements EIP-55 with legacy Keccak-256, matching
// single-auth's @noble/hashes implementation byte-for-byte.
func ChecksumAddress(address string) string {
	normalized := strings.ToLower(address)
	normalized = strings.TrimPrefix(normalized, "0x")
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(normalized))
	digest := hex.EncodeToString(hash.Sum(nil))

	result := make([]byte, 42)
	copy(result, "0x")
	for index := 0; index < 40; index++ {
		character := normalized[index]
		if digest[index] >= '8' && character >= 'a' && character <= 'f' {
			character -= 'a' - 'A'
		}
		result[index+2] = character
	}
	return string(result)
}
