// Package crypto implements the wire-compatible cryptographic formats used by
// the reference implementation. Production helpers always use cryptographically secure entropy.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

const (
	passwordSaltSize = 16
	passwordKeySize  = 64
	passwordScryptN  = 16384
	passwordScryptR  = 16
	passwordScryptP  = 1
)

var ErrInvalidPasswordHash = errors.New("invalid the reference implementation password hash")

// HashPassword creates a the reference implementation compatible scrypt password hash.
func HashPassword(password string) (string, error) {
	return HashPasswordWithReader(password, rand.Reader)
}

// HashPasswordWithReader is HashPassword with injectable entropy for tests.
func HashPasswordWithReader(password string, random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("password hash: nil random source")
	}
	saltBytes := make([]byte, passwordSaltSize)
	if _, err := io.ReadFull(random, saltBytes); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(saltBytes)
	key, err := passwordKey(password, salt)
	if err != nil {
		return "", err
	}
	return salt + ":" + hex.EncodeToString(key), nil
}

// VerifyPassword verifies both current and legacy @noble/hashes the reference implementation
// hashes. Malformed hashes are rejected without panicking.
func VerifyPassword(hash, password string) bool {
	salt, encodedKey, ok := strings.Cut(hash, ":")
	if !ok || salt == "" || encodedKey == "" || strings.Contains(encodedKey, ":") {
		return false
	}
	want, err := hex.DecodeString(encodedKey)
	if err != nil || len(want) != passwordKeySize {
		return false
	}
	got, err := passwordKey(password, salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func passwordKey(password, salt string) ([]byte, error) {
	normalized := norm.NFKC.String(password)
	return scrypt.Key(
		[]byte(normalized),
		[]byte(salt),
		passwordScryptN,
		passwordScryptR,
		passwordScryptP,
		passwordKeySize,
	)
}
