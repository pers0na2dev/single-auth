package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	envelopePrefix = "$ba$"

	// DefaultSecret is the reference implementation 1.6.26's development/test fallback. It is
	// exported so context builders and compatibility layers cannot drift from
	// the crypto package's secret-rotation contract.
	DefaultSecret = "single-auth-secret-12345678901234567890"
)

var (
	ErrInvalidCiphertext = errors.New("invalid the reference implementation ciphertext")
	ErrUnknownSecret     = errors.New("unknown the reference implementation secret version")
)

// SecretEntry is one versioned the reference implementation secret.
type SecretEntry struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}

// SecretInputEntry accepts configuration decoded from dynamic formats where
// the reference implementation permits canonical decimal strings as well as numeric versions.
// NormalizeSecretEntries converts it to the strongly typed Go form.
type SecretInputEntry struct {
	Version any    `json:"version"`
	Value   string `json:"value"`
}

// SecretConfig preserves the reference implementation's ordered secret rotation configuration.
type SecretConfig struct {
	Keys           map[int]string `json:"keys"`
	Order          []int          `json:"order"`
	CurrentVersion int            `json:"currentVersion"`
	LegacySecret   string         `json:"legacySecret,omitempty"`
}

// Envelope is the parsed $ba$<version>$<ciphertext> representation.
type Envelope struct {
	Version    int
	Ciphertext string
}

// NewSecretConfig validates and builds an ordered rotation configuration.
func NewSecretConfig(entries []SecretEntry, legacySecret string) (SecretConfig, error) {
	if err := ValidateSecretEntries(entries); err != nil {
		return SecretConfig{}, err
	}
	keys := make(map[int]string, len(entries))
	order := make([]int, 0, len(entries))
	for _, entry := range entries {
		keys[entry.Version] = entry.Value
		order = append(order, entry.Version)
	}
	return SecretConfig{
		Keys:           keys,
		Order:          order,
		CurrentVersion: entries[0].Version,
		LegacySecret:   legacySecret,
	}, nil
}

// ValidateSecretEntries applies the reference implementation's structural secret checks.
func ValidateSecretEntries(entries []SecretEntry) error {
	if len(entries) == 0 {
		return errors.New("`secrets` array must contain at least one entry")
	}
	seen := make(map[int]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Version < 0 {
			return fmt.Errorf("Invalid version %d in `secrets`. Version must be a non-negative integer.", entry.Version)
		}
		if entry.Value == "" {
			return fmt.Errorf("Empty secret value for version %d in `secrets`.", entry.Version)
		}
		if _, exists := seen[entry.Version]; exists {
			return fmt.Errorf("Duplicate version %d in `secrets`. Each version must be unique.", entry.Version)
		}
		seen[entry.Version] = struct{}{}
	}
	return nil
}

// NormalizeSecretEntries applies the reference implementation's strict validation after its
// parseInt(String(version), 10) coercion. Canonical decimal strings such as
// "1" are accepted, while "0x10", "1e2", fractional values, and duplicate
// versions after coercion are rejected.
func NormalizeSecretEntries(entries []SecretInputEntry) ([]SecretEntry, error) {
	if len(entries) == 0 {
		return nil, errors.New("`secrets` array must contain at least one entry")
	}
	normalized := make([]SecretEntry, 0, len(entries))
	seen := make(map[int]struct{}, len(entries))
	for _, entry := range entries {
		version, ok := normalizeSecretVersion(entry.Version)
		if !ok || version < 0 {
			return nil, fmt.Errorf("Invalid version %v in `secrets`. Version must be a non-negative integer.", entry.Version)
		}
		if entry.Value == "" {
			return nil, fmt.Errorf("Empty secret value for version %d in `secrets`.", version)
		}
		if _, exists := seen[version]; exists {
			return nil, fmt.Errorf("Duplicate version %d in `secrets`. Each version must be unique.", version)
		}
		seen[version] = struct{}{}
		normalized = append(normalized, SecretEntry{Version: version, Value: entry.Value})
	}
	return normalized, nil
}

// ValidateSecretInputs validates dynamically decoded secret entries.
func ValidateSecretInputs(entries []SecretInputEntry) error {
	_, err := NormalizeSecretEntries(entries)
	return err
}

// BuildSecretConfig normalizes dynamic entries and constructs the same key map
// used by the reference implementation. Its built-in default is never retained as a legacy key.
func BuildSecretConfig(entries []SecretInputEntry, legacySecret string) (SecretConfig, error) {
	normalized, err := NormalizeSecretEntries(entries)
	if err != nil {
		return SecretConfig{}, err
	}
	if legacySecret == DefaultSecret {
		legacySecret = ""
	}
	return NewSecretConfig(normalized, legacySecret)
}

func normalizeSecretVersion(value any) (int, bool) {
	if value == nil {
		return 0, false
	}
	if text, ok := value.(string); ok {
		text = strings.TrimSpace(text)
		version, err := strconv.ParseInt(text, 10, 0)
		if err != nil || strconv.FormatInt(version, 10) != text {
			return 0, false
		}
		return int(version), true
	}
	if number, ok := value.(json.Number); ok {
		floatValue, err := number.Float64()
		if err != nil {
			return 0, false
		}
		return normalizedIntegerFloat(floatValue)
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := reflected.Int()
		if integer < int64(minInt()) || integer > int64(maxInt()) {
			return 0, false
		}
		return int(integer), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		integer := reflected.Uint()
		if integer > uint64(maxInt()) {
			return 0, false
		}
		return int(integer), true
	case reflect.Float32, reflect.Float64:
		return normalizedIntegerFloat(reflected.Float())
	default:
		return 0, false
	}
}

func normalizedIntegerFloat(value float64) (int, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value ||
		value < float64(minInt()) || value > float64(maxInt()) {
		return 0, false
	}
	return int(value), true
}

func maxInt() int { return int(^uint(0) >> 1) }
func minInt() int { return -maxInt() - 1 }

// ParseSecretsEnv parses SINGLE_AUTH_SECRETS using JavaScript parseInt-like
// leading-decimal behavior, matching the reference implementation 1.6.26.
func ParseSecretsEnv(value string) ([]SecretEntry, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	entries := make([]SecretEntry, 0, len(parts))
	for _, raw := range parts {
		entry := strings.TrimSpace(raw)
		idx := strings.IndexByte(entry, ':')
		if idx < 0 {
			return nil, fmt.Errorf("Invalid SINGLE_AUTH_SECRETS entry: %q. Expected format: \"<version>:<secret>\"", entry)
		}
		versionText := entry[:idx]
		version, ok := parseJSBase10Integer(versionText)
		if !ok || version < 0 {
			return nil, fmt.Errorf("Invalid version in SINGLE_AUTH_SECRETS: %q. Version must be a non-negative integer.", versionText)
		}
		secret := strings.TrimSpace(entry[idx+1:])
		if secret == "" {
			return nil, fmt.Errorf("Empty secret value for version %d in SINGLE_AUTH_SECRETS.", version)
		}
		entries = append(entries, SecretEntry{Version: version, Value: secret})
	}
	return entries, nil
}

func parseJSBase10Integer(value string) (int, bool) {
	value = strings.TrimLeftFunc(value, unicode.IsSpace)
	if value == "" {
		return 0, false
	}
	end := 0
	if value[0] == '+' || value[0] == '-' {
		end++
	}
	startDigits := end
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == startDigits {
		return 0, false
	}
	n, err := strconv.ParseInt(value[:end], 10, 0)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// ParseEnvelope parses a versioned the reference implementation encrypted value.
func ParseEnvelope(value string) (Envelope, bool) {
	if !strings.HasPrefix(value, envelopePrefix) {
		return Envelope{}, false
	}
	rest := value[len(envelopePrefix):]
	idx := strings.IndexByte(rest, '$')
	if idx < 0 {
		return Envelope{}, false
	}
	version, ok := parseJSBase10Integer(rest[:idx])
	if !ok || version < 0 {
		return Envelope{}, false
	}
	return Envelope{Version: version, Ciphertext: rest[idx+1:]}, true
}

// FormatEnvelope builds the reference implementation's versioned encrypted value format.
func FormatEnvelope(version int, ciphertext string) string {
	return envelopePrefix + strconv.Itoa(version) + "$" + ciphertext
}

// Encrypt encrypts data in the legacy bare-hex XChaCha20-Poly1305 format.
func Encrypt(secret string, data []byte) (string, error) {
	return encryptWithReader(secret, data, rand.Reader)
}

// EncryptWithConfig encrypts data with the current version and adds an envelope.
func EncryptWithConfig(config SecretConfig, data []byte) (string, error) {
	return EncryptWithConfigAndReader(config, data, rand.Reader)
}

// EncryptWithConfigAndReader is EncryptWithConfig with an injectable random
// source. It is used by the auth runtime so OAuth-state vectors can be
// deterministic without weakening the production default.
func EncryptWithConfigAndReader(config SecretConfig, data []byte, random io.Reader) (string, error) {
	secret, ok := config.Keys[config.CurrentVersion]
	if !ok {
		return "", fmt.Errorf("secret version %d not found in keys", config.CurrentVersion)
	}
	ciphertext, err := encryptWithReader(secret, data, random)
	if err != nil {
		return "", err
	}
	return FormatEnvelope(config.CurrentVersion, ciphertext), nil
}

// EncryptWithReader creates deterministic vectors while retaining the legacy
// unversioned format.
func EncryptWithReader(secret string, data []byte, random io.Reader) (string, error) {
	return encryptWithReader(secret, data, random)
}

func encryptWithReader(secret string, data []byte, random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("encrypt: nil random source")
	}
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", err
	}
	// @noble/ciphers managedNonce prepends the nonce to ciphertext+tag.
	sealed := aead.Seal(nil, nonce, data, nil)
	output := append(nonce, sealed...)
	return hex.EncodeToString(output), nil
}

// Decrypt decrypts the legacy bare-hex XChaCha20-Poly1305 format.
func Decrypt(secret, value string) ([]byte, error) {
	return decryptRaw(secret, value)
}

// DecryptWithConfig decrypts versioned data and explicitly configured legacy
// bare-hex data.
func DecryptWithConfig(config SecretConfig, value string) ([]byte, error) {
	if envelope, ok := ParseEnvelope(value); ok {
		secret, exists := config.Keys[envelope.Version]
		if !exists {
			return nil, fmt.Errorf("%w: version %d (key may have been retired)", ErrUnknownSecret, envelope.Version)
		}
		return decryptRaw(secret, envelope.Ciphertext)
	}
	if config.LegacySecret == "" {
		return nil, errors.New("cannot decrypt legacy bare-hex payload: no legacy secret available")
	}
	return decryptRaw(config.LegacySecret, value)
}

func decryptRaw(secret, value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, ErrInvalidCiphertext
	}
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := raw[:chacha20poly1305.NonceSizeX]
	plaintext, err := aead.Open(nil, nonce, raw[chacha20poly1305.NonceSizeX:], nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

// MakeSignature returns the reference implementation's padded base64 HMAC-SHA256 signature.
func MakeSignature(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies MakeSignature in constant time.
func VerifySignature(value, signature, secret string) bool {
	want, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	got := mac.Sum(nil)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}

// MakeURLSignature returns the unpadded base64url HMAC-SHA256 format used by
// the reference implementation's compact session cache.
func MakeURLSignature(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyURLSignature verifies MakeURLSignature in constant time.
func VerifyURLSignature(value, signature, secret string) bool {
	want, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	got := mac.Sum(nil)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}
