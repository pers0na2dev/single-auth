package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var rawBase64URL = base64.RawURLEncoding

// jweInfo is a frozen compatibility label. Keep these bytes stable so existing
// encrypted sessions remain readable across implementations and upgrades.
var jweInfo = []byte{
	0x42, 0x65, 0x74, 0x74, 0x65, 0x72, 0x41, 0x75, 0x74, 0x68,
	0x2e, 0x6a, 0x73, 0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61,
	0x74, 0x65, 0x64, 0x20, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4b, 0x65, 0x79,
}

var (
	ErrInvalidJWT = errors.New("invalid the reference implementation JWT")
	ErrExpiredJWT = errors.New("expired the reference implementation JWT")
)

type jwtHeader struct {
	Algorithm string `json:"alg"`
}

type jweHeader struct {
	Algorithm  string `json:"alg"`
	Encryption string `json:"enc"`
	KeyID      string `json:"kid,omitempty"`
}

// SignJWT creates the HS256 JWT format used by the reference implementation cookie caches.
func SignJWT(payload map[string]any, secret string, expiresIn time.Duration) (string, error) {
	return SignJWTAt(payload, secret, expiresIn, time.Now())
}

// SignJWTAt is SignJWT with an injectable timestamp for deterministic vectors.
func SignJWTAt(payload map[string]any, secret string, expiresIn time.Duration, now time.Time) (string, error) {
	claims := cloneClaims(payload)
	issuedAt := now.Unix()
	claims["iat"] = issuedAt
	claims["exp"] = issuedAt + int64(expiresIn/time.Second)
	headerBytes, err := json.Marshal(jwtHeader{Algorithm: "HS256"})
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := rawBase64URL.EncodeToString(headerBytes) + "." + rawBase64URL.EncodeToString(payloadBytes)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + rawBase64URL.EncodeToString(mac.Sum(nil)), nil
}

// VerifyJWT verifies an HS256 token and its time-based claims.
func VerifyJWT(token, secret string) (map[string]any, error) {
	return VerifyJWTAt(token, secret, time.Now(), 0)
}

// VerifyJWTAt verifies a token at a deterministic time with clock tolerance.
func VerifyJWTAt(token, secret string, now time.Time, tolerance time.Duration) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}
	headerBytes, err := rawBase64URL.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	var header jwtHeader
	if json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "HS256" {
		return nil, ErrInvalidJWT
	}
	signature, err := rawBase64URL.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	want := mac.Sum(nil)
	if len(signature) != len(want) || subtle.ConstantTimeCompare(signature, want) != 1 {
		return nil, ErrInvalidJWT
	}
	payloadBytes, err := rawBase64URL.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	claims := make(map[string]any)
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidJWT
	}
	if err := validateTimes(claims, now, tolerance); err != nil {
		return nil, err
	}
	return claims, nil
}

// EncodeJWE encrypts claims using the reference implementation's dir+A256CBC-HS512 compact JWE.
func EncodeJWE(payload map[string]any, secret, salt string, expiresIn time.Duration) (string, error) {
	return encodeJWE(payload, secret, salt, expiresIn, time.Now(), rand.Reader)
}

// EncodeJWEWithConfig encrypts using the current secret in a rotation config.
func EncodeJWEWithConfig(payload map[string]any, config SecretConfig, salt string, expiresIn time.Duration) (string, error) {
	return EncodeJWEWithConfigAt(payload, config, salt, expiresIn, time.Now(), rand.Reader)
}

// EncodeJWEWithConfigAt is the deterministic, rotation-aware JWE encoder.
func EncodeJWEWithConfigAt(
	payload map[string]any,
	config SecretConfig,
	salt string,
	expiresIn time.Duration,
	now time.Time,
	random io.Reader,
) (string, error) {
	secret, ok := config.Keys[config.CurrentVersion]
	if !ok {
		return "", fmt.Errorf("secret version %d not found in keys", config.CurrentVersion)
	}
	return encodeJWE(payload, secret, salt, expiresIn, now, random)
}

// EncodeJWEAt creates deterministic compatibility vectors.
func EncodeJWEAt(payload map[string]any, secret, salt string, expiresIn time.Duration, now time.Time, random io.Reader) (string, error) {
	return encodeJWE(payload, secret, salt, expiresIn, now, random)
}

func encodeJWE(payload map[string]any, secret, salt string, expiresIn time.Duration, now time.Time, random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("jwe: nil random source")
	}
	key := deriveEncryptionSecret(secret, salt, 64)
	header := jweHeader{
		Algorithm:  "dir",
		Encryption: "A256CBC-HS512",
		KeyID:      encryptionKeyThumbprint(key),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	protected := rawBase64URL.EncodeToString(headerBytes)
	claims := cloneClaims(payload)
	issuedAt := now.Unix()
	claims["iat"] = issuedAt
	claims["exp"] = issuedAt + int64(expiresIn/time.Second)
	jti, err := randomUUID(random)
	if err != nil {
		return "", err
	}
	claims["jti"] = jti
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(random, iv); err != nil {
		return "", err
	}
	ciphertext, tag, err := encryptA256CBCHS512(key, iv, []byte(protected), plaintext)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		protected,
		"",
		rawBase64URL.EncodeToString(iv),
		rawBase64URL.EncodeToString(ciphertext),
		rawBase64URL.EncodeToString(tag),
	}, "."), nil
}

// DecodeJWE decrypts a token produced from one secret.
func DecodeJWE(token, secret, salt string) (map[string]any, error) {
	return decodeJWEWithSecrets(token, []string{secret}, salt, time.Now())
}

// DecodeJWEWithConfig selects a rotation key using kid and falls back for
// legacy kid-less tokens in the reference implementation order.
func DecodeJWEWithConfig(token string, config SecretConfig, salt string) (map[string]any, error) {
	return DecodeJWEWithConfigAt(token, config, salt, time.Now())
}

// DecodeJWEWithConfigAt is the deterministic, rotation-aware JWE decoder.
func DecodeJWEWithConfigAt(token string, config SecretConfig, salt string, now time.Time) (map[string]any, error) {
	secrets := orderedSecrets(config)
	return decodeJWEWithSecrets(token, secrets, salt, now)
}

// DecodeJWEAt decrypts at a deterministic time.
func DecodeJWEAt(token, secret, salt string, now time.Time) (map[string]any, error) {
	return decodeJWEWithSecrets(token, []string{secret}, salt, now)
}

func decodeJWEWithSecrets(token string, secrets []string, salt string, now time.Time) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[1] != "" || len(secrets) == 0 {
		return nil, ErrInvalidJWT
	}
	headerBytes, err := rawBase64URL.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	var header jweHeader
	if json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "dir" {
		return nil, ErrInvalidJWT
	}
	iv, err := rawBase64URL.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	ciphertext, err := rawBase64URL.DecodeString(parts[3])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	tag, err := rawBase64URL.DecodeString(parts[4])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	for _, secret := range secrets {
		key := deriveEncryptionSecret(secret, salt, 64)
		if header.KeyID != "" && header.KeyID != encryptionKeyThumbprint(key) {
			continue
		}
		var plaintext []byte
		switch header.Encryption {
		case "A256CBC-HS512":
			plaintext, err = decryptA256CBCHS512(key, iv, []byte(parts[0]), ciphertext, tag)
		case "A256GCM":
			plaintext, err = decryptLegacyA256GCM(key[:32], iv, []byte(parts[0]), ciphertext, tag)
		default:
			return nil, ErrInvalidJWT
		}
		if err != nil {
			if header.KeyID != "" {
				return nil, ErrInvalidJWT
			}
			continue
		}
		claims := make(map[string]any)
		if json.Unmarshal(plaintext, &claims) != nil {
			return nil, ErrInvalidJWT
		}
		if err := validateTimes(claims, now, 15*time.Second); err != nil {
			return nil, err
		}
		return claims, nil
	}
	return nil, ErrInvalidJWT
}

func encryptA256CBCHS512(key, iv, aad, plaintext []byte) ([]byte, []byte, error) {
	if len(key) != 64 || len(iv) != aes.BlockSize {
		return nil, nil, ErrInvalidJWT
	}
	block, err := aes.NewCipher(key[32:])
	if err != nil {
		return nil, nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	tag := cbcAuthenticationTag(key[:32], aad, iv, ciphertext)
	return ciphertext, tag, nil
}

func decryptA256CBCHS512(key, iv, aad, ciphertext, tag []byte) ([]byte, error) {
	if len(key) != 64 || len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 || len(tag) != 32 {
		return nil, ErrInvalidJWT
	}
	want := cbcAuthenticationTag(key[:32], aad, iv, ciphertext)
	if subtle.ConstantTimeCompare(tag, want) != 1 {
		return nil, ErrInvalidJWT
	}
	block, err := aes.NewCipher(key[32:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext, aes.BlockSize)
}

func cbcAuthenticationTag(macKey, aad, iv, ciphertext []byte) []byte {
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad))*8)
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(aad)
	_, _ = mac.Write(iv)
	_, _ = mac.Write(ciphertext)
	_, _ = mac.Write(al)
	return mac.Sum(nil)[:32]
}

func decryptLegacyA256GCM(key, iv, aad, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
		return nil, ErrInvalidJWT
	}
	sealed := append(append([]byte(nil), ciphertext...), tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, ErrInvalidJWT
	}
	return plaintext, nil
}

func pkcs7Pad(input []byte, blockSize int) []byte {
	padding := blockSize - len(input)%blockSize
	output := make([]byte, len(input)+padding)
	copy(output, input)
	for i := len(input); i < len(output); i++ {
		output[i] = byte(padding)
	}
	return output
}

func pkcs7Unpad(input []byte, blockSize int) ([]byte, error) {
	if len(input) == 0 || len(input)%blockSize != 0 {
		return nil, ErrInvalidJWT
	}
	padding := int(input[len(input)-1])
	if padding == 0 || padding > blockSize || padding > len(input) {
		return nil, ErrInvalidJWT
	}
	var invalid byte
	for _, value := range input[len(input)-padding:] {
		invalid |= value ^ byte(padding)
	}
	if invalid != 0 {
		return nil, ErrInvalidJWT
	}
	return input[:len(input)-padding], nil
}

func deriveEncryptionSecret(secret, salt string, size int) []byte {
	// RFC 5869 HKDF-SHA256 with the configured salt and frozen compatibility label.
	extract := hmac.New(sha256.New, []byte(salt))
	_, _ = extract.Write([]byte(secret))
	prk := extract.Sum(nil)
	output := make([]byte, 0, size)
	var previous []byte
	for counter := byte(1); len(output) < size; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(jweInfo)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		output = append(output, previous...)
	}
	return output[:size]
}

func encryptionKeyThumbprint(key []byte) string {
	canonical := []byte(`{"k":"` + rawBase64URL.EncodeToString(key) + `","kty":"oct"}`)
	digest := sha256.Sum256(canonical)
	return rawBase64URL.EncodeToString(digest[:])
}

func randomUUID(random io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func cloneClaims(payload map[string]any) map[string]any {
	claims := make(map[string]any, len(payload)+3)
	for key, value := range payload {
		claims[key] = value
	}
	return claims
}

func validateTimes(claims map[string]any, now time.Time, tolerance time.Duration) error {
	nowSeconds := float64(now.Unix())
	toleranceSeconds := tolerance.Seconds()
	if exp, ok := numericClaim(claims["exp"]); ok && nowSeconds-toleranceSeconds >= exp {
		return ErrExpiredJWT
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && nowSeconds+toleranceSeconds < nbf {
		return ErrInvalidJWT
	}
	return nil
}

func numericClaim(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	default:
		return 0, false
	}
}

func orderedSecrets(config SecretConfig) []string {
	secrets := make([]string, 0, len(config.Keys)+1)
	seen := make(map[string]struct{}, len(config.Keys)+1)
	order := config.Order
	if len(order) == 0 {
		order = append([]int{config.CurrentVersion}, sortedOtherVersions(config.Keys, config.CurrentVersion)...)
	}
	for _, version := range order {
		if secret, ok := config.Keys[version]; ok {
			if _, duplicate := seen[secret]; !duplicate {
				secrets = append(secrets, secret)
				seen[secret] = struct{}{}
			}
		}
	}
	if config.LegacySecret != "" {
		if _, duplicate := seen[config.LegacySecret]; !duplicate {
			secrets = append(secrets, config.LegacySecret)
		}
	}
	return secrets
}

func sortedOtherVersions(keys map[int]string, current int) []int {
	versions := make([]int, 0, len(keys))
	for version := range keys {
		if version != current {
			versions = append(versions, version)
		}
	}
	for i := 1; i < len(versions); i++ {
		for j := i; j > 0 && versions[j] > versions[j-1]; j-- {
			versions[j], versions[j-1] = versions[j-1], versions[j]
		}
	}
	return versions
}
