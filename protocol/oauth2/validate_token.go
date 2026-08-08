package oauth2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// ValidateTokenOptions constrains the audience and issuer claims accepted by
// ValidateToken. An empty slice leaves the corresponding claim unconstrained;
// one or more values use any-match semantics like jose jwtVerify.
type ValidateTokenOptions struct {
	Audience []string
	Issuer   []string
}

// VerifiedToken is the protected header and payload returned after signature
// and claim validation.
type VerifiedToken struct {
	ProtectedHeader map[string]any
	Payload         map[string]any
}

// ValidateToken fetches a remote JWK set without following redirects and
// verifies a compact JWT against its matching key. RS256, ES256, and EdDSA
// (Ed25519) match the reference implementation's validateToken test surface.
func ValidateToken(
	ctx context.Context,
	client *http.Client,
	token string,
	jwksEndpoint string,
	options ValidateTokenOptions,
) (VerifiedToken, error) {
	protected, payload, signingInput, signature, err := decodeCompactJWT(token)
	if err != nil {
		return VerifiedToken{}, err
	}
	algorithm, _ := protected["alg"].(string)
	if algorithm == "" || algorithm == "none" {
		return VerifiedToken{}, errors.New("oauth2: JWT protected header has no supported algorithm")
	}
	keyID, _ := protected["kid"].(string)

	set, err := FetchJWKSet(ctx, client, jwksEndpoint)
	if err != nil {
		return VerifiedToken{}, err
	}
	if len(set.Keys) == 0 {
		return VerifiedToken{}, errors.New("oauth2: remote JWK set is empty")
	}

	var verificationErrors []error
	matched := false
	for _, jwk := range set.Keys {
		candidateID, _ := jwk["kid"].(string)
		if keyID != "" && candidateID != keyID {
			continue
		}
		candidateAlgorithm, _ := jwk["alg"].(string)
		if candidateAlgorithm != "" && candidateAlgorithm != algorithm {
			continue
		}
		publicKey, keyErr := publicKeyFromJWK(jwk, algorithm)
		if keyErr != nil {
			verificationErrors = append(verificationErrors, keyErr)
			continue
		}
		matched = true
		if verifyJWTSignature(algorithm, publicKey, signingInput, signature) {
			if err := validateTokenClaims(payload, options, time.Now()); err != nil {
				return VerifiedToken{}, err
			}
			return VerifiedToken{ProtectedHeader: protected, Payload: payload}, nil
		}
		verificationErrors = append(verificationErrors, errors.New("signature verification failed"))
	}
	if !matched && len(verificationErrors) == 0 {
		return VerifiedToken{}, fmt.Errorf("oauth2: no JWK matches kid %q and alg %q", keyID, algorithm)
	}
	if len(verificationErrors) > 0 {
		return VerifiedToken{}, fmt.Errorf("oauth2: JWT verification failed: %w", errors.Join(verificationErrors...))
	}
	return VerifiedToken{}, errors.New("oauth2: JWT verification failed")
}

func decodeCompactJWT(token string) (
	protected map[string]any,
	payload map[string]any,
	signingInput []byte,
	signature []byte,
	err error,
) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		err = errors.New("oauth2: JWT must contain three compact parts")
		return
	}
	protectedBytes, decodeErr := base64.RawURLEncoding.DecodeString(parts[0])
	if decodeErr != nil {
		err = fmt.Errorf("oauth2: decode JWT protected header: %w", decodeErr)
		return
	}
	payloadBytes, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decodeErr != nil {
		err = fmt.Errorf("oauth2: decode JWT payload: %w", decodeErr)
		return
	}
	signature, decodeErr = base64.RawURLEncoding.DecodeString(parts[2])
	if decodeErr != nil {
		err = fmt.Errorf("oauth2: decode JWT signature: %w", decodeErr)
		return
	}
	if decodeErr = decodeJSONObject(protectedBytes, &protected); decodeErr != nil {
		err = fmt.Errorf("oauth2: decode JWT protected header: %w", decodeErr)
		return
	}
	if decodeErr = decodeJSONObject(payloadBytes, &payload); decodeErr != nil {
		err = fmt.Errorf("oauth2: decode JWT payload: %w", decodeErr)
		return
	}
	signingInput = []byte(parts[0] + "." + parts[1])
	return
}

func decodeJSONObject(encoded []byte, target *map[string]any) error {
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if *target == nil {
		return errors.New("JSON value is not an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON input contains multiple values")
		}
		return err
	}
	return nil
}

func publicKeyFromJWK(jwk map[string]any, algorithm string) (crypto.PublicKey, error) {
	switch algorithm {
	case "RS256":
		if keyType, _ := jwk["kty"].(string); keyType != "RSA" {
			return nil, fmt.Errorf("oauth2: RS256 JWK has kty %q", keyType)
		}
		modulus, err := decodeJWKInteger(jwk, "n")
		if err != nil {
			return nil, err
		}
		exponentValue, err := decodeJWKInteger(jwk, "e")
		if err != nil {
			return nil, err
		}
		if !exponentValue.IsInt64() || exponentValue.Sign() <= 0 {
			return nil, errors.New("oauth2: RSA JWK exponent is invalid")
		}
		exponent := exponentValue.Int64()
		if int64(int(exponent)) != exponent {
			return nil, errors.New("oauth2: RSA JWK exponent overflows int")
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent)}, nil
	case "ES256":
		if keyType, _ := jwk["kty"].(string); keyType != "EC" {
			return nil, fmt.Errorf("oauth2: ES256 JWK has kty %q", keyType)
		}
		if curve, _ := jwk["crv"].(string); curve != "P-256" {
			return nil, fmt.Errorf("oauth2: ES256 JWK has curve %q", curve)
		}
		x, err := decodeJWKInteger(jwk, "x")
		if err != nil {
			return nil, err
		}
		y, err := decodeJWKInteger(jwk, "y")
		if err != nil {
			return nil, err
		}
		curve := elliptic.P256()
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("oauth2: EC JWK point is not on P-256")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "EdDSA":
		if keyType, _ := jwk["kty"].(string); keyType != "OKP" {
			return nil, fmt.Errorf("oauth2: EdDSA JWK has kty %q", keyType)
		}
		if curve, _ := jwk["crv"].(string); curve != "Ed25519" {
			return nil, fmt.Errorf("oauth2: EdDSA JWK has curve %q", curve)
		}
		x, err := decodeJWKBytes(jwk, "x")
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("oauth2: Ed25519 JWK key length is %d", len(x))
		}
		return ed25519.PublicKey(append([]byte(nil), x...)), nil
	default:
		return nil, fmt.Errorf("oauth2: unsupported JWT algorithm %q", algorithm)
	}
}

func decodeJWKBytes(jwk map[string]any, field string) ([]byte, error) {
	value, ok := jwk[field].(string)
	if !ok || value == "" {
		return nil, fmt.Errorf("oauth2: JWK field %q is missing", field)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("oauth2: decode JWK field %q: %w", field, err)
	}
	return decoded, nil
}

func decodeJWKInteger(jwk map[string]any, field string) (*big.Int, error) {
	decoded, err := decodeJWKBytes(jwk, field)
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("oauth2: JWK integer %q is empty", field)
	}
	return new(big.Int).SetBytes(decoded), nil
}

func verifyJWTSignature(algorithm string, key crypto.PublicKey, input, signature []byte) bool {
	switch algorithm {
	case "RS256":
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature) == nil
	case "ES256":
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok || len(signature) != 64 {
			return false
		}
		digest := sha256.Sum256(input)
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(publicKey, digest[:], r, s)
	case "EdDSA":
		publicKey, ok := key.(ed25519.PublicKey)
		return ok && ed25519.Verify(publicKey, input, signature)
	default:
		return false
	}
}

func validateTokenClaims(payload map[string]any, options ValidateTokenOptions, now time.Time) error {
	if err := validateNumericDate(payload, "exp", now, true); err != nil {
		return err
	}
	if err := validateNumericDate(payload, "nbf", now, false); err != nil {
		return err
	}
	if len(options.Audience) > 0 {
		actual := stringClaimValues(payload["aud"])
		if !claimsIntersect(actual, options.Audience) {
			return fmt.Errorf("oauth2: unexpected JWT audience %v", actual)
		}
	}
	if len(options.Issuer) > 0 {
		actual, _ := payload["iss"].(string)
		if !containsClaim(options.Issuer, actual) {
			return fmt.Errorf("oauth2: unexpected JWT issuer %q", actual)
		}
	}
	return nil
}

func validateNumericDate(payload map[string]any, name string, now time.Time, expiration bool) error {
	value, exists := payload[name]
	if !exists {
		return nil
	}
	var seconds float64
	switch claim := value.(type) {
	case json.Number:
		parsed, err := claim.Float64()
		if err != nil {
			return fmt.Errorf("oauth2: JWT %s claim is invalid: %w", name, err)
		}
		seconds = parsed
	case float64:
		seconds = claim
	default:
		return fmt.Errorf("oauth2: JWT %s claim is not numeric", name)
	}
	nowSeconds := float64(now.UnixNano()) / float64(time.Second)
	if expiration && nowSeconds >= seconds {
		return errors.New("oauth2: JWT has expired")
	}
	if !expiration && nowSeconds < seconds {
		return errors.New("oauth2: JWT is not active yet")
	}
	return nil
}

func stringClaimValues(value any) []string {
	switch claim := value.(type) {
	case string:
		return []string{claim}
	case []any:
		result := make([]string, 0, len(claim))
		for _, item := range claim {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return append([]string(nil), claim...)
	default:
		return nil
	}
}

func claimsIntersect(actual, expected []string) bool {
	for _, value := range actual {
		if containsClaim(expected, value) {
			return true
		}
	}
	return false
}

func containsClaim(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
