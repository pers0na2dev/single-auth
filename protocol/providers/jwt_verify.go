package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type jwtParts struct {
	header       map[string]any
	claims       map[string]any
	signingInput []byte
	signature    []byte
}

type jwtPolicy struct {
	algorithms []string
	issuers    []string
	audiences  []string
	maxAge     time.Duration
	now        time.Time
}

func parseJWT(token string) (jwtParts, error) {
	encoded := strings.Split(token, ".")
	if len(encoded) != 3 {
		return jwtParts{}, errors.New("JWT must have three parts")
	}
	decodeObject := func(part string) (map[string]any, error) {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil, err
		}
		result := map[string]any{}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
		return result, nil
	}
	header, err := decodeObject(encoded[0])
	if err != nil {
		return jwtParts{}, err
	}
	claims, err := decodeObject(encoded[1])
	if err != nil {
		return jwtParts{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(encoded[2])
	if err != nil {
		return jwtParts{}, err
	}
	return jwtParts{header: header, claims: claims, signingInput: []byte(encoded[0] + "." + encoded[1]), signature: signature}, nil
}

func verifyRemoteJWT(ctx context.Context, provider *Provider, token, jwksURI string, policy jwtPolicy) (map[string]any, error) {
	parts, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	kid := stringValue(parts.header["kid"])
	alg := stringValue(parts.header["alg"])
	if kid == "" || alg == "" {
		return nil, errors.New("JWT header requires kid and alg")
	}
	if len(policy.algorithms) != 0 && !contains(policy.algorithms, alg) {
		return nil, fmt.Errorf("JWT algorithm %s is not allowed", alg)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := doJSON(ctx, provider.clientFor(ctx), http.MethodGet, jwksURI, nil, nil, &set); err != nil {
		return nil, err
	}
	if set.Keys == nil {
		return nil, errors.New("Keys not found")
	}
	var key map[string]any
	for _, candidate := range set.Keys {
		if stringValue(candidate["kid"]) == kid {
			key = candidate
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("JWK with kid %s not found", kid)
	}
	if err := verifyJWK(parts, key, alg); err != nil {
		return nil, err
	}
	if err := validateClaims(parts.claims, policy); err != nil {
		return nil, err
	}
	return parts.claims, nil
}

func verifyHMACJWT(token, secret string, policy jwtPolicy) (map[string]any, error) {
	parts, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	alg := stringValue(parts.header["alg"])
	if len(policy.algorithms) != 0 && !contains(policy.algorithms, alg) {
		return nil, fmt.Errorf("JWT algorithm %s is not allowed", alg)
	}
	var expected []byte
	switch alg {
	case "HS256":
		hash := hmac.New(sha256.New, []byte(secret))
		_, _ = hash.Write(parts.signingInput)
		expected = hash.Sum(nil)
	case "HS384":
		hash := hmac.New(sha512.New384, []byte(secret))
		_, _ = hash.Write(parts.signingInput)
		expected = hash.Sum(nil)
	case "HS512":
		hash := hmac.New(sha512.New, []byte(secret))
		_, _ = hash.Write(parts.signingInput)
		expected = hash.Sum(nil)
	default:
		return nil, fmt.Errorf("unsupported HMAC JWT algorithm %s", alg)
	}
	if !hmac.Equal(parts.signature, expected) {
		return nil, errors.New("invalid JWT signature")
	}
	if err := validateClaims(parts.claims, policy); err != nil {
		return nil, err
	}
	return parts.claims, nil
}

func verifyJWK(parts jwtParts, jwk map[string]any, alg string) error {
	switch stringValue(jwk["kty"]) {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["n"]))
		if err != nil {
			return err
		}
		eRaw, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["e"]))
		if err != nil {
			return err
		}
		e := 0
		for _, value := range eRaw {
			e = e<<8 | int(value)
		}
		if e == 0 {
			return errors.New("invalid RSA exponent")
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: e}
		hash, digest, pss, err := jwtDigest(parts.signingInput, alg)
		if err != nil {
			return err
		}
		if pss {
			return rsa.VerifyPSS(key, hash, digest, parts.signature, nil)
		}
		return rsa.VerifyPKCS1v15(key, hash, digest, parts.signature)
	case "EC":
		curveName := stringValue(jwk["crv"])
		var curve elliptic.Curve
		switch curveName {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return fmt.Errorf("unsupported EC curve %s", curveName)
		}
		xRaw, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["x"]))
		if err != nil {
			return err
		}
		yRaw, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["y"]))
		if err != nil {
			return err
		}
		_, digest, _, err := jwtDigest(parts.signingInput, alg)
		if err != nil {
			return err
		}
		if len(parts.signature)%2 != 0 {
			return errors.New("invalid ECDSA signature")
		}
		half := len(parts.signature) / 2
		if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xRaw), Y: new(big.Int).SetBytes(yRaw)}, digest, new(big.Int).SetBytes(parts.signature[:half]), new(big.Int).SetBytes(parts.signature[half:])) {
			return errors.New("invalid JWT signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWK key type %s", stringValue(jwk["kty"]))
	}
}

func jwtDigest(input []byte, alg string) (crypto.Hash, []byte, bool, error) {
	switch alg {
	case "RS256", "PS256", "ES256":
		sum := sha256.Sum256(input)
		return crypto.SHA256, sum[:], strings.HasPrefix(alg, "PS"), nil
	case "RS384", "PS384", "ES384":
		sum := sha512.Sum384(input)
		return crypto.SHA384, sum[:], strings.HasPrefix(alg, "PS"), nil
	case "RS512", "PS512", "ES512":
		sum := sha512.Sum512(input)
		return crypto.SHA512, sum[:], strings.HasPrefix(alg, "PS"), nil
	default:
		return 0, nil, false, fmt.Errorf("unsupported JWT algorithm %s", alg)
	}
}

func validateClaims(claims map[string]any, policy jwtPolicy) error {
	now := policy.now
	if now.IsZero() {
		now = time.Now()
	}
	if exp, ok := numericDate(claims["exp"]); ok && !now.Before(exp) {
		return errors.New("JWT has expired")
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && now.Before(nbf) {
		return errors.New("JWT is not active")
	}
	if len(policy.issuers) != 0 && !contains(policy.issuers, stringValue(claims["iss"])) {
		return errors.New("unexpected JWT issuer")
	}
	if len(policy.audiences) != 0 && !audienceIntersects(claims["aud"], policy.audiences) {
		return errors.New("unexpected JWT audience")
	}
	if policy.maxAge > 0 {
		iat, ok := numericDate(claims["iat"])
		if !ok {
			return errors.New("JWT iat is required")
		}
		if now.Sub(iat) > policy.maxAge {
			return errors.New("JWT is too old")
		}
	}
	return nil
}

func numericDate(value any) (time.Time, bool) {
	var seconds float64
	switch typed := value.(type) {
	case float64:
		seconds = typed
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	case int:
		seconds = float64(typed)
	case int64:
		seconds = float64(typed)
	default:
		return time.Time{}, false
	}
	whole, fraction := mathModf(seconds)
	return time.Unix(whole, int64(fraction*1e9)), true
}

func mathModf(value float64) (int64, float64) {
	whole := int64(value)
	return whole, value - float64(whole)
}

func audienceIntersects(claim any, expected []string) bool {
	actual := []string{}
	switch typed := claim.(type) {
	case string:
		actual = []string{typed}
	case []any:
		for _, value := range typed {
			if text, ok := value.(string); ok {
				actual = append(actual, text)
			}
		}
	case []string:
		actual = typed
	}
	for _, value := range actual {
		if contains(expected, value) {
			return true
		}
	}
	return false
}
