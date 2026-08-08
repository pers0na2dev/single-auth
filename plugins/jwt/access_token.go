package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/pers0na2dev/single-auth/core/engine"
)

// AccessTokenVerification preserves the distinctions required by the OAuth
// provider's RFC 7009 endpoint after cryptographic JWS verification.
type AccessTokenVerification uint8

const (
	AccessTokenNotJWT AccessTokenVerification = iota
	AccessTokenInvalidSignature
	AccessTokenInvalidClaims
	AccessTokenInactive
	AccessTokenValid
)

// VerifyAccessToken performs the same stored-JWK verification as VerifyJWT,
// but retains the JOSE failure class used by OAuth revocation. single-auth
// 1.6.26 falls back to opaque lookup only for TypeError/JWSInvalid failures,
// accepts JWTExpired/JWTInvalid as inactive, and surfaces signature or claim
// validation failures as internal errors.
func VerifyAccessToken(
	ctx *engine.Context,
	token string,
	options Options,
) (map[string]any, AccessTokenVerification, error) {
	compiled, err := normalize(options, false)
	if err != nil {
		return nil, AccessTokenNotJWT, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, AccessTokenNotJWT, nil
	}
	headerBytes, err := rawURL.DecodeString(parts[0])
	if err != nil {
		return nil, AccessTokenNotJWT, nil
	}
	var header map[string]any
	if json.Unmarshal(headerBytes, &header) != nil || header == nil {
		return nil, AccessTokenNotJWT, nil
	}
	algorithmText, _ := header["alg"].(string)
	headerAlgorithm := Algorithm(algorithmText)
	if headerAlgorithm == "" {
		return nil, AccessTokenNotJWT, nil
	}
	if !accessTokenAlgorithmSupported(headerAlgorithm) {
		return nil, AccessTokenNotJWT, fmt.Errorf(
			"jwt: unsupported JWS algorithm %q", headerAlgorithm,
		)
	}
	headerKeyID, _ := header["kid"].(string)
	keys, err := compiled.adapter.getAll(ctx)
	if err != nil {
		return nil, AccessTokenNotJWT, err
	}
	type candidate struct {
		publicJWK map[string]any
		algorithm Algorithm
	}
	candidates := make([]candidate, 0, 1)
	for index := range keys {
		key := keys[index]
		publicJWK, parseErr := parseJWK(key.PublicKey)
		if parseErr != nil {
			return nil, AccessTokenNotJWT, fmt.Errorf(
				"jwt: parse stored public JWK: %w", parseErr,
			)
		}
		algorithm := accessTokenKeyAlgorithm(key, compiled.options)
		if accessTokenJWKMatches(publicJWK, key.ID, algorithm, headerAlgorithm, headerKeyID) {
			candidates = append(candidates, candidate{
				publicJWK: publicJWK, algorithm: algorithm,
			})
		}
	}
	if len(candidates) == 0 {
		return nil, AccessTokenNotJWT, errors.New("jwt: no matching JWK")
	}
	if len(candidates) != 1 {
		return nil, AccessTokenNotJWT, errors.New("jwt: multiple matching JWKs")
	}
	selected := candidates[0]
	publicKey, err := jwkPublicKey(selected.publicJWK, selected.algorithm)
	if err != nil {
		return nil, AccessTokenNotJWT, fmt.Errorf("jwt: import stored public JWK: %w", err)
	}
	signature, err := rawURL.DecodeString(parts[2])
	if err != nil {
		return nil, AccessTokenNotJWT, nil
	}
	if !verifyBytes(
		selected.algorithm,
		publicKey,
		[]byte(parts[0]+"."+parts[1]),
		signature,
	) {
		return nil, AccessTokenInvalidSignature, nil
	}
	payloadBytes, err := rawURL.DecodeString(parts[1])
	if err != nil {
		return nil, AccessTokenNotJWT, nil
	}
	payload := map[string]any{}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	if decoder.Decode(&payload) != nil || payload == nil {
		return nil, AccessTokenInactive, nil
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, AccessTokenInactive, nil
	}
	disposition, err := compiled.verifyAccessTokenClaims(ctx, payload)
	if err != nil {
		return payload, AccessTokenNotJWT, err
	}
	return payload, disposition, nil
}

func accessTokenAlgorithmSupported(algorithm Algorithm) bool {
	switch algorithm {
	case EdDSA, ES256, ES512, PS256, RS256:
		return true
	default:
		return false
	}
}

func accessTokenKeyAlgorithm(key JWK, options Options) Algorithm {
	algorithm := key.Algorithm
	if algorithm == "" && options.JWKS.KeyPair != nil {
		algorithm = options.JWKS.KeyPair.Algorithm
	}
	if algorithm == "" {
		algorithm = EdDSA
	}
	return algorithm
}

func accessTokenJWKMatches(
	jwk map[string]any,
	keyID string,
	keyAlgorithm, tokenAlgorithm Algorithm,
	tokenKeyID string,
) bool {
	if keyAlgorithm != tokenAlgorithm {
		return false
	}
	if tokenKeyID != "" && tokenKeyID != keyID {
		return false
	}
	wantKTY := ""
	switch tokenAlgorithm {
	case EdDSA:
		wantKTY = "OKP"
	case ES256, ES512:
		wantKTY = "EC"
	case PS256, RS256:
		wantKTY = "RSA"
	}
	if kty, _ := jwk["kty"].(string); kty != wantKTY {
		return false
	}
	if algorithm, ok := jwk["alg"].(string); ok && algorithm != string(tokenAlgorithm) {
		return false
	}
	if use, ok := jwk["use"].(string); ok && use != "sig" {
		return false
	}
	if operations, exists := jwk["key_ops"]; exists && !accessTokenAllowsVerify(operations) {
		return false
	}
	switch tokenAlgorithm {
	case EdDSA:
		curve, _ := jwk["crv"].(string)
		return curve == "Ed25519"
	case ES256:
		curve, _ := jwk["crv"].(string)
		return curve == "P-256"
	case ES512:
		curve, _ := jwk["crv"].(string)
		return curve == "P-521"
	default:
		return true
	}
}

func accessTokenAllowsVerify(value any) bool {
	switch operations := value.(type) {
	case []string:
		for _, operation := range operations {
			if operation == "verify" {
				return true
			}
		}
	case []any:
		for _, operation := range operations {
			if operation == "verify" {
				return true
			}
		}
	}
	return false
}

func (plugin *compiledPlugin) verifyAccessTokenClaims(
	ctx *engine.Context,
	payload map[string]any,
) (AccessTokenVerification, error) {
	baseOrigin, err := plugin.baseOrigin(ctx)
	if err != nil {
		return AccessTokenNotJWT, err
	}
	expectedIssuer := baseOrigin
	if plugin.options.Token.Issuer != nil {
		expectedIssuer = *plugin.options.Token.Issuer
	}
	issuer, exists := payload["iss"]
	if !exists || (expectedIssuer != "" && issuer != expectedIssuer) {
		return AccessTokenInvalidClaims, nil
	}

	expectedAudience := plugin.options.Token.Audience
	if expectedAudience == nil {
		expectedAudience = baseOrigin
	}
	actualAudience, exists := payload["aud"]
	if !exists || !accessTokenAudienceMatches(actualAudience, expectedAudience) {
		return AccessTokenInvalidClaims, nil
	}

	if _, exists, claimErr := numericClaim(payload, "iat"); exists && claimErr != nil {
		return AccessTokenInvalidClaims, nil
	}
	now := float64(plugin.clock().Unix())
	if notBefore, exists, claimErr := numericClaim(payload, "nbf"); claimErr != nil || (exists && notBefore > now) {
		return AccessTokenInvalidClaims, nil
	}
	if expiresAt, exists, claimErr := numericClaim(payload, "exp"); claimErr != nil {
		return AccessTokenInvalidClaims, nil
	} else if exists && expiresAt <= now {
		return AccessTokenInactive, nil
	}
	return AccessTokenValid, nil
}

func accessTokenAudienceMatches(actual, expected any) bool {
	want := audiences(expected)
	got := audiences(actual)
	for _, candidate := range got {
		for _, expectedAudience := range want {
			if candidate == expectedAudience {
				return true
			}
		}
	}
	return false
}
