package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"math/big"
	"strings"

	"github.com/pers0na2dev/single-auth/core/engine"
)

// VerifyJWT verifies a token with the configured stored public keys. Invalid,
// expired, or mismatched tokens return nil exactly like the upstream helper.
func VerifyJWT(ctx *engine.Context, token string, options Options) map[string]any {
	compiled, err := normalize(options, false)
	if err != nil {
		return nil
	}
	return compiled.verifyJWT(ctx, token)
}

func (plugin *compiledPlugin) verifyJWT(ctx *engine.Context, token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	headerBytes, err := rawURL.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var header struct {
		Algorithm Algorithm `json:"alg"`
		KeyID     string    `json:"kid"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.KeyID == "" {
		return nil
	}
	keys, err := plugin.adapter.getAll(ctx)
	if err != nil || len(keys) == 0 {
		return nil
	}
	var key *JWK
	for index := range keys {
		if keys[index].ID == header.KeyID {
			candidate := keys[index]
			key = &candidate
			break
		}
	}
	if key == nil {
		return nil
	}
	algorithm := key.Algorithm
	if algorithm == "" && plugin.options.JWKS.KeyPair != nil {
		algorithm = plugin.options.JWKS.KeyPair.Algorithm
	}
	if algorithm == "" {
		algorithm = EdDSA
	}
	// jose importJWK is called with the persisted/configured algorithm. The JWT
	// protected alg must match it; accepting a different value is algorithm
	// confusion and jwtVerify rejects it.
	if header.Algorithm != algorithm {
		return nil
	}
	publicJWK, err := parseJWK(key.PublicKey)
	if err != nil {
		return nil
	}
	publicKey, err := jwkPublicKey(publicJWK, algorithm)
	if err != nil {
		return nil
	}
	signature, err := rawURL.DecodeString(parts[2])
	if err != nil || !verifyBytes(algorithm, publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return nil
	}
	payloadBytes, err := rawURL.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	payload := map[string]any{}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	if decoder.Decode(&payload) != nil {
		return nil
	}
	if !plugin.verifyClaims(ctx, payload) {
		return nil
	}
	return payload
}

func (plugin *compiledPlugin) verifyClaims(ctx *engine.Context, payload map[string]any) bool {
	subject, ok := payload["sub"].(string)
	if !ok || subject == "" {
		return false
	}
	audienceClaim, exists := payload["aud"]
	if !exists || audienceClaim == nil {
		return false
	}
	now := float64(plugin.clock().Unix())
	if exp, exists, err := numericClaim(payload, "exp"); err != nil || (exists && now >= exp) {
		return false
	}
	if nbf, exists, err := numericClaim(payload, "nbf"); err != nil || (exists && now < nbf) {
		return false
	}
	baseOrigin, err := plugin.baseOrigin(ctx)
	if err != nil {
		return false
	}
	expectedIssuer := ""
	if plugin.options.Token.Issuer == nil {
		expectedIssuer = baseOrigin
	} else {
		expectedIssuer = *plugin.options.Token.Issuer
	}
	issuer, ok := payload["iss"].(string)
	if !ok || issuer != expectedIssuer {
		return false
	}
	expectedAudience := plugin.options.Token.Audience
	if expectedAudience == nil {
		expectedAudience = baseOrigin
	}
	want := audiences(expectedAudience)
	got := audiences(audienceClaim)
	if len(want) == 0 || len(got) == 0 {
		return false
	}
	for _, candidate := range got {
		for _, expected := range want {
			if candidate == expected {
				return true
			}
		}
	}
	return false
}

func verifyBytes(algorithm Algorithm, key crypto.PublicKey, input, signature []byte) bool {
	switch algorithm {
	case EdDSA:
		public, ok := key.(ed25519.PublicKey)
		return ok && ed25519.Verify(public, input, signature)
	case ES256:
		digest := sha256.Sum256(input)
		return verifyECDSA(key, digest[:], signature, 32)
	case ES512:
		digest := sha512.Sum512(input)
		return verifyECDSA(key, digest[:], signature, 66)
	case PS256:
		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256(input)
		return rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) == nil
	case RS256:
		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) == nil
	default:
		return false
	}
}

func verifyECDSA(key crypto.PublicKey, digest, signature []byte, size int) bool {
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || len(signature) != size*2 {
		return false
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	return ecdsa.Verify(public, digest, r, s)
}
