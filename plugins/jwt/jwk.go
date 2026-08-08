package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var rawURL = base64.RawURLEncoding

func generateExportedKeyPair(options Options, random io.Reader) (ExportedKeyPair, error) {
	config := KeyPairConfig{Algorithm: EdDSA, Curve: "Ed25519"}
	if options.JWKS.KeyPair != nil {
		config = *options.JWKS.KeyPair
	}
	switch config.Algorithm {
	case EdDSA:
		if config.Curve == "" {
			config.Curve = "Ed25519"
		}
		if config.Curve != "Ed25519" {
			return ExportedKeyPair{}, fmt.Errorf("jwt: unsupported EdDSA curve %q", config.Curve)
		}
		public, private, err := ed25519.GenerateKey(random)
		if err != nil {
			return ExportedKeyPair{}, err
		}
		publicJWK := map[string]any{
			"crv": "Ed25519", "kty": "OKP", "x": rawURL.EncodeToString(public),
		}
		privateJWK := cloneMap(publicJWK)
		privateJWK["d"] = rawURL.EncodeToString(private.Seed())
		return ExportedKeyPair{PublicKey: publicJWK, PrivateKey: privateJWK, Algorithm: EdDSA, Curve: config.Curve}, nil
	case ES256, ES512:
		curve := elliptic.P256()
		curveName := "P-256"
		if config.Algorithm == ES512 {
			curve = elliptic.P521()
			curveName = "P-521"
		}
		private, err := ecdsa.GenerateKey(curve, random)
		if err != nil {
			return ExportedKeyPair{}, err
		}
		coordinateSize := (curve.Params().BitSize + 7) / 8
		publicJWK := map[string]any{
			"crv": curveName,
			"kty": "EC",
			"x":   rawURL.EncodeToString(leftPad(private.X.Bytes(), coordinateSize)),
			"y":   rawURL.EncodeToString(leftPad(private.Y.Bytes(), coordinateSize)),
		}
		privateJWK := cloneMap(publicJWK)
		privateJWK["d"] = rawURL.EncodeToString(leftPad(private.D.Bytes(), coordinateSize))
		return ExportedKeyPair{PublicKey: publicJWK, PrivateKey: privateJWK, Algorithm: config.Algorithm, Curve: curveName}, nil
	case PS256, RS256:
		bits := config.ModulusLength
		if bits == 0 {
			bits = 2048
		}
		private, err := rsa.GenerateKey(random, bits)
		if err != nil {
			return ExportedKeyPair{}, err
		}
		private.Precompute()
		publicJWK := map[string]any{
			"kty": "RSA",
			"n":   rawURL.EncodeToString(private.N.Bytes()),
			"e":   rawURL.EncodeToString(big.NewInt(int64(private.E)).Bytes()),
		}
		privateJWK := cloneMap(publicJWK)
		privateJWK["d"] = rawURL.EncodeToString(private.D.Bytes())
		if len(private.Primes) >= 2 {
			privateJWK["p"] = rawURL.EncodeToString(private.Primes[0].Bytes())
			privateJWK["q"] = rawURL.EncodeToString(private.Primes[1].Bytes())
		}
		if private.Precomputed.Dp != nil {
			privateJWK["dp"] = rawURL.EncodeToString(private.Precomputed.Dp.Bytes())
		}
		if private.Precomputed.Dq != nil {
			privateJWK["dq"] = rawURL.EncodeToString(private.Precomputed.Dq.Bytes())
		}
		if private.Precomputed.Qinv != nil {
			privateJWK["qi"] = rawURL.EncodeToString(private.Precomputed.Qinv.Bytes())
		}
		return ExportedKeyPair{PublicKey: publicJWK, PrivateKey: privateJWK, Algorithm: config.Algorithm}, nil
	default:
		return ExportedKeyPair{}, fmt.Errorf("jwt: unsupported JWS algorithm %q", config.Algorithm)
	}
}

// GenerateExportedKeyPair generates an extractable public/private JWK pair.
// It snapshots options and uses Runtime.Random, defaulting to crypto/rand.
func GenerateExportedKeyPair(options Options) (ExportedKeyPair, error) {
	normalized, err := normalize(options, false)
	if err != nil {
		return ExportedKeyPair{}, err
	}
	return generateExportedKeyPair(normalized.options, normalized.random)
}

func marshalJWK(value map[string]any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func parseJWK(value string) (map[string]any, error) {
	var result map[string]any
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("jwt: JWK is not an object")
	}
	return result, nil
}

func jwkPublicKey(jwk map[string]any, algorithm Algorithm) (crypto.PublicKey, error) {
	switch algorithm {
	case EdDSA:
		x, err := jwkBytes(jwk, "x")
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("jwt: invalid Ed25519 public JWK")
		}
		return ed25519.PublicKey(append([]byte(nil), x...)), nil
	case ES256, ES512:
		xBytes, err := jwkBytes(jwk, "x")
		if err != nil {
			return nil, err
		}
		yBytes, err := jwkBytes(jwk, "y")
		if err != nil {
			return nil, err
		}
		curve := elliptic.P256()
		curveName := "P-256"
		if algorithm == ES512 {
			curve = elliptic.P521()
			curveName = "P-521"
		}
		if name, _ := jwk["crv"].(string); name != "" && name != curveName {
			return nil, fmt.Errorf("jwt: JWK curve %q does not match %s", name, algorithm)
		}
		x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("jwt: EC public JWK point is invalid")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case PS256, RS256:
		nBytes, err := jwkBytes(jwk, "n")
		if err != nil {
			return nil, err
		}
		eBytes, err := jwkBytes(jwk, "e")
		if err != nil {
			return nil, err
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Sign() <= 0 {
			return nil, errors.New("jwt: RSA exponent is invalid")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
	default:
		return nil, fmt.Errorf("jwt: unsupported JWS algorithm %q", algorithm)
	}
}

func jwkPrivateKey(jwk map[string]any, algorithm Algorithm) (crypto.PrivateKey, error) {
	switch algorithm {
	case EdDSA:
		d, err := jwkBytes(jwk, "d")
		if err != nil || len(d) != ed25519.SeedSize {
			return nil, errors.New("jwt: invalid Ed25519 private JWK")
		}
		return ed25519.NewKeyFromSeed(d), nil
	case ES256, ES512:
		public, err := jwkPublicKey(jwk, algorithm)
		if err != nil {
			return nil, err
		}
		d, err := jwkBytes(jwk, "d")
		if err != nil {
			return nil, err
		}
		return &ecdsa.PrivateKey{PublicKey: *(public.(*ecdsa.PublicKey)), D: new(big.Int).SetBytes(d)}, nil
	case PS256, RS256:
		public, err := jwkPublicKey(jwk, algorithm)
		if err != nil {
			return nil, err
		}
		d, err := jwkBytes(jwk, "d")
		if err != nil {
			return nil, err
		}
		p, err := jwkBytes(jwk, "p")
		if err != nil {
			return nil, err
		}
		q, err := jwkBytes(jwk, "q")
		if err != nil {
			return nil, err
		}
		private := &rsa.PrivateKey{
			PublicKey: *(public.(*rsa.PublicKey)),
			D:         new(big.Int).SetBytes(d),
			Primes:    []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)},
		}
		if err := private.Validate(); err != nil {
			return nil, err
		}
		private.Precompute()
		return private, nil
	default:
		return nil, fmt.Errorf("jwt: unsupported JWS algorithm %q", algorithm)
	}
}

func jwkBytes(jwk map[string]any, name string) ([]byte, error) {
	value, ok := jwk[name].(string)
	if !ok || value == "" {
		return nil, fmt.Errorf("jwt: JWK field %q is missing", name)
	}
	decoded, err := rawURL.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("jwt: decode JWK field %q: %w", name, err)
	}
	return decoded, nil
}

func leftPad(value []byte, size int) []byte {
	if len(value) >= size {
		return append([]byte(nil), value...)
	}
	result := make([]byte, size)
	copy(result[size-len(value):], value)
	return result
}
