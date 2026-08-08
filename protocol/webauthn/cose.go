package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

const (
	COSEKTYOKP = 1
	COSEKTYEC2 = 2
	COSEKTYRSA = 3

	COSECurveP256      = 1
	COSECurveP384      = 2
	COSECurveP521      = 3
	COSECurveEd25519   = 6
	COSECurveSecp256k1 = 8
)

type COSEPublicKey struct {
	KTY   int
	Alg   int
	Curve int
	X     []byte
	Y     []byte
	N     []byte
	E     []byte
	Raw   map[int64]any
}

func DecodeCredentialPublicKey(encoded []byte) (COSEPublicKey, error) {
	if len(encoded) == 0 {
		return COSEPublicKey{}, errors.New("credential public key was empty")
	}
	if len(encoded) > MaxCredentialPublicKeyBytes {
		return COSEPublicKey{}, fmt.Errorf("%w: credential public key was %d bytes", ErrInputTooLarge, len(encoded))
	}
	var values map[int64]any
	if err := decodeCBORExact(encoded, &values); err != nil {
		return COSEPublicKey{}, fmt.Errorf("decode credential public key: %w", err)
	}
	keyType, err := integer(values[1], "credential public key kty")
	if err != nil {
		return COSEPublicKey{}, err
	}
	algorithm, err := integer(values[3], "credential public key alg")
	if err != nil {
		return COSEPublicKey{}, err
	}
	key := COSEPublicKey{KTY: keyType, Alg: algorithm, Raw: values}
	switch keyType {
	case COSEKTYEC2:
		key.Curve, err = integer(values[-1], "credential public key crv")
		if err != nil {
			return COSEPublicKey{}, err
		}
		key.X, err = byteString(values[-2], "credential public key x")
		if err != nil {
			return COSEPublicKey{}, err
		}
		key.Y, err = byteString(values[-3], "credential public key y")
		if err != nil {
			return COSEPublicKey{}, err
		}
	case COSEKTYRSA:
		key.N, err = byteString(values[-1], "credential public key n")
		if err != nil {
			return COSEPublicKey{}, err
		}
		key.E, err = byteString(values[-2], "credential public key e")
		if err != nil {
			return COSEPublicKey{}, err
		}
	case COSEKTYOKP:
		key.Curve, err = integer(values[-1], "credential public key crv")
		if err != nil {
			return COSEPublicKey{}, err
		}
		key.X, err = byteString(values[-2], "credential public key x")
		if err != nil {
			return COSEPublicKey{}, err
		}
	default:
		return COSEPublicKey{}, fmt.Errorf("signature verification with public key of kty %d is not supported by this method", keyType)
	}
	return key, nil
}

func (key COSEPublicKey) CryptoPublicKey() (crypto.PublicKey, error) {
	switch key.KTY {
	case COSEKTYEC2:
		var curve elliptic.Curve
		coordinateSize := 0
		switch key.Curve {
		case COSECurveP256:
			curve, coordinateSize = elliptic.P256(), 32
		case COSECurveP384:
			curve, coordinateSize = elliptic.P384(), 48
		case COSECurveP521:
			curve, coordinateSize = elliptic.P521(), 66
		default:
			return nil, fmt.Errorf("unexpected COSE crv value of %d (EC2)", key.Curve)
		}
		if len(key.X) != coordinateSize || len(key.Y) != coordinateSize {
			return nil, fmt.Errorf("invalid EC2 coordinate length x=%d y=%d for curve %d", len(key.X), len(key.Y), key.Curve)
		}
		x := new(big.Int).SetBytes(key.X)
		y := new(big.Int).SetBytes(key.Y)
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("credential public key point was not on its declared curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case COSEKTYRSA:
		if len(key.N) < 128 || len(key.N) > MaxCredentialPublicKeyBytes {
			return nil, fmt.Errorf("invalid RSA modulus length %d", len(key.N))
		}
		if len(key.E) == 0 || len(key.E) > 4 {
			return nil, fmt.Errorf("invalid RSA exponent length %d", len(key.E))
		}
		exponent := 0
		for _, value := range key.E {
			exponent = exponent<<8 | int(value)
		}
		if exponent < 3 || exponent%2 == 0 {
			return nil, fmt.Errorf("invalid RSA exponent %d", exponent)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(key.N), E: exponent}, nil
	case COSEKTYOKP:
		if key.Curve != COSECurveEd25519 {
			return nil, fmt.Errorf("unexpected COSE crv value of %d (OKP)", key.Curve)
		}
		if len(key.X) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key length %d", len(key.X))
		}
		return ed25519.PublicKey(append([]byte(nil), key.X...)), nil
	default:
		return nil, fmt.Errorf("unsupported COSE key type %d", key.KTY)
	}
}

func VerifySignature(credentialPublicKey, signature, data []byte) (bool, error) {
	key, err := DecodeCredentialPublicKey(credentialPublicKey)
	if err != nil {
		return false, err
	}
	publicKey, err := key.CryptoPublicKey()
	if err != nil {
		return false, err
	}
	return verifyCryptoSignature(publicKey, key.Alg, signature, data)
}

func verifyCertificateSignature(certificateDER, signature, data []byte, algorithmOverride *int) (bool, error) {
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return false, fmt.Errorf("parse attestation certificate: %w", err)
	}
	keyAlgorithm, err := coseAlgorithmForCertificate(certificate)
	if err != nil {
		return false, err
	}
	hashAlgorithm := keyAlgorithm
	if algorithmOverride != nil {
		hashAlgorithm = *algorithmOverride
	}
	return verifyCryptoSignatureWithAlgorithms(certificate.PublicKey, keyAlgorithm, hashAlgorithm, signature, data)
}

func verifyCryptoSignature(publicKey crypto.PublicKey, algorithm int, signature, data []byte) (bool, error) {
	return verifyCryptoSignatureWithAlgorithms(publicKey, algorithm, algorithm, signature, data)
}

// SimpleWebAuthn treats an attestation hash override as exactly that: the
// certificate-derived key algorithm still selects RSA-PSS versus PKCS#1 v1.5,
// while the attestation alg selects the digest. For EC keys the primitive is
// always ECDSA.
func verifyCryptoSignatureWithAlgorithms(publicKey crypto.PublicKey, keyAlgorithm, hashAlgorithm int, signature, data []byte) (bool, error) {
	if len(signature) == 0 {
		return false, errors.New("signature was empty")
	}
	if len(signature) > MaxSignatureBytes {
		return false, fmt.Errorf("%w: signature was %d bytes", ErrInputTooLarge, len(signature))
	}
	if !isSupportedCOSEAlgorithm(keyAlgorithm) {
		return false, fmt.Errorf("public key had invalid alg %d", keyAlgorithm)
	}
	if !isSupportedCOSEAlgorithm(hashAlgorithm) {
		return false, fmt.Errorf("invalid signature hash algorithm %d", hashAlgorithm)
	}
	if key, ok := publicKey.(ed25519.PublicKey); ok {
		// SimpleWebAuthn dispatches by key type; certificate signature metadata
		// is not used to choose a different primitive for an OKP subject key.
		return ed25519.Verify(key, data, signature), nil
	}
	if pointer, ok := publicKey.(*ed25519.PublicKey); ok {
		return ed25519.Verify(*pointer, data, signature), nil
	}

	hash, digest, err := hashForCOSEAlgorithm(hashAlgorithm, data)
	if err != nil {
		return false, err
	}
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		// The X.509 certificate may itself be signed with RSA while its subject
		// key is EC. Upstream uses the certificate algorithm only as a SHA
		// selector and always performs ECDSA for an EC subject key.
		var parsedSignature struct {
			R *big.Int
			S *big.Int
		}
		rest, err := asn1.Unmarshal(signature, &parsedSignature)
		if err != nil || len(rest) != 0 || parsedSignature.R == nil || parsedSignature.S == nil {
			if err == nil {
				err = errors.New("invalid ECDSA signature structure")
			}
			return false, fmt.Errorf("decode ECDSA signature: %w", err)
		}
		return ecdsa.Verify(key, digest, parsedSignature.R, parsedSignature.S), nil
	case *rsa.PublicKey:
		switch keyAlgorithm {
		case COSEAlgRS256, COSEAlgRS384, COSEAlgRS512, COSEAlgRS1:
			err = rsa.VerifyPKCS1v15(key, hash, digest, signature)
		case COSEAlgPS256, COSEAlgPS384, COSEAlgPS512:
			err = rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash})
		default:
			return false, fmt.Errorf("RSA key used with COSE algorithm %d", keyAlgorithm)
		}
		if err != nil {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func hashForCOSEAlgorithm(algorithm int, data []byte) (crypto.Hash, []byte, error) {
	switch algorithm {
	case COSEAlgRS1:
		digest := sha1.Sum(data)
		return crypto.SHA1, digest[:], nil
	case COSEAlgES256, COSEAlgPS256, COSEAlgRS256, COSEAlgES256K:
		digest := sha256.Sum256(data)
		return crypto.SHA256, digest[:], nil
	case COSEAlgES384, COSEAlgPS384, COSEAlgRS384:
		digest := sha512.Sum384(data)
		return crypto.SHA384, digest[:], nil
	case COSEAlgEdDSA, COSEAlgES512, COSEAlgPS512, COSEAlgRS512:
		digest := sha512.Sum512(data)
		return crypto.SHA512, digest[:], nil
	default:
		return 0, nil, fmt.Errorf("could not map COSE alg value of %d to a hash", algorithm)
	}
}

func coseAlgorithmForCertificate(certificate *x509.Certificate) (int, error) {
	switch certificate.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		return COSEAlgRS1, nil
	case x509.SHA256WithRSA:
		return COSEAlgRS256, nil
	case x509.SHA384WithRSA:
		return COSEAlgRS384, nil
	case x509.SHA512WithRSA:
		return COSEAlgRS512, nil
	case x509.SHA256WithRSAPSS:
		return COSEAlgPS256, nil
	case x509.SHA384WithRSAPSS:
		return COSEAlgPS384, nil
	case x509.SHA512WithRSAPSS:
		return COSEAlgPS512, nil
	case x509.ECDSAWithSHA256:
		return COSEAlgES256, nil
	case x509.ECDSAWithSHA384:
		return COSEAlgES384, nil
	case x509.ECDSAWithSHA512:
		return COSEAlgES512, nil
	case x509.PureEd25519:
		return COSEAlgEdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported certificate signature algorithm %s", certificate.SignatureAlgorithm)
	}
}

func cosePublicKeyBytes(key COSEPublicKey) ([]byte, error) {
	publicKey, err := key.CryptoPublicKey()
	if err != nil {
		return nil, err
	}
	switch typed := publicKey.(type) {
	case *ecdsa.PublicKey:
		return elliptic.Marshal(typed.Curve, typed.X, typed.Y), nil
	case ed25519.PublicKey:
		return append([]byte{0x04}, typed...), nil
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(typed), nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}
