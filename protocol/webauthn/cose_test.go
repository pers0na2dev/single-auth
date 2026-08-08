package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"testing"
)

func TestCOSESignatureVerificationKeyTypes(t *testing.T) {
	data := []byte("single-auth WebAuthn compatibility vector")

	t.Run("OKP Ed25519", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeCBOR(map[int64]any{1: int64(COSEKTYOKP), 3: int64(COSEAlgEdDSA), -1: int64(COSECurveEd25519), -2: []byte(publicKey)})
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifySignature(encoded, ed25519.Sign(privateKey, data), data)
		if err != nil || !verified {
			t.Fatalf("verified=%v err=%v", verified, err)
		}
	})

	t.Run("EC2 P384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x := privateKey.X.FillBytes(make([]byte, 48))
		y := privateKey.Y.FillBytes(make([]byte, 48))
		encoded, err := encodeCBOR(map[int64]any{1: int64(COSEKTYEC2), 3: int64(COSEAlgES384), -1: int64(COSECurveP384), -2: x, -3: y})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha512.Sum384(data)
		signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifySignature(encoded, signature, data)
		if err != nil || !verified {
			t.Fatalf("verified=%v err=%v", verified, err)
		}
	})

	t.Run("RSA PKCS1 and PSS", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		exponent := big.NewInt(int64(privateKey.E)).Bytes()
		for _, test := range []struct {
			name      string
			algorithm int
			sign      func([]byte) ([]byte, error)
		}{
			{"RS256", COSEAlgRS256, func(digest []byte) ([]byte, error) {
				return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
			}},
			{"PS256", COSEAlgPS256, func(digest []byte) ([]byte, error) {
				return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				encoded, err := encodeCBOR(map[int64]any{1: int64(COSEKTYRSA), 3: int64(test.algorithm), -1: privateKey.N.Bytes(), -2: exponent})
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(data)
				signature, err := test.sign(digest[:])
				if err != nil {
					t.Fatal(err)
				}
				verified, err := VerifySignature(encoded, signature, data)
				if err != nil || !verified {
					t.Fatalf("verified=%v err=%v", verified, err)
				}
			})
		}
	})
}
