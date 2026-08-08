package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	pkcs8 "github.com/youmark/pkcs8"
)

// ParseDecryptionPrivateKeyPEM parses the RSA private key used to unwrap an
// XML Encryption content key. Samlify's public encrypted-assertion contract is
// RSA-only even though SAML signatures may also use ECDSA keys.
func ParseDecryptionPrivateKeyPEM(value []byte, password string) (*rsa.PrivateKey, error) {
	signer, err := ParsePrivateKeyPEM(value, password)
	if err != nil {
		return nil, newError(
			"SAML_DECRYPTION_KEY_INVALID",
			"Invalid SAML assertion decryption private key or password",
			err,
		)
	}
	privateKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return nil, newError(
			"SAML_DECRYPTION_KEY_INVALID",
			fmt.Sprintf("Unsupported SAML assertion decryption private key type %T", signer),
		)
	}
	return privateKey, nil
}

// ParsePrivateKeyPEM parses RSA or ECDSA PKCS#1, SEC1, PKCS#8, legacy
// encrypted PEM, and encrypted PKCS#8 keys used by SAML SP configurations.
func ParsePrivateKeyPEM(value []byte, password string) (crypto.Signer, error) {
	lines := strings.Split(string(value), "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	value = []byte(strings.TrimSpace(strings.Join(lines, "\n")) + "\n")
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, newError("SAML_SIGNING_KEY_INVALID", "Invalid SAML signing private key")
	}
	der := block.Bytes
	var err error
	if x509.IsEncryptedPEMBlock(block) {
		der, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, newError("SAML_SIGNING_KEY_INVALID", "Invalid SAML signing private key or password", err)
		}
	}
	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(der)
	case "ENCRYPTED PRIVATE KEY":
		key, err = pkcs8.ParsePKCS8PrivateKey(der, []byte(password))
	default:
		key, err = x509.ParsePKCS8PrivateKey(der)
		if err != nil && password != "" {
			key, err = pkcs8.ParsePKCS8PrivateKey(der, []byte(password))
		}
	}
	if err != nil {
		return nil, newError("SAML_SIGNING_KEY_INVALID", "Invalid SAML signing private key", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, newError(
			"SAML_SIGNING_KEY_INVALID",
			fmt.Sprintf("Unsupported SAML signing private key type %T", key),
		)
	}
	return signer, nil
}
