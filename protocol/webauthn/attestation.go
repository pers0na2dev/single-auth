package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

type attestationVerificationInput struct {
	Format                   string
	Statement                map[string]any
	AuthData                 []byte
	ClientDataHash           []byte
	ParsedAuthData           ParsedAuthenticatorData
	CredentialPublicKey      COSEPublicKey
	Roots                    map[string]*x509.CertPool
	Now                      func() time.Time
	SafetyNetEnforceCTSCheck bool
}

func verifyAttestation(input attestationVerificationInput) (bool, error) {
	switch input.Format {
	case "none":
		if len(input.Statement) != 0 {
			return false, errors.New("none attestation had unexpected attestation statement")
		}
		return true, nil
	case "packed":
		return verifyPackedAttestation(input)
	case "fido-u2f":
		return verifyFIDOU2FAttestation(input)
	case "android-key":
		return verifyAndroidKeyAttestation(input)
	case "android-safetynet":
		return verifyAndroidSafetyNetAttestation(input)
	case "apple":
		return verifyAppleAttestation(input)
	case "tpm":
		return verifyTPMAttestation(input)
	default:
		return false, fmt.Errorf("unsupported attestation format: %s", input.Format)
	}
}

func verifyPackedAttestation(input attestationVerificationInput) (bool, error) {
	signature, err := byteString(input.Statement["sig"], "attestation signature (Packed)")
	if err != nil {
		return false, err
	}
	algorithm, err := integer(input.Statement["alg"], "attestation alg (Packed)")
	if err != nil {
		return false, err
	}
	if !isSupportedCOSEAlgorithm(algorithm) {
		return false, fmt.Errorf("attestation statement contained invalid alg %d (Packed)", algorithm)
	}
	signatureBase := concatenate(input.AuthData, input.ClientDataHash)
	if x5cValue, exists := input.Statement["x5c"]; exists {
		certificates, err := byteStringArray(x5cValue, "attestation x5c (Packed)")
		if err != nil {
			return false, err
		}
		if len(certificates) == 0 {
			return false, errors.New("no certificates present in x5c array (Packed)")
		}
		leaf, err := x509.ParseCertificate(certificates[0])
		if err != nil {
			return false, fmt.Errorf("parse attestation certificate (Packed): %w", err)
		}
		if leaf.Subject.OrganizationalUnit == nil || leaf.Subject.OrganizationalUnit[0] != "Authenticator Attestation" {
			return false, errors.New("certificate OU was not \"Authenticator Attestation\" (Packed|Full)")
		}
		if leaf.Subject.CommonName == "" {
			return false, errors.New("certificate CN was empty (Packed|Full)")
		}
		if len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] == "" {
			return false, errors.New("certificate O was empty (Packed|Full)")
		}
		if len(leaf.Subject.Country) == 0 || len(leaf.Subject.Country[0]) != 2 {
			return false, errors.New("certificate C was not two-character ISO 3166 code (Packed|Full)")
		}
		if leaf.IsCA {
			return false, errors.New("certificate basic constraints CA was not false (Packed|Full)")
		}
		if leaf.Version != 3 {
			return false, errors.New("certificate version was not 3 (ASN.1 value of 2) (Packed|Full)")
		}
		if err := verifyCertificateTime(leaf, input.Now); err != nil {
			return false, fmt.Errorf("%w (Packed|Full)", err)
		}
		if err := validateFIDOAAGUIDExtension(leaf, input.ParsedAuthData.AAGUID); err != nil {
			return false, fmt.Errorf("%w (Packed|Full)", err)
		}
		if err := validateCertificatePath(certificates, rootPool(input, "packed"), input.Now); err != nil {
			return false, fmt.Errorf("%w (Packed|Full)", err)
		}
		return verifyCertificateSignature(certificates[0], signature, signatureBase, nil)
	}
	return verifyCryptoSignatureForCOSE(input.CredentialPublicKey, algorithm, signature, signatureBase)
}

func verifyFIDOU2FAttestation(input attestationVerificationInput) (bool, error) {
	certificates, err := byteStringArray(input.Statement["x5c"], "attestation x5c (FIDOU2F)")
	if err != nil || len(certificates) == 0 {
		return false, errors.New("no attestation certificate provided in attestation statement (FIDOU2F)")
	}
	signature, err := byteString(input.Statement["sig"], "attestation signature (FIDOU2F)")
	if err != nil {
		return false, errors.New("no attestation signature provided in attestation statement (FIDOU2F)")
	}
	for _, value := range input.ParsedAuthData.AAGUID {
		if value != 0 {
			return false, fmt.Errorf("AAGUID %x was not expected value", input.ParsedAuthData.AAGUID)
		}
	}
	publicKey, err := cosePublicKeyBytes(input.CredentialPublicKey)
	if err != nil {
		return false, err
	}
	signatureBase := concatenate([]byte{0x00}, input.ParsedAuthData.RPIDHash, input.ClientDataHash, input.ParsedAuthData.CredentialID, publicKey)
	if err := validateCertificatePath(certificates, rootPool(input, "fido-u2f"), input.Now); err != nil {
		return false, fmt.Errorf("%w (FIDOU2F)", err)
	}
	algorithm := COSEAlgES256
	return verifyCertificateSignature(certificates[0], signature, signatureBase, &algorithm)
}

func verifyCryptoSignatureForCOSE(key COSEPublicKey, algorithm int, signature, data []byte) (bool, error) {
	publicKey, err := key.CryptoPublicKey()
	if err != nil {
		return false, err
	}
	return verifyCryptoSignature(publicKey, algorithm, signature, data)
}

func rootPool(input attestationVerificationInput, format string) *x509.CertPool {
	if input.Roots == nil {
		return defaultAttestationRootPool(format)
	}
	return input.Roots[format]
}

func validateCertificatePath(certificates [][]byte, roots *x509.CertPool, now func() time.Time) error {
	// SimpleWebAuthn intentionally skips path validation when no trust anchors
	// are configured for a format.
	if roots == nil {
		return nil
	}
	if len(certificates) == 0 {
		return errors.New("certificate path was empty")
	}
	leaf, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range certificates[1:] {
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil {
			return fmt.Errorf("parse intermediate certificate: %w", err)
		}
		intermediates.AddCert(certificate)
	}
	currentTime := time.Now()
	if now != nil {
		currentTime = now()
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: currentTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("validate certificate path: %w", err)
	}
	return nil
}

func verifyCertificateTime(certificate *x509.Certificate, now func() time.Time) error {
	currentTime := time.Now()
	if now != nil {
		currentTime = now()
	}
	if currentTime.Before(certificate.NotBefore) {
		return fmt.Errorf("certificate not good before %q", certificate.NotBefore)
	}
	if currentTime.After(certificate.NotAfter) {
		return fmt.Errorf("certificate not good after %q", certificate.NotAfter)
	}
	return nil
}

var oidFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

func validateFIDOAAGUIDExtension(certificate *x509.Certificate, aaguid []byte) error {
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidFIDOGenCEAAGUID) {
			continue
		}
		var extensionValue []byte
		if rest, err := asn1.Unmarshal(extension.Value, &extensionValue); err != nil || len(rest) != 0 {
			return errors.New("could not parse certificate id-fido-gen-ce-aaguid extension")
		}
		if !bytes.Equal(extensionValue, aaguid) {
			return fmt.Errorf("certificate extension id-fido-gen-ce-aaguid value %x was present but not equal to attestation statement AAGUID value %x", extensionValue, aaguid)
		}
		return nil
	}
	return nil
}

func publicKeysEqual(first any, second COSEPublicKey) (bool, error) {
	secondKey, err := second.CryptoPublicKey()
	if err != nil {
		return false, err
	}
	switch firstKey := first.(type) {
	case *ecdsa.PublicKey:
		other, ok := secondKey.(*ecdsa.PublicKey)
		return ok && firstKey.Curve == other.Curve && firstKey.X.Cmp(other.X) == 0 && firstKey.Y.Cmp(other.Y) == 0, nil
	case *rsa.PublicKey:
		other, ok := secondKey.(*rsa.PublicKey)
		return ok && firstKey.E == other.E && firstKey.N.Cmp(other.N) == 0, nil
	case ed25519.PublicKey:
		other, ok := secondKey.(ed25519.PublicKey)
		return ok && bytes.Equal(firstKey, other), nil
	default:
		return false, fmt.Errorf("unsupported certificate public key type %T", first)
	}
}

func isSupportedCOSEAlgorithm(algorithm int) bool {
	switch algorithm {
	case COSEAlgEdDSA, COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgPS256, COSEAlgPS384, COSEAlgPS512, COSEAlgES256K, COSEAlgRS256, COSEAlgRS384, COSEAlgRS512, COSEAlgRS1:
		return true
	default:
		return false
	}
}

func concatenate(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		total += len(part)
	}
	result := make([]byte, 0, total)
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}
