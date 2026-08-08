package webauthn

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	oidAndroidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	oidAppleWebAuthnNonce    = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
)

func verifyAndroidKeyAttestation(input attestationVerificationInput) (bool, error) {
	certificates, err := byteStringArray(input.Statement["x5c"], "attestation x5c (Android Key)")
	if err != nil || len(certificates) == 0 {
		return false, errors.New("no attestation certificate provided in attestation statement (Android Key)")
	}
	signature, err := byteString(input.Statement["sig"], "attestation signature (Android Key)")
	if err != nil {
		return false, errors.New("no attestation signature provided in attestation statement (Android Key)")
	}
	algorithm, err := integer(input.Statement["alg"], "attestation alg (Android Key)")
	if err != nil {
		return false, errors.New("attestation statement did not contain alg (Android Key)")
	}
	if !isSupportedCOSEAlgorithm(algorithm) {
		return false, fmt.Errorf("attestation statement contained invalid alg %d (Android Key)", algorithm)
	}
	leaf, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return false, fmt.Errorf("parse leaf certificate (Android Key): %w", err)
	}
	equal, err := publicKeysEqual(leaf.PublicKey, input.CredentialPublicKey)
	if err != nil {
		return false, err
	}
	if !equal {
		return false, errors.New("credential public key does not equal leaf cert public key (Android Key)")
	}

	var keyDescriptionExtension []byte
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(oidAndroidKeyDescription) {
			keyDescriptionExtension = extension.Value
			break
		}
	}
	if len(keyDescriptionExtension) == 0 {
		return false, errors.New("certificate did not contain extKeyStore (Android Key)")
	}
	description, err := parseAndroidKeyDescription(keyDescriptionExtension)
	if err != nil {
		return false, fmt.Errorf("parse extKeyStore (Android Key): %w", err)
	}
	if !bytes.Equal(description.Challenge, input.ClientDataHash) {
		return false, errors.New("attestation challenge was not equal to client data hash (Android Key)")
	}
	if containsASN1ContextTag(description.TEEEnforced, 600) {
		return false, errors.New("teeEnforced contained allApplications [600] tag (Android Key)")
	}
	if containsASN1ContextTag(description.SoftwareEnforced, 600) {
		return false, errors.New("softwareEnforced contained allApplications [600] tag (Android Key)")
	}
	if err := validateAndroidKeyCertificatePath(certificates, rootPool(input, "android-key"), input.Now); err != nil {
		return false, fmt.Errorf("%w (Android Key)", err)
	}
	signatureBase := concatenate(input.AuthData, input.ClientDataHash)
	return verifyCertificateSignature(certificates[0], signature, signatureBase, &algorithm)
}

// Android Key attestations are unusual: the authenticator supplies the root as
// the final x5c entry. SimpleWebAuthn always validates the preceding chain to
// that root, even when the configured trusted-root list is empty, and only then
// applies the configured Google-root allow-list.
func validateAndroidKeyCertificatePath(certificates [][]byte, trustedRoots *x509.CertPool, now func() time.Time) error {
	if len(certificates) == 0 {
		return errors.New("certificate path was empty")
	}
	providedRoot, err := x509.ParseCertificate(certificates[len(certificates)-1])
	if err != nil {
		return fmt.Errorf("parse x5c root certificate: %w", err)
	}
	if err := verifyCertificateTime(providedRoot, now); err != nil {
		return err
	}
	if len(certificates) > 1 {
		providedRoots := x509.NewCertPool()
		providedRoots.AddCert(providedRoot)
		if err := validateCertificatePath(certificates[:len(certificates)-1], providedRoots, now); err != nil {
			return err
		}
	}
	if trustedRoots == nil {
		return nil
	}
	currentTime := time.Now()
	if now != nil {
		currentTime = now()
	}
	if _, err := providedRoot.Verify(x509.VerifyOptions{
		Roots:       trustedRoots,
		CurrentTime: currentTime,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return errors.New("x5c root certificate was not a known root certificate")
	}
	return nil
}

type androidKeyDescription struct {
	Challenge        []byte
	SoftwareEnforced asn1.RawValue
	TEEEnforced      asn1.RawValue
}

func parseAndroidKeyDescription(encoded []byte) (androidKeyDescription, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &sequence)
	if err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return androidKeyDescription{}, errors.New("invalid KeyDescription sequence")
	}
	content := sequence.Bytes
	fields := make([]asn1.RawValue, 0, 8)
	for len(content) != 0 {
		var field asn1.RawValue
		content, err = asn1.Unmarshal(content, &field)
		if err != nil {
			return androidKeyDescription{}, err
		}
		fields = append(fields, field)
		if len(fields) > 8 {
			return androidKeyDescription{}, errors.New("KeyDescription had too many fields")
		}
	}
	if len(fields) != 8 || fields[4].Tag != asn1.TagOctetString {
		return androidKeyDescription{}, fmt.Errorf("KeyDescription had %d fields, expected 8", len(fields))
	}
	return androidKeyDescription{
		Challenge:        append([]byte(nil), fields[4].Bytes...),
		SoftwareEnforced: fields[6],
		TEEEnforced:      fields[7],
	}, nil
}

func containsASN1ContextTag(value asn1.RawValue, tag int) bool {
	if value.Class == asn1.ClassContextSpecific && value.Tag == tag {
		return true
	}
	if !value.IsCompound {
		return false
	}
	rest := value.Bytes
	for len(rest) != 0 {
		var child asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &child)
		if err != nil {
			return false
		}
		if containsASN1ContextTag(child, tag) {
			return true
		}
	}
	return false
}

func verifyAppleAttestation(input attestationVerificationInput) (bool, error) {
	certificates, err := byteStringArray(input.Statement["x5c"], "attestation x5c (Apple)")
	if err != nil || len(certificates) == 0 {
		return false, errors.New("no attestation certificate provided in attestation statement (Apple)")
	}
	if err := validateCertificatePath(certificates, rootPool(input, "apple"), input.Now); err != nil {
		return false, fmt.Errorf("%w (Apple)", err)
	}
	leaf, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return false, fmt.Errorf("parse credCert (Apple): %w", err)
	}
	var extensionValue []byte
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(oidAppleWebAuthnNonce) {
			extensionValue = extension.Value
			break
		}
	}
	if len(extensionValue) == 0 {
		return false, errors.New("credCert missing 1.2.840.113635.100.8.2 extension (Apple)")
	}
	// Apple encodes the nonce as SEQUENCE { [1] EXPLICIT OCTET STRING }.
	if len(extensionValue) != 38 || !bytes.Equal(extensionValue[:6], []byte{0x30, 0x24, 0xa1, 0x22, 0x04, 0x20}) {
		return false, errors.New("credCert nonce extension had unexpected ASN.1 structure (Apple)")
	}
	nonce := sha256.Sum256(concatenate(input.AuthData, input.ClientDataHash))
	if !bytes.Equal(nonce[:], extensionValue[6:]) {
		return false, errors.New("credCert nonce was not expected value (Apple)")
	}
	equal, err := publicKeysEqual(leaf.PublicKey, input.CredentialPublicKey)
	if err != nil {
		return false, err
	}
	if !equal {
		return false, errors.New("credential public key does not equal credCert public key (Apple)")
	}
	return true, nil
}

type safetyNetHeader struct {
	Algorithm string   `json:"alg"`
	X5C       []string `json:"x5c"`
}

type safetyNetPayload struct {
	Nonce           string `json:"nonce"`
	TimestampMS     int64  `json:"timestampMs"`
	CTSProfileMatch bool   `json:"ctsProfileMatch"`
}

func verifyAndroidSafetyNetAttestation(input attestationVerificationInput) (bool, error) {
	if _, err := stringField(input.Statement["ver"], "attestation ver (SafetyNet)"); err != nil {
		return false, errors.New("no ver value in attestation (SafetyNet)")
	}
	response, err := byteString(input.Statement["response"], "attestation response (SafetyNet)")
	if err != nil {
		return false, errors.New("no response was included in attStmt by authenticator (SafetyNet)")
	}
	parts := strings.Split(string(response), ".")
	if len(parts) != 3 {
		return false, errors.New("SafetyNet response was not a compact JWT")
	}
	headerBytes, err := decodeBase64URL(parts[0], "SafetyNet JWT header", MaxClientDataJSONBytes)
	if err != nil {
		return false, err
	}
	payloadBytes, err := decodeBase64URL(parts[1], "SafetyNet JWT payload", MaxClientDataJSONBytes)
	if err != nil {
		return false, err
	}
	var header safetyNetHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false, fmt.Errorf("decode SafetyNet JWT header: %w", err)
	}
	var payload safetyNetPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false, fmt.Errorf("decode SafetyNet JWT payload: %w", err)
	}
	currentTime := time.Now()
	if input.Now != nil {
		currentTime = input.Now()
	}
	nowMS := currentTime.UnixMilli()
	if payload.TimestampMS > nowMS {
		return false, fmt.Errorf("payload timestamp %q was later than %q (SafetyNet)", payload.TimestampMS, nowMS)
	}
	if payload.TimestampMS+60_000 < nowMS {
		return false, fmt.Errorf("payload timestamp %q has expired (SafetyNet)", payload.TimestampMS+60_000)
	}
	nonce := sha256.Sum256(concatenate(input.AuthData, input.ClientDataHash))
	if payload.Nonce != base64.StdEncoding.EncodeToString(nonce[:]) {
		return false, errors.New("could not verify payload nonce (SafetyNet)")
	}
	if input.SafetyNetEnforceCTSCheck && !payload.CTSProfileMatch {
		return false, errors.New("could not verify device integrity (SafetyNet)")
	}
	if len(header.X5C) == 0 {
		return false, errors.New("SafetyNet JWT header did not contain x5c")
	}
	certificates := make([][]byte, len(header.X5C))
	for index, encoded := range header.X5C {
		certificates[index], err = decodeBase64(encoded, fmt.Sprintf("SafetyNet x5c[%d]", index), MaxAttestationObjectBytes)
		if err != nil {
			return false, err
		}
	}
	leaf, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return false, fmt.Errorf("parse SafetyNet leaf certificate: %w", err)
	}
	if leaf.Subject.CommonName != "attest.android.com" {
		return false, errors.New("certificate common name was not attest.android.com (SafetyNet)")
	}
	if err := validateCertificatePath(certificates, rootPool(input, "android-safetynet"), input.Now); err != nil {
		return false, fmt.Errorf("%w (SafetyNet)", err)
	}
	signature, err := decodeBase64URL(parts[2], "SafetyNet JWT signature", MaxSignatureBytes)
	if err != nil {
		return false, err
	}
	return verifyCertificateSignature(certificates[0], signature, []byte(parts[0]+"."+parts[1]), nil)
}
