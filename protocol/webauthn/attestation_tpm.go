package webauthn

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const (
	tmpAlgRSA          = 0x0001
	tmpAlgSHA256       = 0x000b
	tmpAlgSHA384       = 0x000c
	tmpAlgSHA512       = 0x000d
	tmpAlgECC          = 0x0023
	tmpSTAttestCertify = 0x8017
	tmpGeneratedValue  = 0xff544347
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTCGKPAttest            = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	oidTPMManufacturer        = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel               = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion             = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

var knownTPMManufacturers = map[string]struct{}{
	"id:414D4400": {}, "id:414E5400": {}, "id:41544D4C": {},
	"id:4252434D": {}, "id:4353434F": {}, "id:464C5953": {},
	"id:524F4343": {}, "id:474F4F47": {}, "id:48504900": {},
	"id:48504500": {}, "id:48495349": {}, "id:49424d00": {},
	"id:49424D00": {}, "id:49465800": {}, "id:494E5443": {},
	"id:4C454E00": {}, "id:4D534654": {}, "id:4E534D20": {},
	"id:4E545A00": {}, "id:4E534700": {}, "id:4E544300": {},
	"id:51434F4D": {}, "id:534D534E": {}, "id:53454345": {},
	"id:534E5300": {}, "id:534D5343": {}, "id:53544D20": {},
	"id:54584E00": {}, "id:57454300": {}, "id:5345414C": {},
	"id:FFFFF1D0": {},
}

type tpmPublicArea struct {
	Type     uint16
	CurveID  uint16
	Exponent uint32
	Unique   []byte
}

type tpmCertInfo struct {
	Magic              uint32
	Type               uint16
	ExtraData          []byte
	AttestedNameAlg    uint16
	AttestedNameAlgRaw []byte
	AttestedName       []byte
}

func verifyTPMAttestation(input attestationVerificationInput) (bool, error) {
	version, err := stringField(input.Statement["ver"], "attestation ver (TPM)")
	if err != nil || version != "2.0" {
		return false, fmt.Errorf("unexpected ver %q, expected 2.0 (TPM)", version)
	}
	signature, err := byteString(input.Statement["sig"], "attestation signature (TPM)")
	if err != nil {
		return false, errors.New("no attestation signature provided in attestation statement (TPM)")
	}
	algorithm, err := integer(input.Statement["alg"], "attestation alg (TPM)")
	if err != nil {
		return false, errors.New("attestation statement did not contain alg (TPM)")
	}
	if !isSupportedCOSEAlgorithm(algorithm) {
		return false, fmt.Errorf("attestation statement contained invalid alg %d (TPM)", algorithm)
	}
	certificates, err := byteStringArray(input.Statement["x5c"], "attestation x5c (TPM)")
	if err != nil || len(certificates) == 0 {
		return false, errors.New("no attestation certificate provided in attestation statement (TPM)")
	}
	pubAreaBytes, err := byteString(input.Statement["pubArea"], "attestation pubArea (TPM)")
	if err != nil {
		return false, errors.New("attestation statement did not contain pubArea (TPM)")
	}
	certInfoBytes, err := byteString(input.Statement["certInfo"], "attestation certInfo (TPM)")
	if err != nil {
		return false, errors.New("attestation statement did not contain certInfo (TPM)")
	}
	publicArea, err := parseTPMPublicArea(pubAreaBytes)
	if err != nil {
		return false, err
	}
	if err := compareTPMPublicArea(publicArea, input.CredentialPublicKey); err != nil {
		return false, err
	}
	certInfo, err := parseTPMCertInfo(certInfoBytes)
	if err != nil {
		return false, err
	}
	if certInfo.Magic != tmpGeneratedValue {
		return false, fmt.Errorf("unexpected magic value %x, expected ff544347 (TPM)", certInfo.Magic)
	}
	if certInfo.Type != tmpSTAttestCertify {
		return false, fmt.Errorf("unexpected type %x, expected TPM_ST_ATTEST_CERTIFY (TPM)", certInfo.Type)
	}
	nameHashAlgorithm, err := tpmHashAlgorithm(certInfo.AttestedNameAlg)
	if err != nil {
		return false, err
	}
	_, publicAreaHash, err := hashForCOSEAlgorithm(nameHashAlgorithm, pubAreaBytes)
	if err != nil {
		return false, err
	}
	expectedAttestedName := concatenate(certInfo.AttestedNameAlgRaw, publicAreaHash)
	if !bytes.Equal(certInfo.AttestedName, expectedAttestedName) {
		return false, errors.New("attested name comparison failed (TPM)")
	}
	_, expectedExtraData, err := hashForCOSEAlgorithm(algorithm, concatenate(input.AuthData, input.ClientDataHash))
	if err != nil {
		return false, err
	}
	if !bytes.Equal(certInfo.ExtraData, expectedExtraData) {
		return false, errors.New("certInfo extra data did not equal hashed attestation (TPM)")
	}

	leaf, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return false, fmt.Errorf("parse leaf certificate (TPM): %w", err)
	}
	if leaf.IsCA {
		return false, errors.New("certificate basic constraints CA was not false (TPM)")
	}
	if leaf.Version != 3 {
		return false, errors.New("certificate version was not 3 (ASN.1 value of 2) (TPM)")
	}
	if leaf.Subject.String() != "" {
		return false, errors.New("certificate subject was not empty (TPM)")
	}
	if err := verifyCertificateTime(leaf, input.Now); err != nil {
		return false, fmt.Errorf("%w (TPM)", err)
	}
	attributes, sanPresent, err := tpmSubjectAlternativeNameAttributes(leaf)
	if err != nil {
		return false, err
	}
	if !sanPresent {
		return false, errors.New("certificate did not contain subjectAltName extension (TPM)")
	}
	manufacturer := attributes[oidTPMManufacturer.String()]
	model := attributes[oidTPMModel.String()]
	versionValue := attributes[oidTPMVersion.String()]
	if manufacturer == "" || model == "" || versionValue == "" {
		return false, errors.New("certificate contained incomplete subjectAltName data (TPM)")
	}
	if _, ok := knownTPMManufacturers[manufacturer]; !ok {
		return false, fmt.Errorf("could not match TPM manufacturer %q (TPM)", manufacturer)
	}
	if !certificateHasUnknownEKU(leaf, oidTCGKPAttest) {
		return false, errors.New("unexpected extKeyUsage, expected 2.23.133.8.3 (TPM)")
	}
	if err := validateFIDOAAGUIDExtension(leaf, input.ParsedAuthData.AAGUID); err != nil {
		return false, fmt.Errorf("%w (TPM)", err)
	}
	if err := validateCertificatePath(certificates, rootPool(input, "tpm"), input.Now); err != nil {
		return false, fmt.Errorf("%w (TPM)", err)
	}
	return verifyCertificateSignature(certificates[0], signature, certInfoBytes, &algorithm)
}

func parseTPMPublicArea(data []byte) (tpmPublicArea, error) {
	reader := tpmReader{data: data}
	typeValue, err := reader.uint16()
	if err != nil {
		return tpmPublicArea{}, fmt.Errorf("parse pubArea type: %w", err)
	}
	if _, err := reader.uint16(); err != nil { // nameAlg
		return tpmPublicArea{}, err
	}
	if _, err := reader.uint32(); err != nil { // objectAttributes
		return tpmPublicArea{}, err
	}
	if _, err := reader.sized(); err != nil { // authPolicy
		return tpmPublicArea{}, err
	}
	result := tpmPublicArea{Type: typeValue}
	switch typeValue {
	case tmpAlgRSA:
		if _, err := reader.uint16(); err != nil {
			return tpmPublicArea{}, err
		}
		if _, err := reader.uint16(); err != nil {
			return tpmPublicArea{}, err
		}
		if _, err := reader.uint16(); err != nil {
			return tpmPublicArea{}, err
		}
		result.Exponent, err = reader.uint32()
		if err != nil {
			return tpmPublicArea{}, err
		}
		result.Unique, err = reader.sized()
		if err != nil {
			return tpmPublicArea{}, err
		}
	case tmpAlgECC:
		if _, err := reader.uint16(); err != nil {
			return tpmPublicArea{}, err
		}
		if _, err := reader.uint16(); err != nil {
			return tpmPublicArea{}, err
		}
		result.CurveID, err = reader.uint16()
		if err != nil {
			return tpmPublicArea{}, err
		}
		if _, err := reader.uint16(); err != nil {
			return tpmPublicArea{}, err
		}
		x, err := reader.sized()
		if err != nil {
			return tpmPublicArea{}, err
		}
		y, err := reader.sized()
		if err != nil {
			return tpmPublicArea{}, err
		}
		result.Unique = concatenate(x, y)
	default:
		return tpmPublicArea{}, fmt.Errorf("unexpected type %x (TPM)", typeValue)
	}
	if reader.remaining() != 0 {
		return tpmPublicArea{}, errors.New("leftover bytes detected while parsing pubArea (TPM)")
	}
	return result, nil
}

func compareTPMPublicArea(area tpmPublicArea, key COSEPublicKey) error {
	switch area.Type {
	case tmpAlgRSA:
		if key.KTY != COSEKTYRSA {
			return fmt.Errorf("credential public key with kty %d did not match TPM_ALG_RSA", key.KTY)
		}
		if !bytes.Equal(area.Unique, key.N) {
			return errors.New("pubArea unique is not same as credentialPublicKey (TPM|RSA)")
		}
		exponent := new(big.Int).SetBytes(key.E)
		expected := uint64(area.Exponent)
		if expected == 0 {
			expected = 65537
		}
		if !exponent.IsUint64() || exponent.Uint64() != expected {
			return fmt.Errorf("unexpected public key exp %s, expected %d (TPM|RSA)", exponent.String(), expected)
		}
	case tmpAlgECC:
		if key.KTY != COSEKTYEC2 {
			return fmt.Errorf("credential public key with kty %d did not match TPM_ALG_ECC", key.KTY)
		}
		if !bytes.Equal(area.Unique, concatenate(key.X, key.Y)) {
			return errors.New("pubArea unique is not same as public key x and y (TPM|ECC)")
		}
		curveMap := map[uint16]int{0x0003: COSECurveP256, 0x0004: COSECurveP384, 0x0005: COSECurveP521, 0x0010: COSECurveP256, 0x0020: COSECurveP256}
		if curveMap[area.CurveID] != key.Curve {
			return fmt.Errorf("public area curve ID %x did not match public key crv %d (TPM|ECC)", area.CurveID, key.Curve)
		}
	}
	return nil
}

func parseTPMCertInfo(data []byte) (tpmCertInfo, error) {
	reader := tpmReader{data: data}
	magic, err := reader.uint32()
	if err != nil {
		return tpmCertInfo{}, err
	}
	typeValue, err := reader.uint16()
	if err != nil {
		return tpmCertInfo{}, err
	}
	if _, err := reader.sized(); err != nil {
		return tpmCertInfo{}, err
	}
	extraData, err := reader.sized()
	if err != nil {
		return tpmCertInfo{}, err
	}
	if _, err := reader.take(8); err != nil {
		return tpmCertInfo{}, err
	}
	if _, err := reader.uint32(); err != nil {
		return tpmCertInfo{}, err
	}
	if _, err := reader.uint32(); err != nil {
		return tpmCertInfo{}, err
	}
	if _, err := reader.take(1); err != nil {
		return tpmCertInfo{}, err
	}
	if _, err := reader.take(8); err != nil {
		return tpmCertInfo{}, err
	}
	attestedName, err := reader.sized()
	if err != nil {
		return tpmCertInfo{}, err
	}
	if len(attestedName) < 2 {
		return tpmCertInfo{}, errors.New("attested name was shorter than algorithm identifier (TPM)")
	}
	if _, err := reader.sized(); err != nil {
		return tpmCertInfo{}, err
	}
	if reader.remaining() != 0 {
		return tpmCertInfo{}, errors.New("leftover bytes detected while parsing certInfo (TPM)")
	}
	return tpmCertInfo{
		Magic:              magic,
		Type:               typeValue,
		ExtraData:          extraData,
		AttestedNameAlg:    binary.BigEndian.Uint16(attestedName[:2]),
		AttestedNameAlgRaw: append([]byte(nil), attestedName[:2]...),
		AttestedName:       attestedName,
	}, nil
}

func tpmHashAlgorithm(identifier uint16) (int, error) {
	switch identifier {
	case tmpAlgSHA256:
		return COSEAlgES256, nil
	case tmpAlgSHA384:
		return COSEAlgES384, nil
	case tmpAlgSHA512:
		return COSEAlgES512, nil
	default:
		return 0, fmt.Errorf("unexpected TPM attested name alg %x", identifier)
	}
}

type tpmReader struct {
	data     []byte
	position int
}

func (reader *tpmReader) remaining() int { return len(reader.data) - reader.position }

func (reader *tpmReader) take(length int) ([]byte, error) {
	if length < 0 || length > reader.remaining() {
		return nil, errors.New("truncated TPM structure")
	}
	result := append([]byte(nil), reader.data[reader.position:reader.position+length]...)
	reader.position += length
	return result, nil
}

func (reader *tpmReader) uint16() (uint16, error) {
	data, err := reader.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(data), nil
}

func (reader *tpmReader) uint32() (uint32, error) {
	data, err := reader.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data), nil
}

func (reader *tpmReader) sized() ([]byte, error) {
	length, err := reader.uint16()
	if err != nil {
		return nil, err
	}
	return reader.take(int(length))
}

func tpmSubjectAlternativeNameAttributes(certificate *x509.Certificate) (map[string]string, bool, error) {
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidSubjectAlternativeName) {
			continue
		}
		attributes := map[string]string{}
		if err := collectASN1Attributes(extension.Value, attributes, 0); err != nil {
			return nil, true, fmt.Errorf("parse subjectAltName extension (TPM): %w", err)
		}
		return attributes, true, nil
	}
	return nil, false, nil
}

func collectASN1Attributes(data []byte, attributes map[string]string, depth int) error {
	if depth > 16 {
		return errors.New("ASN.1 nesting exceeded limit")
	}
	for len(data) != 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil {
			return err
		}
		if value.Tag == asn1.TagSequence && value.IsCompound {
			var oid asn1.ObjectIdentifier
			nested, oidErr := asn1.Unmarshal(value.Bytes, &oid)
			if oidErr == nil && len(nested) != 0 {
				var attribute asn1.RawValue
				if trailing, attrErr := asn1.Unmarshal(nested, &attribute); attrErr == nil && len(trailing) == 0 {
					if text, ok := asn1String(attribute); ok {
						attributes[oid.String()] = text
					}
				}
			}
		}
		if value.IsCompound {
			if err := collectASN1Attributes(value.Bytes, attributes, depth+1); err != nil {
				return err
			}
		}
		data = rest
	}
	return nil
}

func asn1String(value asn1.RawValue) (string, bool) {
	switch value.Tag {
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String, asn1.TagT61String:
		return string(value.Bytes), true
	default:
		return "", false
	}
}

func certificateHasUnknownEKU(certificate *x509.Certificate, wanted asn1.ObjectIdentifier) bool {
	for _, usage := range certificate.UnknownExtKeyUsage {
		if usage.Equal(wanted) {
			return true
		}
	}
	return false
}
