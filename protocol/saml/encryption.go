package saml

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/beevik/etree"
)

const encryptedElementType = XMLEncNamespace + "Element"

// DecryptResponseAssertion replaces the single direct EncryptedAssertion in a
// SAML Response with its plaintext Assertion. It implements the algorithms
// accepted by Samlify 2.13.1 / @authenio/xml-encryption 2.0.2, the runtime used
// by the reference implementation 1.6.26.
func DecryptResponseAssertion(
	xmlData []byte,
	privateKey *rsa.PrivateKey,
	algorithms AlgorithmValidationOptions,
	maxBytes int,
) ([]byte, error) {
	decrypted, _, err := decryptResponseAssertion(
		xmlData,
		privateKey,
		algorithms,
		responseSizeLimit(maxBytes),
	)
	return decrypted, err
}

func decryptResponseAssertion(
	xmlData []byte,
	privateKey *rsa.PrivateKey,
	algorithms AlgorithmValidationOptions,
	maxBytes int,
) ([]byte, *etree.Element, error) {
	if privateKey == nil {
		return nil, nil, newError(
			"SAML_DECRYPTION_KEY_MISSING",
			"No SAML assertion decryption private key is configured",
		)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseSize
	}
	if err := validateSingleAssertionXMLWithLimit(xmlData, maxBytes); err != nil {
		return nil, nil, err
	}
	document, err := parseXML(xmlData, maxBytes)
	if err != nil {
		return nil, nil, err
	}
	root := document.Root()
	if root.Tag != "Response" || !namespaceMatches(root, ProtocolNamespace) {
		return nil, nil, newError(
			"SAML_RESPONSE_ROOT_INVALID",
			"Encrypted SAML assertion must be a direct child of a Response",
		)
	}
	if err := validateUniqueIDs(root); err != nil {
		return nil, nil, err
	}
	if len(directChildren(root, "Assertion", AssertionNamespace)) != 0 {
		return nil, nil, newError(
			"SAML_MULTIPLE_ASSERTIONS",
			"SAML response must not mix plain and encrypted assertions",
		)
	}
	encryptedAssertions := directChildren(root, "EncryptedAssertion", AssertionNamespace)
	if len(encryptedAssertions) != 1 {
		return nil, nil, newError(
			"SAML_ENCRYPTED_ASSERTION_INVALID",
			"SAML response must contain exactly one direct encrypted assertion",
		)
	}

	material, err := inspectEncryptedAssertion(encryptedAssertions[0], maxBytes)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateEncryptionAlgorithms(
		material.keyAlgorithm,
		material.dataAlgorithm,
		algorithms,
	); err != nil {
		return nil, nil, err
	}
	plaintext, err := decryptAssertionMaterial(material, privateKey, maxBytes)
	if err != nil {
		return nil, nil, assertionDecryptionError(err)
	}
	assertionDocument, err := parseXML(plaintext, maxBytes)
	if err != nil {
		return nil, nil, assertionDecryptionError(err)
	}
	assertion := assertionDocument.Root()
	if assertion.Tag != "Assertion" || !namespaceMatches(assertion, AssertionNamespace) {
		return nil, nil, assertionDecryptionError(errors.New("plaintext root is not a SAML Assertion"))
	}
	if len(descendantsByTag(assertion, "Assertion")) != 1 ||
		len(descendantsByTag(assertion, "EncryptedAssertion")) != 0 {
		return nil, nil, assertionDecryptionError(errors.New("plaintext contains nested assertions"))
	}

	// Preserve this untouched tree for outer Response signature verification.
	originalResponse := root.Copy()
	parent := encryptedAssertions[0].Parent()
	index := encryptedAssertions[0].Index()
	parent.RemoveChild(encryptedAssertions[0])
	parent.InsertChildAt(index, assertion.Copy())
	decryptedXML, err := document.WriteToBytes()
	if err != nil {
		return nil, nil, assertionDecryptionError(err)
	}
	if len(decryptedXML) > maxBytes {
		return nil, nil, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", maxBytes),
		)
	}
	return decryptedXML, originalResponse, nil
}

type encryptedAssertionMaterial struct {
	keyAlgorithm  string
	dataAlgorithm string
	encryptedKey  []byte
	ciphertext    []byte
}

func inspectEncryptedAssertion(
	encryptedAssertion *etree.Element,
	maxBytes int,
) (encryptedAssertionMaterial, error) {
	var result encryptedAssertionMaterial
	encryptedData, err := exactlyOneEncryptionChild(
		encryptedAssertion,
		"EncryptedData",
		"encrypted assertion data",
	)
	if err != nil {
		return result, err
	}
	dataType := encryptedData.SelectAttrValue("Type", "")
	if dataType != "" && dataType != encryptedElementType {
		return result, newError(
			"SAML_ENCRYPTED_ASSERTION_INVALID",
			"Encrypted SAML assertion has an invalid EncryptedData type",
		)
	}
	dataMethod, err := exactlyOneEncryptionChild(
		encryptedData,
		"EncryptionMethod",
		"data encryption method",
	)
	if err != nil {
		return result, err
	}
	result.dataAlgorithm = strings.TrimSpace(dataMethod.SelectAttrValue("Algorithm", ""))
	if result.dataAlgorithm == "" {
		return result, newError(
			"SAML_ENCRYPTION_ALGORITHM_MISSING",
			"Encrypted SAML assertion is missing its data encryption algorithm",
		)
	}
	cipherData, err := exactlyOneEncryptionChild(encryptedData, "CipherData", "encrypted assertion cipher data")
	if err != nil {
		return result, err
	}
	cipherValue, err := exactlyOneEncryptionChild(cipherData, "CipherValue", "encrypted assertion cipher value")
	if err != nil {
		return result, err
	}
	result.ciphertext, err = decodeEncryptionValue(cipherValue.Text(), maxBytes)
	if err != nil {
		return result, assertionDecryptionError(err)
	}

	keyInfo := directChildren(encryptedData, "KeyInfo", XMLDSigNamespace)
	if len(keyInfo) != 1 {
		return result, newError(
			"SAML_ENCRYPTED_ASSERTION_INVALID",
			"Encrypted SAML assertion must contain exactly one KeyInfo",
		)
	}
	encryptedKey, err := resolveEncryptedKey(encryptedAssertion, keyInfo[0])
	if err != nil {
		return result, err
	}
	keyMethod, err := exactlyOneEncryptionChild(encryptedKey, "EncryptionMethod", "key encryption method")
	if err != nil {
		return result, err
	}
	result.keyAlgorithm = strings.TrimSpace(keyMethod.SelectAttrValue("Algorithm", ""))
	if result.keyAlgorithm == "" {
		return result, newError(
			"SAML_ENCRYPTION_ALGORITHM_MISSING",
			"Encrypted SAML assertion is missing its key encryption algorithm",
		)
	}
	keyCipherData, err := exactlyOneEncryptionChild(encryptedKey, "CipherData", "encrypted key cipher data")
	if err != nil {
		return result, err
	}
	keyCipherValue, err := exactlyOneEncryptionChild(keyCipherData, "CipherValue", "encrypted key cipher value")
	if err != nil {
		return result, err
	}
	result.encryptedKey, err = decodeEncryptionValue(keyCipherValue.Text(), maxBytes)
	if err != nil {
		return result, assertionDecryptionError(err)
	}
	return result, nil
}

func resolveEncryptedKey(
	encryptedAssertion *etree.Element,
	keyInfo *etree.Element,
) (*etree.Element, error) {
	embedded := directChildren(keyInfo, "EncryptedKey", XMLEncNamespace)
	retrievalMethods := directChildren(keyInfo, "RetrievalMethod", XMLDSigNamespace)
	if len(embedded) == 1 && len(retrievalMethods) == 0 {
		return embedded[0], nil
	}
	if len(embedded) != 0 || len(retrievalMethods) != 1 {
		return nil, newError(
			"SAML_ENCRYPTED_ASSERTION_INVALID",
			"Encrypted SAML assertion has an ambiguous encrypted key",
		)
	}
	uri := strings.TrimSpace(retrievalMethods[0].SelectAttrValue("URI", ""))
	if len(uri) < 2 || uri[0] != '#' {
		return nil, newError(
			"SAML_ENCRYPTED_ASSERTION_INVALID",
			"Encrypted SAML assertion RetrievalMethod must reference a local key",
		)
	}
	identifier := uri[1:]
	var matches []*etree.Element
	for _, candidate := range descendantsByTag(encryptedAssertion, "EncryptedKey") {
		if !namespaceMatches(candidate, XMLEncNamespace) {
			continue
		}
		if candidate.SelectAttrValue("ID", candidate.SelectAttrValue("Id", "")) == identifier {
			matches = append(matches, candidate)
		}
	}
	if len(matches) != 1 {
		return nil, newError(
			"SAML_ENCRYPTED_ASSERTION_INVALID",
			"Encrypted SAML assertion RetrievalMethod did not resolve one key",
		)
	}
	return matches[0], nil
}

func exactlyOneEncryptionChild(
	parent *etree.Element,
	tag string,
	description string,
) (*etree.Element, error) {
	children := directChildren(parent, tag, XMLEncNamespace)
	if len(children) != 1 {
		return nil, newError(
			"SAML_ENCRYPTED_ASSERTION_INVALID",
			fmt.Sprintf("Encrypted SAML assertion must contain exactly one %s", description),
		)
	}
	return children[0], nil
}

func decodeEncryptionValue(value string, maxBytes int) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	if compact == "" || len(compact) > base64.StdEncoding.EncodedLen(maxBytes)+4 {
		return nil, errors.New("invalid encrypted value")
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil || len(decoded) == 0 || len(decoded) > maxBytes {
		return nil, errors.New("invalid encrypted value")
	}
	return decoded, nil
}

func decryptAssertionMaterial(
	material encryptedAssertionMaterial,
	privateKey *rsa.PrivateKey,
	maxBytes int,
) ([]byte, error) {
	keyLength, err := dataEncryptionKeyLength(material.dataAlgorithm)
	if err != nil {
		return nil, err
	}
	var symmetricKey []byte
	switch material.keyAlgorithm {
	case KeyEncryptionRSAOAEP:
		symmetricKey, err = rsa.DecryptOAEP(
			sha1.New(),
			rand.Reader,
			privateKey,
			material.encryptedKey,
			nil,
		)
	case KeyEncryptionRSA15:
		// SessionKey avoids a PKCS#1 v1.5 padding oracle by substituting random
		// key bytes when padding is invalid. Every downstream failure is exposed
		// through the same generic assertion-decryption error.
		symmetricKey = make([]byte, keyLength)
		if _, err = rand.Read(symmetricKey); err == nil {
			err = rsa.DecryptPKCS1v15SessionKey(
				rand.Reader,
				privateKey,
				material.encryptedKey,
				symmetricKey,
			)
		}
	default:
		return nil, fmt.Errorf("unsupported key encryption algorithm %q", material.keyAlgorithm)
	}
	if err != nil || len(symmetricKey) != keyLength {
		return nil, errors.New("unable to unwrap assertion content key")
	}

	block, err := dataEncryptionBlock(material.dataAlgorithm, symmetricKey)
	if err != nil {
		return nil, err
	}
	var plaintext []byte
	switch material.dataAlgorithm {
	case DataEncryptionAES128GCM, DataEncryptionAES256GCM:
		plaintext, err = decryptGCM(block, material.ciphertext)
	case DataEncryptionAES128CBC, DataEncryptionAES256CBC, DataEncryptionTripleDESCBC:
		plaintext, err = decryptCBC(block, material.ciphertext)
	default:
		return nil, fmt.Errorf("unsupported data encryption algorithm %q", material.dataAlgorithm)
	}
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxBytes {
		return nil, errors.New("unable to decrypt assertion content")
	}
	return plaintext, nil
}

func dataEncryptionKeyLength(algorithm string) (int, error) {
	switch algorithm {
	case DataEncryptionAES128CBC, DataEncryptionAES128GCM:
		return 16, nil
	case DataEncryptionAES256CBC, DataEncryptionAES256GCM:
		return 32, nil
	case DataEncryptionTripleDESCBC:
		return 24, nil
	default:
		return 0, fmt.Errorf("unsupported data encryption algorithm %q", algorithm)
	}
}

func dataEncryptionBlock(algorithm string, key []byte) (cipher.Block, error) {
	switch algorithm {
	case DataEncryptionAES128CBC, DataEncryptionAES256CBC,
		DataEncryptionAES128GCM, DataEncryptionAES256GCM:
		return aes.NewCipher(key)
	case DataEncryptionTripleDESCBC:
		return des.NewTripleDESCipher(key)
	default:
		return nil, fmt.Errorf("unsupported data encryption algorithm %q", algorithm)
	}
}

func decryptGCM(block cipher.Block, encrypted []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("encrypted GCM assertion is too short")
	}
	nonce := encrypted[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, encrypted[gcm.NonceSize():], nil)
}

func decryptCBC(block cipher.Block, encrypted []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(encrypted) < blockSize*2 || len(encrypted)%blockSize != 0 {
		return nil, errors.New("encrypted CBC assertion has an invalid length")
	}
	iv := encrypted[:blockSize]
	plaintext := append([]byte(nil), encrypted[blockSize:]...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, plaintext)
	padding := int(plaintext[len(plaintext)-1])
	// XML Encryption only defines the final padding-length octet; preceding
	// padding octets are deliberately unspecified.
	if padding < 1 || padding > blockSize || padding > len(plaintext) {
		return nil, errors.New("encrypted CBC assertion has invalid padding")
	}
	return plaintext[:len(plaintext)-padding], nil
}

func assertionDecryptionError(cause error) *Error {
	return newError(
		"SAML_ASSERTION_DECRYPTION_FAILED",
		"Encrypted SAML assertion could not be decrypted",
		cause,
	)
}
