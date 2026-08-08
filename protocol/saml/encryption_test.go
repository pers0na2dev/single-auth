package saml

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	pkcs8 "github.com/youmark/pkcs8"
)

func TestValidateEncryptedResponseSupportedAlgorithms(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	dataAlgorithms := []string{
		DataEncryptionAES128CBC,
		DataEncryptionAES256CBC,
		DataEncryptionAES128GCM,
		DataEncryptionAES256GCM,
		DataEncryptionTripleDESCBC,
	}
	keyAlgorithms := []string{KeyEncryptionRSAOAEP, KeyEncryptionRSA15}
	for _, keyAlgorithm := range keyAlgorithms {
		for _, dataAlgorithm := range dataAlgorithms {
			name := shortEncryptionName(keyAlgorithm) + "/" + shortEncryptionName(dataAlgorithm)
			t.Run(name, func(t *testing.T) {
				signedAssertion := signFixture(
					t,
					validResponseFixture(),
					privateKey,
					certificate,
					false,
					true,
				)
				encrypted := encryptAssertionTestFixture(
					t,
					signedAssertion,
					&privateKey.PublicKey,
					keyAlgorithm,
					dataAlgorithm,
					false,
				)
				options := encryptedValidationOptions(certificate, privateKey)
				options.Signatures.Requirement = SignatureAssertion
				options.Signatures.Algorithms.OnDeprecated = DeprecatedAllow
				validated, err := ValidateResponseXML(context.Background(), encrypted, options)
				if err != nil {
					t.Fatal(err)
				}
				if !validated.Signatures.AssertionSigned || validated.Signatures.ResponseSigned ||
					validated.Response.Assertion.NameID != "user@example.com" {
					t.Fatalf("validated response = %+v", validated)
				}
			})
		}
	}
}

func TestValidateEncryptedResponseSignaturePlacements(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	tests := []struct {
		name        string
		requirement SignatureRequirement
		assertion   bool
		response    bool
	}{
		{name: "assertion signed before encryption", requirement: SignatureAssertion, assertion: true},
		{name: "response signed after encryption", requirement: SignatureResponse, response: true},
		{name: "both signatures", requirement: SignatureBoth, assertion: true, response: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			xmlData := validResponseFixture()
			if test.assertion {
				xmlData = signFixture(t, xmlData, privateKey, certificate, false, true)
			}
			xmlData = encryptAssertionTestFixture(
				t,
				xmlData,
				&privateKey.PublicKey,
				KeyEncryptionRSAOAEP,
				DataEncryptionAES256GCM,
				false,
			)
			if test.response {
				xmlData = signFixture(t, xmlData, privateKey, certificate, true, false)
			}
			options := encryptedValidationOptions(certificate, privateKey)
			options.Signatures.Requirement = test.requirement
			validated, err := ValidateResponseXML(context.Background(), xmlData, options)
			if err != nil {
				t.Fatal(err)
			}
			if validated.Signatures.AssertionSigned != test.assertion ||
				validated.Signatures.ResponseSigned != test.response {
				t.Fatalf("signatures = %+v", validated.Signatures)
			}
		})
	}
}

func TestValidateEncryptedResponseDetachedKeyAndBinding(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	xmlData := signFixture(t, validResponseFixture(), privateKey, certificate, false, true)
	encrypted := encryptAssertionTestFixture(
		t,
		xmlData,
		&privateKey.PublicKey,
		KeyEncryptionRSAOAEP,
		DataEncryptionAES128CBC,
		true,
	)
	options := encryptedValidationOptions(certificate, privateKey)
	if _, err := ValidateResponseXML(context.Background(), encrypted, options); err != nil {
		t.Fatal(err)
	}

	wrongAudience := bytes.Replace(
		validResponseFixture(),
		[]byte(fixtureAudience),
		[]byte(otherAudience),
		1,
	)
	wrongAudience = signFixture(t, wrongAudience, privateKey, certificate, false, true)
	wrongAudience = encryptAssertionTestFixture(
		t,
		wrongAudience,
		&privateKey.PublicKey,
		KeyEncryptionRSAOAEP,
		DataEncryptionAES128GCM,
		false,
	)
	if _, err := ValidateResponseXML(context.Background(), wrongAudience, options); !IsErrorCode(err, "SAML_AUDIENCE_MISMATCH") {
		t.Fatalf("wrong-audience error = %v", err)
	}
}

func TestValidateEncryptedResponseRejectsInvalidCryptographicInputs(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	signed := signFixture(t, validResponseFixture(), privateKey, certificate, false, true)
	encrypted := encryptAssertionTestFixture(
		t,
		signed,
		&privateKey.PublicKey,
		KeyEncryptionRSAOAEP,
		DataEncryptionAES256GCM,
		false,
	)
	options := encryptedValidationOptions(certificate, privateKey)

	t.Run("wrong private key", func(t *testing.T) {
		wrongKey, _ := testKeyPair(t)
		wrongOptions := options
		wrongOptions.Decryption = &AssertionDecryptionOptions{PrivateKey: wrongKey}
		if _, err := ValidateResponseXML(context.Background(), encrypted, wrongOptions); !IsErrorCode(err, "SAML_ASSERTION_DECRYPTION_FAILED") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("tampered authenticated ciphertext", func(t *testing.T) {
		tampered := mutateEncryptedCipherValue(t, encrypted)
		if _, err := ValidateResponseXML(context.Background(), tampered, options); !IsErrorCode(err, "SAML_ASSERTION_DECRYPTION_FAILED") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("unsupported Samlify algorithm", func(t *testing.T) {
		unsupported := bytes.Replace(
			encrypted,
			[]byte(DataEncryptionAES256GCM),
			[]byte(DataEncryptionAES192GCM),
			1,
		)
		if _, err := ValidateResponseXML(context.Background(), unsupported, options); !IsErrorCode(err, "SAML_ASSERTION_DECRYPTION_FAILED") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("data algorithm allow-list", func(t *testing.T) {
		restricted := options
		restricted.Signatures.Algorithms.AllowedDataEncryptionAlgorithms = []string{DataEncryptionAES128GCM}
		if _, err := ValidateResponseXML(context.Background(), encrypted, restricted); !IsErrorCode(err, "SAML_ALGORITHM_NOT_ALLOWED") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("deprecated key algorithm rejected", func(t *testing.T) {
		legacy := encryptAssertionTestFixture(
			t,
			signed,
			&privateKey.PublicKey,
			KeyEncryptionRSA15,
			DataEncryptionAES128GCM,
			false,
		)
		restricted := options
		restricted.Signatures.Algorithms.OnDeprecated = DeprecatedReject
		if _, err := ValidateResponseXML(context.Background(), legacy, restricted); !IsErrorCode(err, "SAML_DEPRECATED_ALGORITHM") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("deprecated data algorithm rejected", func(t *testing.T) {
		legacy := encryptAssertionTestFixture(
			t,
			signed,
			&privateKey.PublicKey,
			KeyEncryptionRSAOAEP,
			DataEncryptionTripleDESCBC,
			false,
		)
		restricted := options
		restricted.Signatures.Algorithms.OnDeprecated = DeprecatedReject
		if _, err := ValidateResponseXML(context.Background(), legacy, restricted); !IsErrorCode(err, "SAML_DEPRECATED_ALGORITHM") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestValidateEncryptedResponseRequiresConfiguredShape(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	signed := signFixture(t, validResponseFixture(), privateKey, certificate, false, true)
	encrypted := encryptAssertionTestFixture(
		t,
		signed,
		&privateKey.PublicKey,
		KeyEncryptionRSAOAEP,
		DataEncryptionAES128GCM,
		false,
	)

	t.Run("encrypted response without decryption config", func(t *testing.T) {
		options := encryptedValidationOptions(certificate, privateKey)
		options.Decryption = nil
		if _, err := ValidateResponseXML(context.Background(), encrypted, options); !IsErrorCode(err, "SAML_ENCRYPTED_ASSERTION_UNSUPPORTED") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("configured IdP requires encrypted assertion", func(t *testing.T) {
		options := encryptedValidationOptions(certificate, privateKey)
		if _, err := ValidateResponseXML(context.Background(), signed, options); !IsErrorCode(err, "SAML_ENCRYPTED_ASSERTION_MISSING") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrapping layout is rejected before decryption", func(t *testing.T) {
		document := parseEncryptionFixture(t, encrypted)
		root := document.Root()
		encryptedAssertion := descendantsByTag(root, "EncryptedAssertion")[0]
		root.RemoveChild(encryptedAssertion)
		extensions := etree.NewElement("samlp:Extensions")
		extensions.Space = "samlp"
		extensions.AddChild(encryptedAssertion)
		root.AddChild(extensions)
		wrapped, err := document.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		options := encryptedValidationOptions(certificate, privateKey)
		if _, err := ValidateResponseXML(context.Background(), wrapped, options); !IsErrorCode(err, "SAML_ENCRYPTED_ASSERTION_INVALID") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestValidateEncryptedResponseReplayUsesPlaintextAssertionID(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	plain := bytes.ReplaceAll(validResponseFixture(), []byte(` InResponseTo="_request"`), nil)
	plain = signFixture(t, plain, privateKey, certificate, false, true)
	encrypted := encryptAssertionTestFixture(
		t,
		plain,
		&privateKey.PublicKey,
		KeyEncryptionRSAOAEP,
		DataEncryptionAES256GCM,
		false,
	)
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	options := encryptedValidationOptions(certificate, privateKey)
	options.InResponseTo = InResponseToValidationOptions{ProviderID: "provider", Store: store}
	options.Replay = AssertionReplayOptions{ProviderID: "provider", Store: store}
	options.EnableReplayProtection = nil
	if _, err := ValidateResponseXML(context.Background(), encrypted, options); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateResponseXML(context.Background(), encrypted, options); !IsErrorCode(err, "SAML_ASSERTION_REPLAYED") {
		t.Fatalf("second response error = %v", err)
	}
}

func TestParseDecryptionPrivateKeyPEM(t *testing.T) {
	privateKey, _ := testKeyPair(t)
	password := []byte("correct horse battery staple")
	der, err := pkcs8.MarshalPrivateKey(privateKey, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	indented := "  " + strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{
		Type: "ENCRYPTED PRIVATE KEY", Bytes: der,
	})), "\n", "\n  ")
	parsed, err := ParseDecryptionPrivateKeyPEM([]byte(indented), string(password))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PublicKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Fatal("parsed a different RSA key")
	}
	if _, err := ParseDecryptionPrivateKeyPEM([]byte(indented), "wrong password"); !IsErrorCode(err, "SAML_DECRYPTION_KEY_INVALID") {
		t.Fatalf("wrong-password error = %v", err)
	}
	ecdsaKey, _ := testECDSAKeyPair(t)
	ecdsaDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDecryptionPrivateKeyPEM(pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: ecdsaDER,
	}), ""); !IsErrorCode(err, "SAML_DECRYPTION_KEY_INVALID") {
		t.Fatalf("ECDSA error = %v", err)
	}
}

func encryptedValidationOptions(
	certificate *x509.Certificate,
	privateKey *rsa.PrivateKey,
) ResponseValidationOptions {
	return ResponseValidationOptions{
		ExpectedIssuer: fixtureIssuer,
		Signatures: SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
		},
		Timestamp: TimestampValidationOptions{Now: func() time.Time { return fixtureNow }},
		Binding: ResponseBindingValidationOptions{
			ExpectedAudiences:  []string{fixtureAudience},
			ExpectedRecipients: []string{fixtureRecipient},
		},
		InResponseTo:           InResponseToValidationOptions{EnableValidation: boolPointer(false)},
		EnableReplayProtection: boolPointer(false),
		Decryption:             &AssertionDecryptionOptions{PrivateKey: privateKey},
	}
}

func encryptAssertionTestFixture(
	t *testing.T,
	xmlData []byte,
	publicKey *rsa.PublicKey,
	keyAlgorithm string,
	dataAlgorithm string,
	detachedKey bool,
) []byte {
	t.Helper()
	document := parseEncryptionFixture(t, xmlData)
	assertions := descendantsByTag(document.Root(), "Assertion")
	if len(assertions) != 1 {
		t.Fatalf("assertions = %d", len(assertions))
	}
	assertionDocument := etree.NewDocument()
	assertionDocument.SetRoot(assertions[0].Copy())
	plaintext, err := assertionDocument.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	keyLength, err := dataEncryptionKeyLength(dataAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	symmetricKey := make([]byte, keyLength)
	if _, err := rand.Read(symmetricKey); err != nil {
		t.Fatal(err)
	}
	block, err := dataEncryptionBlock(dataAlgorithm, symmetricKey)
	if err != nil {
		t.Fatal(err)
	}
	var encryptedContent []byte
	switch dataAlgorithm {
	case DataEncryptionAES128GCM, DataEncryptionAES256GCM:
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		encryptedContent = append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...)
	case DataEncryptionAES128CBC, DataEncryptionAES256CBC, DataEncryptionTripleDESCBC:
		padding := block.BlockSize() - len(plaintext)%block.BlockSize()
		padded := append(append([]byte(nil), plaintext...), bytes.Repeat([]byte{byte(padding)}, padding)...)
		iv := make([]byte, block.BlockSize())
		if _, err := rand.Read(iv); err != nil {
			t.Fatal(err)
		}
		encryptedContent = append([]byte(nil), iv...)
		ciphertext := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
		encryptedContent = append(encryptedContent, ciphertext...)
	default:
		t.Fatalf("unsupported test data algorithm %q", dataAlgorithm)
	}
	var encryptedKey []byte
	switch keyAlgorithm {
	case KeyEncryptionRSAOAEP:
		encryptedKey, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, symmetricKey, nil)
	case KeyEncryptionRSA15:
		encryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, publicKey, symmetricKey)
	default:
		t.Fatalf("unsupported test key algorithm %q", keyAlgorithm)
	}
	if err != nil {
		t.Fatal(err)
	}

	keyXML := fmt.Sprintf(`<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`,
		keyAlgorithm,
		DigestSHA1,
		base64.StdEncoding.EncodeToString(encryptedKey),
	)
	keyInfo := `<ds:KeyInfo>` + keyXML + `</ds:KeyInfo>`
	detached := ""
	if detachedKey {
		keyInfo = `<ds:KeyInfo><ds:RetrievalMethod URI="#_encrypted-key"/></ds:KeyInfo>`
		detached = strings.Replace(keyXML, `<xenc:EncryptedKey>`, `<xenc:EncryptedKey ID="_encrypted-key">`, 1)
	}
	fragment := fmt.Sprintf(`<saml:EncryptedAssertion xmlns:saml="%s" xmlns:xenc="%s" xmlns:ds="%s"><xenc:EncryptedData Type="%s"><xenc:EncryptionMethod Algorithm="%s"/>%s<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>%s</saml:EncryptedAssertion>`,
		AssertionNamespace,
		XMLEncNamespace,
		XMLDSigNamespace,
		encryptedElementType,
		dataAlgorithm,
		keyInfo,
		base64.StdEncoding.EncodeToString(encryptedContent),
		detached,
	)
	fragmentDocument := parseEncryptionFixture(t, []byte(fragment))
	parent := assertions[0].Parent()
	index := assertions[0].Index()
	parent.RemoveChild(assertions[0])
	parent.InsertChildAt(index, fragmentDocument.Root().Copy())
	result, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mutateEncryptedCipherValue(t *testing.T, xmlData []byte) []byte {
	t.Helper()
	document := parseEncryptionFixture(t, xmlData)
	encryptedData := descendantsByTag(document.Root(), "EncryptedData")[0]
	cipherValue := descendantsByTag(encryptedData, "CipherValue")
	if len(cipherValue) < 2 {
		t.Fatalf("cipher values = %d", len(cipherValue))
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cipherValue[len(cipherValue)-1].Text()))
	if err != nil || len(decoded) == 0 {
		t.Fatal("invalid test cipher value")
	}
	decoded[len(decoded)/2] ^= 0x80
	cipherValue[len(cipherValue)-1].SetText(base64.StdEncoding.EncodeToString(decoded))
	result, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func parseEncryptionFixture(t *testing.T, xmlData []byte) *etree.Document {
	t.Helper()
	document := etree.NewDocument()
	document.ReadSettings.Permissive = false
	if err := document.ReadFromBytes(xmlData); err != nil {
		t.Fatal(err)
	}
	return document
}

func shortEncryptionName(value string) string {
	if index := strings.LastIndexByte(value, '#'); index >= 0 {
		return value[index+1:]
	}
	return value
}
