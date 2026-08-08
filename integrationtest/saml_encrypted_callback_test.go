package singleauth_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	pkcs8 "github.com/youmark/pkcs8"

	samlplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
)

func TestSAMLEncryptedCallbackAcrossTransports(t *testing.T) {
	for _, transport := range samlTestTransports() {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			decryptionKey, encryptedKeyPEM := encryptedCallbackPrivateKey(t, "sp-encryption-password")
			harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
				config.IDPMetadata.IsAssertionEncrypted = true
				config.SPMetadata.IsAssertionEncrypted = true
				config.SPMetadata.EncPrivateKey = encryptedKeyPEM
				config.SPMetadata.EncPrivateKeyPass = "sp-encryption-password"
			})
			relayState, requestID := startSAMLCallbackFlow(t, harness.auth, transport)
			plain := harness.assertionSignedResponse(t, samlResponseFixture{
				AssertionID: "_encrypted-" + strings.ReplaceAll(transport, "/", "-"),
				RequestID:   requestID,
				Recipient:   harness.config.CallbackURL,
				Audience:    samlCallbackSP,
				Issuer:      samlCallbackIDP,
				Email:       "encrypted@corp.example.com",
			})
			encrypted := encryptSAMLCallbackAssertion(t, plain, &decryptionKey.PublicKey)

			result := invokeSAMLCallback(t, harness.auth, transport, false, encrypted, relayState)
			if result.status != http.StatusFound || headerValue(result.headers, "Location") != "/dashboard" {
				t.Fatalf("encrypted callback status=%d location=%q body=%s", result.status, headerValue(result.headers, "Location"), result.body)
			}
			if len(result.headers.Values("Set-Cookie")) == 0 {
				t.Fatal("encrypted callback did not issue a session cookie")
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)

			replay := invokeSAMLCallback(t, harness.auth, transport, false, encrypted, relayState)
			replayURL, err := url.Parse(headerValue(replay.headers, "Location"))
			if replay.status != http.StatusFound || err != nil || replayURL.Query().Get("error") != "invalid_saml_response" {
				t.Fatalf("encrypted replay status=%d location=%q error=%v", replay.status, headerValue(replay.headers, "Location"), err)
			}
			if len(replay.headers.Values("Set-Cookie")) != 0 {
				t.Fatal("encrypted replay issued cookies")
			}
			assertSAMLCallbackRows(t, harness.adapter, 1, 1, 1)
		})
	}
}

func TestSAMLEncryptedCallbackRejectsMissingAndWrongKeys(t *testing.T) {
	t.Run("missing SP decryption key", func(t *testing.T) {
		harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
			config.IDPMetadata.IsAssertionEncrypted = true
		})
		relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
		response := harness.signedResponse(t, samlResponseFixture{
			AssertionID: "_missing-key", RequestID: requestID,
			Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
			Issuer: samlCallbackIDP, Email: "missing-key@corp.example.com",
		})
		result := invokeSAMLCallback(t, harness.auth, "direct", false, response, relayState)
		if result.status != http.StatusBadRequest || len(result.headers.Values("Set-Cookie")) != 0 {
			t.Fatalf("missing-key status=%d cookies=%v body=%s", result.status, result.headers.Values("Set-Cookie"), result.body)
		}
		assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
	})

	t.Run("wrong SP decryption key", func(t *testing.T) {
		actualKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, wrongKeyPEM := encryptedCallbackPrivateKey(t, "wrong-key-password")
		harness := newSAMLCallbackHarness(t, func(config *samlplugin.SAMLConfig) {
			config.IDPMetadata.IsAssertionEncrypted = true
			config.SPMetadata.IsAssertionEncrypted = true
			config.SPMetadata.EncPrivateKey = wrongKeyPEM
			config.SPMetadata.EncPrivateKeyPass = "wrong-key-password"
		})
		relayState, requestID := startSAMLCallbackFlow(t, harness.auth, "direct")
		plain := harness.assertionSignedResponse(t, samlResponseFixture{
			AssertionID: "_wrong-key", RequestID: requestID,
			Recipient: harness.config.CallbackURL, Audience: samlCallbackSP,
			Issuer: samlCallbackIDP, Email: "wrong-key@corp.example.com",
		})
		encrypted := encryptSAMLCallbackAssertion(t, plain, &actualKey.PublicKey)
		result := invokeSAMLCallback(t, harness.auth, "direct", false, encrypted, relayState)
		if result.status != http.StatusBadRequest || len(result.headers.Values("Set-Cookie")) != 0 {
			t.Fatalf("wrong-key status=%d cookies=%v body=%s", result.status, result.headers.Values("Set-Cookie"), result.body)
		}
		assertSAMLCallbackRows(t, harness.adapter, 0, 0, 0)
	})
}

func (h samlCallbackHarness) assertionSignedResponse(
	t *testing.T,
	fixture samlResponseFixture,
) []byte {
	t.Helper()
	outerSigned, err := base64.StdEncoding.DecodeString(h.signedResponse(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	document.ReadSettings.Permissive = false
	if err := document.ReadFromBytes(outerSigned); err != nil {
		t.Fatal(err)
	}
	root := document.Root()
	for _, child := range root.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == samlprotocol.XMLDSigNamespace {
			root.RemoveChild(child)
		}
	}
	assertions := encryptedCallbackDescendants(root, "Assertion")
	if len(assertions) != 1 {
		t.Fatalf("assertions=%d", len(assertions))
	}
	signingContext, err := dsig.NewSigningContext(h.privateKey, [][]byte{h.cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signingContext.SetSignatureMethod(samlprotocol.SignatureRSASHA256); err != nil {
		t.Fatal(err)
	}
	signedAssertion, err := signingContext.SignEnveloped(assertions[0])
	if err != nil {
		t.Fatal(err)
	}
	parent := assertions[0].Parent()
	index := assertions[0].Index()
	parent.RemoveChild(assertions[0])
	parent.InsertChildAt(index, signedAssertion)
	result, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func encryptSAMLCallbackAssertion(
	t *testing.T,
	xmlData []byte,
	publicKey *rsa.PublicKey,
) string {
	t.Helper()
	document := etree.NewDocument()
	document.ReadSettings.Permissive = false
	if err := document.ReadFromBytes(xmlData); err != nil {
		t.Fatal(err)
	}
	assertions := encryptedCallbackDescendants(document.Root(), "Assertion")
	if len(assertions) != 1 {
		t.Fatalf("assertions=%d", len(assertions))
	}
	assertionDocument := etree.NewDocument()
	assertionDocument.SetRoot(assertions[0].Copy())
	plaintext, err := assertionDocument.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	symmetricKey := make([]byte, 32)
	if _, err := rand.Read(symmetricKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...)
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, symmetricKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	fragment := fmt.Sprintf(`<saml:EncryptedAssertion xmlns:saml="%s" xmlns:xenc="%s" xmlns:ds="%s"><xenc:EncryptedData Type="%sElement"><xenc:EncryptionMethod Algorithm="%s"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>`,
		samlprotocol.AssertionNamespace,
		samlprotocol.XMLEncNamespace,
		samlprotocol.XMLDSigNamespace,
		samlprotocol.XMLEncNamespace,
		samlprotocol.DataEncryptionAES256GCM,
		samlprotocol.KeyEncryptionRSAOAEP,
		samlprotocol.DigestSHA1,
		base64.StdEncoding.EncodeToString(encryptedKey),
		base64.StdEncoding.EncodeToString(ciphertext),
	)
	fragmentDocument := etree.NewDocument()
	fragmentDocument.ReadSettings.Permissive = false
	if err := fragmentDocument.ReadFromString(fragment); err != nil {
		t.Fatal(err)
	}
	parent := assertions[0].Parent()
	index := assertions[0].Index()
	parent.RemoveChild(assertions[0])
	parent.InsertChildAt(index, fragmentDocument.Root().Copy())
	result, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(result)
}

func encryptedCallbackPrivateKey(t *testing.T, password string) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pkcs8.MarshalPrivateKey(privateKey, []byte(password), nil)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, string(pem.EncodeToMemory(&pem.Block{
		Type: "ENCRYPTED PRIVATE KEY", Bytes: der,
	}))
}

func encryptedCallbackDescendants(root *etree.Element, tag string) []*etree.Element {
	var result []*etree.Element
	var visit func(*etree.Element)
	visit = func(element *etree.Element) {
		if element.Tag == tag {
			result = append(result, element)
		}
		for _, child := range element.ChildElements() {
			visit(child)
		}
	}
	visit(root)
	return result
}
