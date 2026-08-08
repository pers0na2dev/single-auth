package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

var fixtureNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

const (
	fixtureIssuer    = "https://idp.example.com/metadata"
	fixtureAudience  = "https://sp.example.com/metadata"
	fixtureRecipient = "https://sp.example.com/saml/acs"
	fixtureRequestID = "_request"
)

func validResponseFixture() []byte {
	return []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2026-08-08T11:59:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_request">
  <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="2026-08-08T11:59:00Z">
    <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://sp.example.com/saml/acs" InResponseTo="_request" NotOnOrAfter="2026-08-08T12:05:00Z"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-08-08T11:55:00Z" NotOnOrAfter="2026-08-08T12:05:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com/metadata</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement SessionIndex="_session"/>
    <saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`)
}

func testKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SAML test IdP"},
		NotBefore:    fixtureNow.Add(-24 * time.Hour),
		NotAfter:     fixtureNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return privateKey, certificate
}

func testECDSAKeyPair(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "SAML ECDSA test IdP"},
		NotBefore:    fixtureNow.Add(-24 * time.Hour),
		NotAfter:     fixtureNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("create ECDSA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ECDSA certificate: %v", err)
	}
	return privateKey, certificate
}

func signFixture(
	t *testing.T,
	xmlData []byte,
	privateKey *rsa.PrivateKey,
	certificate *x509.Certificate,
	signResponse bool,
	signAssertion bool,
) []byte {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromBytes(xmlData); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	context, err := dsig.NewSigningContext(privateKey, [][]byte{certificate.Raw})
	if err != nil {
		t.Fatalf("create signing context: %v", err)
	}
	context.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := context.SetSignatureMethod(SignatureRSASHA256); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	if signAssertion {
		assertions := descendantsByTag(document.Root(), "Assertion")
		if len(assertions) != 1 {
			t.Fatalf("expected one assertion, got %d", len(assertions))
		}
		replaceWithSignedElement(t, assertions[0], context)
	}
	if signResponse {
		signed, err := context.SignEnveloped(document.Root())
		if err != nil {
			t.Fatalf("sign response: %v", err)
		}
		document.SetRoot(signed)
	}
	result, err := document.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize signed fixture: %v", err)
	}
	return result
}

func replaceWithSignedElement(
	t *testing.T,
	element *etree.Element,
	context *dsig.SigningContext,
) {
	t.Helper()
	parent := element.Parent()
	if parent == nil {
		t.Fatal("signed fixture element has no parent")
	}
	index := element.Index()
	signed, err := context.SignEnveloped(element)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	parent.RemoveChild(element)
	parent.InsertChildAt(index, signed)
}

func boolPointer(value bool) *bool {
	return &value
}

func durationPointer(value time.Duration) *time.Duration {
	return &value
}
