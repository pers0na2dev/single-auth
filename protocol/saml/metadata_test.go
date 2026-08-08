package saml

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

func TestParseMetadata(t *testing.T) {
	t.Parallel()
	_, certificate := testKeyPair(t)
	encodedCertificate := base64.StdEncoding.EncodeToString(certificate.Raw)
	metadata := []byte(fmt.Sprintf(`<md:EntitiesDescriptor xmlns:md="%s" xmlns:ds="%s">
  <md:EntityDescriptor entityID="%s">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="true">
      <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
        %s
      </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:NameIDFormat>urn:test:nameid</md:NameIDFormat>
      <md:SingleSignOnService Binding="%s" Location="https://idp.example.com/redirect"/>
      <md:SingleSignOnService Binding="%s" Location="https://idp.example.com/post"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="%s">
    <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true">
      <md:AssertionConsumerService Binding="%s" Location="%s" index="0" isDefault="true"/>
    </md:SPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`,
		MetadataNamespace,
		XMLDSigNamespace,
		fixtureIssuer,
		encodedCertificate,
		encodedCertificate,
		HTTPRedirectBinding,
		HTTPPostBinding,
		fixtureAudience,
		HTTPPostBinding,
		fixtureRecipient,
	))
	document, err := ParseMetadata(metadata, DefaultMaxMetadataSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Entities) != 2 {
		t.Fatalf("entities = %+v", document.Entities)
	}
	idp := document.Entities[0]
	if idp.EntityID != fixtureIssuer || idp.IDP == nil ||
		!idp.IDP.WantAuthnRequestsSigned || len(idp.IDP.SingleSignOnServices) != 2 ||
		len(idp.IDP.NameIDFormats) != 1 {
		t.Fatalf("IdP metadata = %+v", idp)
	}
	if endpoint, found := EndpointForBinding(idp.IDP.SingleSignOnServices, HTTPPostBinding); !found || endpoint.Location != "https://idp.example.com/post" {
		t.Fatalf("POST endpoint = %+v, found = %t", endpoint, found)
	}
	signingCertificates := idp.IDP.SigningCertificates()
	if len(signingCertificates) != 1 || !signingCertificates[0].Equal(certificate) {
		t.Fatalf("signing certificates = %v", signingCertificates)
	}
	sp := document.Entities[1]
	if sp.SP == nil || !sp.SP.AuthnRequestsSigned || !sp.SP.WantAssertionsSigned ||
		len(sp.SP.AssertionConsumerServices) != 1 ||
		!sp.SP.AssertionConsumerServices[0].HasIndex ||
		!sp.SP.AssertionConsumerServices[0].IsDefault {
		t.Fatalf("SP metadata = %+v", sp)
	}
}

func TestParseCertificatesPEMAndRawDER(t *testing.T) {
	t.Parallel()
	_, certificate := testKeyPair(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	certificates, err := ParseCertificatesPEM(pemData)
	if err != nil || len(certificates) != 1 || !certificates[0].Equal(certificate) {
		t.Fatalf("PEM certificates = %v, error = %v", certificates, err)
	}
	raw := base64.StdEncoding.EncodeToString(certificate.Raw)
	certificates, err = ParseCertificatesPEM([]byte(raw))
	if err != nil || len(certificates) != 1 || !certificates[0].Equal(certificate) {
		t.Fatalf("raw certificates = %v, error = %v", certificates, err)
	}
	if _, err := ParseCertificatesPEM([]byte("not a certificate")); !IsErrorCode(err, "SAML_CERTIFICATE_INVALID") {
		t.Fatalf("invalid certificate error = %v", err)
	}
}

func TestMetadataGuards(t *testing.T) {
	t.Parallel()
	if _, err := ParseMetadata(
		[]byte(`<!DOCTYPE EntityDescriptor><EntityDescriptor entityID="x"/>`),
		DefaultMaxMetadataSize,
	); !IsErrorCode(err, "SAML_METADATA_INVALID_XML") {
		t.Fatalf("unsafe metadata error = %v", err)
	}
	oversized := []byte(`<EntityDescriptor entityID="x">` + strings.Repeat(" ", 128) + `</EntityDescriptor>`)
	if _, err := ParseMetadata(oversized, 64); !IsErrorCode(err, "SAML_METADATA_TOO_LARGE") {
		t.Fatalf("oversized metadata error = %v", err)
	}
	if _, err := ParseMetadata([]byte(`<EntityDescriptor/>`), 1024); !IsErrorCode(err, "SAML_METADATA_ENTITY_ID_MISSING") {
		t.Fatalf("missing entity ID error = %v", err)
	}
}
