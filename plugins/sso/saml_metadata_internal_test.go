package sso

import (
	"strings"
	"testing"
)

func TestValidateSAMLRegistrationAllowsMetadataOnlyTrust(t *testing.T) {
	config := map[string]any{
		"callbackUrl": "https://sp.example.com/acs",
		"spMetadata":  map[string]any{},
		"idpMetadata": map[string]any{
			"metadata": `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"/>`,
		},
	}
	if err := validateSAMLRegistration(config); err != nil {
		t.Fatalf("metadata-only registration rejected: %v", err)
	}

	delete(config, "idpMetadata")
	if err := validateSAMLRegistration(config); err == nil {
		t.Fatal("registration without metadata, entryPoint, or certificate was accepted")
	}
}

func TestConfigurableSAMLMetadataLimitAppliesToRegistrationAndParsing(t *testing.T) {
	const limit = 64
	metadata := strings.Repeat("x", limit+1)
	config := map[string]any{
		"callbackUrl": "https://sp.example.com/acs",
		"spMetadata":  map[string]any{},
		"idpMetadata": map[string]any{"metadata": metadata},
	}
	if err := validateSAMLRegistration(config, limit); err == nil ||
		!strings.Contains(err.Error(), "IdP metadata exceeds maximum allowed size (64 bytes)") {
		t.Fatalf("oversized registration error=%v", err)
	}
	if err := validateSAMLMetadataSize(SAMLConfig{
		IDPMetadata: &SAMLIDPMetadata{Metadata: metadata},
	}, limit); err == nil {
		t.Fatal("oversized configured metadata was accepted")
	}

	valid := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"/>`
	if _, err := resolveSAMLRedirectSSO(SAMLConfig{
		IDPMetadata: &SAMLIDPMetadata{Metadata: valid},
	}, len(valid)-1); err == nil {
		t.Fatal("runtime metadata parse ignored configured byte limit")
	}
}

func TestSSOProviderSchemaPhysicalNames(t *testing.T) {
	schema := providerSchemaWithOptions(Options{
		ModelName: "enterprise_identity_provider",
		Fields: ProviderFieldNames{
			Issuer: "issuer_url", ProviderID: "provider_slug", Domain: "email_domain",
		},
		DomainVerification: DomainVerificationOptions{Enabled: true},
	})
	model := schema.Models["ssoProvider"]
	if model.ModelName != "enterprise_identity_provider" ||
		model.Fields["issuer"].FieldName != "issuer_url" ||
		model.Fields["providerId"].FieldName != "provider_slug" ||
		model.Fields["domain"].FieldName != "email_domain" ||
		model.Fields["domainVerified"].Type == "" {
		t.Fatalf("mapped schema=%#v", model)
	}
}
