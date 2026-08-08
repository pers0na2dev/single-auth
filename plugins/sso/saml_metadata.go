package sso

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/beevik/etree"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
)

const spMetadataCacheControl = "no-store"

type samlIDPMaterial struct {
	Issuer       string
	RedirectSSO  string
	Certificates []*x509.Certificate
}

func resolveSAMLRedirectSSO(config SAMLConfig, maxMetadataSize ...int) (string, error) {
	if config.IDPMetadata != nil && strings.TrimSpace(config.IDPMetadata.Metadata) != "" {
		document, err := samlprotocol.ParseMetadata(
			[]byte(config.IDPMetadata.Metadata), metadataSizeLimit(maxMetadataSize...),
		)
		if err != nil {
			return "", err
		}
		entity, err := selectIDPEntity(document, config.IDPMetadata.EntityID)
		if err != nil {
			return "", err
		}
		endpoint, found := samlprotocol.EndpointForBinding(
			entity.IDP.SingleSignOnServices, samlprotocol.HTTPRedirectBinding,
		)
		if !found {
			return "", fmt.Errorf("SAML IdP metadata has no HTTP-Redirect SingleSignOnService")
		}
		if _, err := absoluteHTTPURL(endpoint.Location); err != nil {
			return "", fmt.Errorf("SAML IdP metadata has an invalid HTTP-Redirect SingleSignOnService: %w", err)
		}
		return endpoint.Location, nil
	}
	if config.IDPMetadata != nil {
		for _, endpoint := range config.IDPMetadata.SingleSignOnService {
			if endpoint.Binding != samlprotocol.HTTPRedirectBinding {
				continue
			}
			if _, err := absoluteHTTPURL(endpoint.Location); err != nil {
				return "", fmt.Errorf("SAML IdP configuration has an invalid HTTP-Redirect SingleSignOnService: %w", err)
			}
			return endpoint.Location, nil
		}
	}
	entryPoint := strings.TrimSpace(config.EntryPoint)
	if _, err := absoluteHTTPURL(entryPoint); err != nil {
		return "", fmt.Errorf("SAML IdP entryPoint is invalid: %w", err)
	}
	return entryPoint, nil
}

// resolveSAMLIDPMaterial gives full metadata XML precedence over legacy
// top-level fields, matching single-auth's createIdP helper. An
// EntitiesDescriptor with multiple IdPs must name the intended entity
// explicitly; silently trusting the first entity would make metadata order a
// security boundary.
func resolveSAMLIDPMaterial(config SAMLConfig, maxMetadataSize ...int) (samlIDPMaterial, error) {
	if config.IDPMetadata != nil && strings.TrimSpace(config.IDPMetadata.Metadata) != "" {
		document, err := samlprotocol.ParseMetadata(
			[]byte(config.IDPMetadata.Metadata), metadataSizeLimit(maxMetadataSize...),
		)
		if err != nil {
			return samlIDPMaterial{}, err
		}
		entity, err := selectIDPEntity(document, config.IDPMetadata.EntityID)
		if err != nil {
			return samlIDPMaterial{}, err
		}
		endpoint, found := samlprotocol.EndpointForBinding(
			entity.IDP.SingleSignOnServices, samlprotocol.HTTPRedirectBinding,
		)
		if !found {
			return samlIDPMaterial{}, fmt.Errorf("SAML IdP metadata has no HTTP-Redirect SingleSignOnService")
		}
		if _, err := absoluteHTTPURL(endpoint.Location); err != nil {
			return samlIDPMaterial{}, fmt.Errorf("SAML IdP metadata has an invalid HTTP-Redirect SingleSignOnService: %w", err)
		}
		certificates := entity.IDP.SigningCertificates()
		if len(certificates) == 0 {
			return samlIDPMaterial{}, fmt.Errorf("SAML IdP metadata has no signing certificate")
		}
		return samlIDPMaterial{
			Issuer: entity.EntityID, RedirectSSO: endpoint.Location,
			Certificates: certificates,
		}, nil
	}

	issuer := strings.TrimSpace(config.Issuer)
	certificateValue := config.Certificate
	if config.IDPMetadata != nil {
		if config.IDPMetadata.EntityID != "" {
			issuer = strings.TrimSpace(config.IDPMetadata.EntityID)
		}
		if config.IDPMetadata.Certificate != "" {
			certificateValue = config.IDPMetadata.Certificate
		}
	}
	if issuer == "" {
		return samlIDPMaterial{}, fmt.Errorf("SAML IdP issuer is missing")
	}
	entryPoint, err := resolveSAMLRedirectSSO(config, metadataSizeLimit(maxMetadataSize...))
	if err != nil {
		return samlIDPMaterial{}, err
	}
	certificates, err := samlprotocol.ParseCertificatesPEM([]byte(certificateValue))
	if err != nil {
		return samlIDPMaterial{}, err
	}
	return samlIDPMaterial{
		Issuer: issuer, RedirectSSO: entryPoint, Certificates: certificates,
	}, nil
}

func selectIDPEntity(
	document samlprotocol.MetadataDocument,
	entityID string,
) (samlprotocol.EntityDescriptor, error) {
	candidates := make([]samlprotocol.EntityDescriptor, 0, len(document.Entities))
	for _, entity := range document.Entities {
		if entity.IDP == nil {
			continue
		}
		if entityID == "" || entity.EntityID == entityID {
			candidates = append(candidates, entity)
		}
	}
	if len(candidates) == 0 {
		if entityID != "" {
			return samlprotocol.EntityDescriptor{}, fmt.Errorf("SAML IdP metadata does not contain entity %q", entityID)
		}
		return samlprotocol.EntityDescriptor{}, fmt.Errorf("SAML metadata contains no IdP entity")
	}
	if len(candidates) != 1 {
		return samlprotocol.EntityDescriptor{}, fmt.Errorf("SAML IdP metadata is ambiguous; configure idpMetadata.entityID")
	}
	return candidates[0], nil
}

func (p *plugin) spMetadata(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil || len(query["providerId"]) != 1 || len(query["format"]) > 1 {
		return contract.Response{}, apiError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters",
		)
	}
	providerID := query.Get("providerId")
	format := query.Get("format")
	if format != "" && format != "xml" && format != "json" {
		return contract.Response{}, apiError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters",
		)
	}
	provider, err := p.findProvider(ctx, providerID, "")
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: find provider: %w", err)
	}
	if provider == nil {
		return contract.Response{}, apiError(
			contract.StatusNotFound, "NOT_FOUND", "No provider found for the given providerId",
		)
	}
	if provider.SAMLConfig == nil {
		return contract.Response{}, invalidSAMLConfigurationError()
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: resolve base URL: %w", err)
	}
	metadata, err := serviceProviderMetadata(
		*provider.SAMLConfig, strings.TrimRight(baseURL, "/"), providerID,
		p.options.SAML.MaxMetadataSize, p.options.SAML.EnableSingleLogout,
	)
	if err != nil {
		return contract.Response{}, invalidSAMLConfigurationError()
	}
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "Content-Type", Value: "application/xml"},
		contract.HeaderField{Name: "Cache-Control", Value: spMetadataCacheControl},
		contract.HeaderField{Name: "Pragma", Value: "no-cache"},
		contract.HeaderField{Name: "X-Content-Type-Options", Value: "nosniff"},
	)
	return contract.NewResponse(http.StatusOK, headers, metadata), nil
}

func serviceProviderMetadata(config SAMLConfig, baseURL, providerID string, maxMetadataSize int, enableSLO ...bool) ([]byte, error) {
	if config.SPMetadata != nil && strings.TrimSpace(config.SPMetadata.Metadata) != "" {
		metadata := []byte(config.SPMetadata.Metadata)
		document, err := samlprotocol.ParseMetadata(metadata, metadataSizeLimit(maxMetadataSize))
		if err != nil {
			return nil, err
		}
		spEntities := 0
		for _, entity := range document.Entities {
			if entity.SP != nil {
				spEntities++
			}
		}
		if spEntities != 1 {
			return nil, fmt.Errorf("SAML SP metadata is ambiguous; publish exactly one SP entity")
		}
		entity, err := selectSPEntity(document, config.SPMetadata.EntityID)
		if err != nil {
			return nil, err
		}
		hasPostACS := false
		for _, endpoint := range entity.SP.AssertionConsumerServices {
			if endpoint.Binding != samlprotocol.HTTPPostBinding {
				continue
			}
			hasPostACS = true
			if _, err := absoluteHTTPURL(endpoint.Location); err != nil {
				return nil, fmt.Errorf("SAML SP metadata has an invalid HTTP-POST AssertionConsumerService: %w", err)
			}
		}
		if !hasPostACS {
			return nil, fmt.Errorf("SAML SP metadata has no HTTP-POST AssertionConsumerService")
		}
		return append([]byte(nil), metadata...), nil
	}

	entityID := serviceProviderEntityID(config)
	if entityID == "" {
		return nil, fmt.Errorf("SAML SP entityID is missing")
	}
	acsLocation := strings.TrimSpace(config.CallbackURL)
	if acsLocation == "" {
		acsLocation = strings.TrimRight(baseURL, "/") + "/sso/saml2/sp/acs/" + url.PathEscape(providerID)
	}
	if _, err := absoluteHTTPURL(acsLocation); err != nil {
		return nil, fmt.Errorf("SAML SP AssertionConsumerService is invalid: %w", err)
	}

	document := etree.NewDocument()
	entity := document.CreateElement("md:EntityDescriptor")
	entity.CreateAttr("xmlns:md", samlprotocol.MetadataNamespace)
	entity.CreateAttr("entityID", entityID)
	descriptor := entity.CreateElement("md:SPSSODescriptor")
	descriptor.CreateAttr("AuthnRequestsSigned", xmlBool(config.AuthnRequestsSigned))
	descriptor.CreateAttr("WantAssertionsSigned", xmlBool(config.WantAssertionsSigned))
	descriptor.CreateAttr("protocolSupportEnumeration", samlprotocol.ProtocolNamespace)
	if format := strings.TrimSpace(config.IdentifierFormat); format != "" {
		descriptor.CreateElement("md:NameIDFormat").SetText(format)
	}
	if len(enableSLO) > 0 && enableSLO[0] {
		sloLocation := strings.TrimRight(baseURL, "/") + "/sso/saml2/sp/slo/" + url.PathEscape(providerID)
		for _, binding := range []string{samlprotocol.HTTPPostBinding, samlprotocol.HTTPRedirectBinding} {
			service := descriptor.CreateElement("md:SingleLogoutService")
			service.CreateAttr("Binding", binding)
			service.CreateAttr("Location", sloLocation)
		}
	}
	acs := descriptor.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", samlprotocol.HTTPPostBinding)
	acs.CreateAttr("Location", acsLocation)
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")
	document.SetRoot(entity)
	return document.WriteToBytes()
}

func serviceProviderEntityID(config SAMLConfig) string {
	entityID := strings.TrimSpace(config.Issuer)
	if config.SPMetadata != nil && strings.TrimSpace(config.SPMetadata.EntityID) != "" {
		entityID = strings.TrimSpace(config.SPMetadata.EntityID)
	}
	return entityID
}

func selectSPEntity(
	document samlprotocol.MetadataDocument,
	entityID string,
) (samlprotocol.EntityDescriptor, error) {
	candidates := make([]samlprotocol.EntityDescriptor, 0, len(document.Entities))
	for _, entity := range document.Entities {
		if entity.SP == nil {
			continue
		}
		if entityID == "" || entity.EntityID == entityID {
			candidates = append(candidates, entity)
		}
	}
	if len(candidates) == 0 {
		if entityID != "" {
			return samlprotocol.EntityDescriptor{}, fmt.Errorf("SAML SP metadata does not contain entity %q", entityID)
		}
		return samlprotocol.EntityDescriptor{}, fmt.Errorf("SAML metadata contains no SP entity")
	}
	if len(candidates) != 1 {
		return samlprotocol.EntityDescriptor{}, fmt.Errorf("SAML SP metadata is ambiguous; configure spMetadata.entityID")
	}
	return candidates[0], nil
}

func xmlBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
