package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/beevik/etree"
)

// Endpoint is one binding endpoint advertised by SAML metadata.
type Endpoint struct {
	Binding          string
	Location         string
	ResponseLocation string
	Index            int
	HasIndex         bool
	IsDefault        bool
}

// KeyDescriptor is one metadata key and its intended use.
type KeyDescriptor struct {
	Use          string
	Certificates []*x509.Certificate
}

// IDPDescriptor contains the IdP metadata used by SSO response validation.
type IDPDescriptor struct {
	WantAuthnRequestsSigned bool
	SingleSignOnServices    []Endpoint
	SingleLogoutServices    []Endpoint
	NameIDFormats           []string
	Keys                    []KeyDescriptor
}

// SPDescriptor contains the SP metadata used by AuthnRequest generation and
// response audience/recipient validation.
type SPDescriptor struct {
	AuthnRequestsSigned       bool
	WantAssertionsSigned      bool
	AssertionConsumerServices []Endpoint
	SingleLogoutServices      []Endpoint
	NameIDFormats             []string
	Keys                      []KeyDescriptor
}

// EntityDescriptor is one EntityDescriptor from a metadata document.
type EntityDescriptor struct {
	EntityID string
	IDP      *IDPDescriptor
	SP       *SPDescriptor
}

// MetadataDocument supports both EntityDescriptor and an EntitiesDescriptor
// containing multiple entities.
type MetadataDocument struct {
	Entities []EntityDescriptor
}

// ParseMetadata parses IdP/SP metadata with size and unsafe-XML guards.
func ParseMetadata(xmlData []byte, maxBytes int) (MetadataDocument, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxMetadataSize
	}
	document, err := parseXML(xmlData, maxBytes)
	if err != nil {
		if IsErrorCode(err, "SAML_DOCUMENT_TOO_LARGE") {
			return MetadataDocument{}, newError(
				"SAML_METADATA_TOO_LARGE",
				fmt.Sprintf("SAML metadata exceeds maximum allowed size (%d bytes)", maxBytes),
				err,
			)
		}
		return MetadataDocument{}, newError(
			"SAML_METADATA_INVALID_XML",
			"SAML metadata XML could not be parsed",
			err,
		)
	}
	entityElements := descendantsByTag(document.Root(), "EntityDescriptor")
	if document.Root().Tag == "EntityDescriptor" {
		entityElements = []*etree.Element{document.Root()}
	}
	entities := make([]EntityDescriptor, 0, len(entityElements))
	for _, element := range entityElements {
		if !namespaceMatches(element, MetadataNamespace) {
			continue
		}
		entity, err := parseEntityDescriptor(element)
		if err != nil {
			return MetadataDocument{}, err
		}
		entities = append(entities, entity)
	}
	if len(entities) == 0 {
		return MetadataDocument{}, newError(
			"SAML_METADATA_ENTITY_MISSING",
			"SAML metadata contains no EntityDescriptor",
		)
	}
	return MetadataDocument{Entities: entities}, nil
}

func parseEntityDescriptor(element *etree.Element) (EntityDescriptor, error) {
	entity := EntityDescriptor{EntityID: element.SelectAttrValue("entityID", "")}
	if entity.EntityID == "" {
		return EntityDescriptor{}, newError(
			"SAML_METADATA_ENTITY_ID_MISSING",
			"SAML metadata EntityDescriptor is missing entityID",
		)
	}
	if idp := firstDirectChild(element, "IDPSSODescriptor", MetadataNamespace); idp != nil {
		parsed, err := parseIDPDescriptor(idp)
		if err != nil {
			return EntityDescriptor{}, err
		}
		entity.IDP = &parsed
	}
	if sp := firstDirectChild(element, "SPSSODescriptor", MetadataNamespace); sp != nil {
		parsed, err := parseSPDescriptor(sp)
		if err != nil {
			return EntityDescriptor{}, err
		}
		entity.SP = &parsed
	}
	return entity, nil
}

func parseIDPDescriptor(element *etree.Element) (IDPDescriptor, error) {
	keys, err := parseKeyDescriptors(element)
	if err != nil {
		return IDPDescriptor{}, err
	}
	return IDPDescriptor{
		WantAuthnRequestsSigned: parseXMLBool(element.SelectAttrValue("WantAuthnRequestsSigned", "")),
		SingleSignOnServices:    parseEndpoints(element, "SingleSignOnService"),
		SingleLogoutServices:    parseEndpoints(element, "SingleLogoutService"),
		NameIDFormats:           parseTextChildren(element, "NameIDFormat"),
		Keys:                    keys,
	}, nil
}

func parseSPDescriptor(element *etree.Element) (SPDescriptor, error) {
	keys, err := parseKeyDescriptors(element)
	if err != nil {
		return SPDescriptor{}, err
	}
	return SPDescriptor{
		AuthnRequestsSigned:       parseXMLBool(element.SelectAttrValue("AuthnRequestsSigned", "")),
		WantAssertionsSigned:      parseXMLBool(element.SelectAttrValue("WantAssertionsSigned", "")),
		AssertionConsumerServices: parseEndpoints(element, "AssertionConsumerService"),
		SingleLogoutServices:      parseEndpoints(element, "SingleLogoutService"),
		NameIDFormats:             parseTextChildren(element, "NameIDFormat"),
		Keys:                      keys,
	}, nil
}

func parseEndpoints(parent *etree.Element, tag string) []Endpoint {
	elements := directChildren(parent, tag, MetadataNamespace)
	endpoints := make([]Endpoint, 0, len(elements))
	for _, element := range elements {
		location := element.SelectAttrValue("Location", "")
		if location == "" {
			continue
		}
		endpoint := Endpoint{
			Binding:          element.SelectAttrValue("Binding", ""),
			Location:         location,
			ResponseLocation: element.SelectAttrValue("ResponseLocation", ""),
			IsDefault:        parseXMLBool(element.SelectAttrValue("isDefault", "")),
		}
		if rawIndex := element.SelectAttrValue("index", ""); rawIndex != "" {
			if index, err := strconv.Atoi(rawIndex); err == nil {
				endpoint.Index = index
				endpoint.HasIndex = true
			}
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func parseTextChildren(parent *etree.Element, tag string) []string {
	var values []string
	for _, element := range directChildren(parent, tag, MetadataNamespace) {
		if value := trimmedText(element); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func parseKeyDescriptors(parent *etree.Element) ([]KeyDescriptor, error) {
	var descriptors []KeyDescriptor
	for _, element := range directChildren(parent, "KeyDescriptor", MetadataNamespace) {
		descriptor := KeyDescriptor{Use: element.SelectAttrValue("use", "")}
		for _, certificateElement := range descendantsByTag(element, "X509Certificate") {
			if certificateElement.NamespaceURI() != XMLDSigNamespace && certificateElement.NamespaceURI() != "" {
				continue
			}
			certificate, err := parseBase64Certificate(trimmedText(certificateElement))
			if err != nil {
				return nil, newError(
					"SAML_METADATA_CERTIFICATE_INVALID",
					"SAML metadata contains an invalid X509 certificate",
					err,
				)
			}
			descriptor.Certificates = appendUniqueCertificate(
				descriptor.Certificates,
				certificate,
			)
		}
		descriptors = append(descriptors, descriptor)
	}
	return descriptors, nil
}

func parseXMLBool(value string) bool {
	return value == "true" || value == "1"
}

func parseBase64Certificate(value string) (*x509.Certificate, error) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, value)
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ParseCertificatesPEM parses one or more trusted signing certificates. Raw
// base64 DER is also accepted for compatibility with SAML configuration UIs.
func ParseCertificatesPEM(value []byte) ([]*x509.Certificate, error) {
	rest := bytes.TrimSpace(value)
	var certificates []*x509.Certificate
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if len(certificates) > 0 {
				break
			}
			certificate, err := parseBase64Certificate(string(rest))
			if err != nil {
				return nil, newError(
					"SAML_CERTIFICATE_INVALID",
					"Invalid SAML signing certificate",
					err,
				)
			}
			return []*x509.Certificate{certificate}, nil
		}
		rest = bytes.TrimSpace(remaining)
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, newError(
				"SAML_CERTIFICATE_INVALID",
				"Invalid SAML signing certificate",
				err,
			)
		}
		certificates = appendUniqueCertificate(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, newError(
			"SAML_CERTIFICATE_INVALID",
			"Invalid SAML signing certificate",
		)
	}
	return certificates, nil
}

func appendUniqueCertificate(
	certificates []*x509.Certificate,
	candidate *x509.Certificate,
) []*x509.Certificate {
	for _, certificate := range certificates {
		if certificate.Equal(candidate) {
			return certificates
		}
	}
	return append(certificates, candidate)
}

// SigningCertificates returns IdP signing keys (use="signing" or unspecified)
// with duplicates removed.
func (descriptor IDPDescriptor) SigningCertificates() []*x509.Certificate {
	var certificates []*x509.Certificate
	for _, key := range descriptor.Keys {
		if key.Use != "" && key.Use != "signing" {
			continue
		}
		for _, certificate := range key.Certificates {
			certificates = appendUniqueCertificate(certificates, certificate)
		}
	}
	return certificates
}

// SigningCertificates returns SP signing keys (use="signing" or unspecified)
// with duplicates removed.
func (descriptor SPDescriptor) SigningCertificates() []*x509.Certificate {
	var certificates []*x509.Certificate
	for _, key := range descriptor.Keys {
		if key.Use != "" && key.Use != "signing" {
			continue
		}
		for _, certificate := range key.Certificates {
			certificates = appendUniqueCertificate(certificates, certificate)
		}
	}
	return certificates
}

// EndpointForBinding returns the first endpoint for binding.
func EndpointForBinding(endpoints []Endpoint, binding string) (Endpoint, bool) {
	for _, endpoint := range endpoints {
		if endpoint.Binding == binding {
			return endpoint, true
		}
	}
	return Endpoint{}, false
}

// PostAssertionConsumerServiceURLs extracts unique HTTP-POST ACS locations,
// matching the reference implementation's metadata helper.
func PostAssertionConsumerServiceURLs(xmlData []byte) []string {
	locations := make([]string, 0)
	document, err := parseXML(xmlData, 0)
	if err != nil {
		return locations
	}
	seen := make(map[string]struct{})
	for _, descriptor := range descendantsByTag(document.Root(), "SPSSODescriptor") {
		for _, service := range directChildrenByTag(descriptor, "AssertionConsumerService") {
			if service.SelectAttrValue("Binding", "") != HTTPPostBinding {
				continue
			}
			location := service.SelectAttrValue("Location", "")
			if location == "" {
				continue
			}
			if _, exists := seen[location]; exists {
				continue
			}
			seen[location] = struct{}{}
			locations = append(locations, location)
		}
	}
	return locations
}
