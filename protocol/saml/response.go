package saml

import (
	"fmt"

	"github.com/beevik/etree"
)

// SubjectConfirmationData is one bearer confirmation target and correlation
// tuple from an assertion.
type SubjectConfirmationData struct {
	Method       string
	Recipient    string
	RecipientSet bool
	InResponseTo string
	NotBefore    string
	NotOnOrAfter string
}

// Assertion is the security-relevant data extracted from the single direct
// assertion in a SAML response.
type Assertion struct {
	ID                   string
	Version              string
	IssueInstant         string
	Issuer               string
	NameID               string
	SessionIndex         string
	Conditions           Conditions
	AudienceRestrictions [][]string
	SubjectConfirmations []SubjectConfirmationData
	Attributes           map[string][]string

	element *etree.Element
}

// Response is the parsed protocol response and its single assertion.
type Response struct {
	ID           string
	Version      string
	Issuer       string
	Destination  string
	InResponseTo string
	IssueInstant string
	StatusCode   string
	Assertion    Assertion

	element *etree.Element
	// signatureElement retains the original encrypted Response for XMLDSIG
	// verification. Replacing EncryptedAssertion with plaintext necessarily
	// changes the document and would otherwise invalidate a legitimate outer
	// Response signature.
	signatureElement *etree.Element
}

// ParseResponse parses a structurally guarded plain-text SAML response.
func ParseResponse(xmlData []byte) (Response, error) {
	return ParseResponseWithLimit(xmlData, DefaultMaxResponseSize)
}

// ParseResponseWithLimit parses a response with a caller-selected decoded XML
// size limit. A non-positive limit uses DefaultMaxResponseSize.
func ParseResponseWithLimit(xmlData []byte, maxBytes int) (Response, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseSize
	}
	if err := validateSingleAssertionXMLWithLimit(xmlData, maxBytes); err != nil {
		return Response{}, err
	}
	document, err := parseXML(xmlData, maxBytes)
	if err != nil {
		return Response{}, newError(
			"SAML_RESPONSE_INVALID_XML",
			"SAML response XML could not be parsed",
			err,
		)
	}
	if err := validateUniqueIDs(document.Root()); err != nil {
		return Response{}, err
	}
	root := document.Root()
	var responseElement *etree.Element
	var assertionElement *etree.Element
	switch {
	case root.Tag == "Response" && namespaceMatches(root, ProtocolNamespace):
		responseElement = root
		assertions := directChildren(root, "Assertion", AssertionNamespace)
		if len(assertions) == 1 {
			assertionElement = assertions[0]
		}
	case root.Tag == "Assertion" && namespaceMatches(root, AssertionNamespace):
		assertionElement = root
	default:
		return Response{}, newError(
			"SAML_RESPONSE_ROOT_INVALID",
			"SAML document root must be a Response or Assertion",
		)
	}
	if assertionElement == nil {
		if len(descendantsByTag(root, "EncryptedAssertion")) > 0 {
			return Response{}, newError(
				"SAML_ENCRYPTED_ASSERTION_UNSUPPORTED",
				"Encrypted SAML assertions require a configured decryption hook",
			)
		}
		return Response{}, newError(
			"SAML_ASSERTION_MISSING",
			"SAML response is missing an assertion",
		)
	}
	assertion := parseAssertion(assertionElement)
	response := Response{Assertion: assertion, element: responseElement}
	if responseElement == nil {
		response.element = assertionElement
		return response, nil
	}
	response.ID = responseElement.SelectAttrValue("ID", "")
	response.Version = responseElement.SelectAttrValue("Version", "")
	response.Destination = responseElement.SelectAttrValue("Destination", "")
	response.InResponseTo = responseElement.SelectAttrValue("InResponseTo", "")
	response.IssueInstant = responseElement.SelectAttrValue("IssueInstant", "")
	response.Issuer = trimmedText(firstDirectChild(responseElement, "Issuer", AssertionNamespace))
	if status := firstDirectChild(responseElement, "Status", ProtocolNamespace); status != nil {
		if code := firstDirectChild(status, "StatusCode", ProtocolNamespace); code != nil {
			response.StatusCode = code.SelectAttrValue("Value", "")
		}
	}
	return response, nil
}

func parseAssertion(element *etree.Element) Assertion {
	assertion := Assertion{
		ID:           element.SelectAttrValue("ID", ""),
		Version:      element.SelectAttrValue("Version", ""),
		IssueInstant: element.SelectAttrValue("IssueInstant", ""),
		Issuer:       trimmedText(firstDirectChild(element, "Issuer", AssertionNamespace)),
		Attributes:   make(map[string][]string),
		element:      element,
	}
	if subject := firstDirectChild(element, "Subject", AssertionNamespace); subject != nil {
		assertion.NameID = trimmedText(firstDirectChild(subject, "NameID", AssertionNamespace))
		for _, confirmation := range directChildren(subject, "SubjectConfirmation", AssertionNamespace) {
			data := firstDirectChild(confirmation, "SubjectConfirmationData", AssertionNamespace)
			if data == nil {
				continue
			}
			assertion.SubjectConfirmations = append(
				assertion.SubjectConfirmations,
				SubjectConfirmationData{
					Method:       confirmation.SelectAttrValue("Method", ""),
					Recipient:    data.SelectAttrValue("Recipient", ""),
					RecipientSet: data.SelectAttr("Recipient") != nil,
					InResponseTo: data.SelectAttrValue("InResponseTo", ""),
					NotBefore:    data.SelectAttrValue("NotBefore", ""),
					NotOnOrAfter: data.SelectAttrValue("NotOnOrAfter", ""),
				},
			)
		}
	}
	if conditions := firstDirectChild(element, "Conditions", AssertionNamespace); conditions != nil {
		assertion.Conditions = Conditions{
			NotBefore:    conditions.SelectAttrValue("NotBefore", ""),
			NotOnOrAfter: conditions.SelectAttrValue("NotOnOrAfter", ""),
		}
		for _, restriction := range directChildren(conditions, "AudienceRestriction", AssertionNamespace) {
			var audiences []string
			for _, audience := range directChildren(restriction, "Audience", AssertionNamespace) {
				if value := trimmedText(audience); value != "" {
					audiences = append(audiences, value)
				}
			}
			assertion.AudienceRestrictions = append(assertion.AudienceRestrictions, audiences)
		}
	}
	if authnStatement := firstDirectChild(element, "AuthnStatement", AssertionNamespace); authnStatement != nil {
		assertion.SessionIndex = authnStatement.SelectAttrValue("SessionIndex", "")
	}
	for _, statement := range directChildren(element, "AttributeStatement", AssertionNamespace) {
		for _, attribute := range directChildren(statement, "Attribute", AssertionNamespace) {
			name := attribute.SelectAttrValue("Name", "")
			if name == "" {
				continue
			}
			for _, value := range directChildren(attribute, "AttributeValue", AssertionNamespace) {
				assertion.Attributes[name] = append(assertion.Attributes[name], trimmedText(value))
			}
		}
	}
	return assertion
}

func validateUniqueIDs(root *etree.Element) error {
	seen := make(map[string]struct{})
	var visit func(*etree.Element) error
	visit = func(element *etree.Element) error {
		var elementID string
		idAttributeCount := 0
		for _, name := range []string{"ID", "Id", "id"} {
			value := element.SelectAttrValue(name, "")
			if value == "" {
				continue
			}
			idAttributeCount++
			elementID = value
		}
		if idAttributeCount > 1 {
			return newError(
				"SAML_AMBIGUOUS_ID",
				"SAML element contains multiple ID attributes",
			)
		}
		if elementID != "" {
			if _, duplicate := seen[elementID]; duplicate {
				return newError(
					"SAML_DUPLICATE_ID",
					fmt.Sprintf("SAML document contains duplicate ID: %s", elementID),
				)
			}
			seen[elementID] = struct{}{}
		}
		for _, child := range element.ChildElements() {
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root)
}

// ResponseBindingValidationOptions configures audience, bearer recipient, and
// response Destination checks.
type ResponseBindingValidationOptions struct {
	ExpectedAudiences  []string
	ExpectedRecipients []string
}

// ValidateResponseBindingXML is the direct Go counterpart of the reference implementation's
// validateSAMLResponseBinding. It parses only the binding-relevant fields and
// returns the same HTTP-facing API errors as the upstream helper.
func ValidateResponseBindingXML(
	xmlData []byte,
	options ResponseBindingValidationOptions,
) error {
	response, err := parseResponseBindingXML(xmlData)
	if err != nil {
		return err
	}
	return ValidateResponseBinding(response, options)
}

func parseResponseBindingXML(xmlData []byte) (Response, error) {
	document, err := parseXML(xmlData, 0)
	if err != nil {
		return Response{}, newResponseBindingBadRequest(
			"SAML_RESPONSE_INVALID_XML",
			"SAML response XML could not be parsed",
		)
	}
	root := document.Root()
	var responseElement *etree.Element
	var assertionElement *etree.Element
	switch root.Tag {
	case "Response":
		responseElement = root
		assertionElement = firstDirectChildByTag(root, "Assertion")
	case "Assertion":
		assertionElement = root
	}
	if assertionElement == nil {
		return Response{}, newResponseBindingBadRequest(
			"SAML_ASSERTION_MISSING",
			"SAML response is missing an assertion",
		)
	}

	assertion := Assertion{Attributes: make(map[string][]string), element: assertionElement}
	if conditions := firstDirectChildByTag(assertionElement, "Conditions"); conditions != nil {
		for _, restriction := range directChildrenByTag(conditions, "AudienceRestriction") {
			audiences := make([]string, 0)
			for _, audience := range directChildrenByTag(restriction, "Audience") {
				if value := trimmedText(audience); value != "" {
					audiences = append(audiences, value)
				}
			}
			assertion.AudienceRestrictions = append(assertion.AudienceRestrictions, audiences)
		}
	}
	if subject := firstDirectChildByTag(assertionElement, "Subject"); subject != nil {
		for _, confirmation := range directChildrenByTag(subject, "SubjectConfirmation") {
			data := firstDirectChildByTag(confirmation, "SubjectConfirmationData")
			if data == nil {
				continue
			}
			assertion.SubjectConfirmations = append(
				assertion.SubjectConfirmations,
				SubjectConfirmationData{
					Method:       confirmation.SelectAttrValue("Method", ""),
					Recipient:    data.SelectAttrValue("Recipient", ""),
					RecipientSet: data.SelectAttr("Recipient") != nil,
				},
			)
		}
	}
	response := Response{Assertion: assertion, element: responseElement}
	if responseElement != nil {
		response.Destination = responseElement.SelectAttrValue("Destination", "")
	}
	return response, nil
}

func directChildrenByTag(parent *etree.Element, tag string) []*etree.Element {
	if parent == nil {
		return nil
	}
	children := make([]*etree.Element, 0)
	for _, child := range parent.ChildElements() {
		if child.Tag == tag {
			children = append(children, child)
		}
	}
	return children
}

func firstDirectChildByTag(parent *etree.Element, tag string) *etree.Element {
	children := directChildrenByTag(parent, tag)
	if len(children) == 0 {
		return nil
	}
	return children[0]
}

func newResponseBindingBadRequest(code, message string) *APIError {
	err := newBadRequest(code, message)
	err.Body["code"] = code
	return err
}

// ValidateResponseBinding enforces the reference implementation's exact audience-group and
// bearer recipient semantics.
func ValidateResponseBinding(
	response Response,
	options ResponseBindingValidationOptions,
) error {
	expectedAudiences := stringSet(options.ExpectedAudiences)
	expectedRecipients := stringSet(options.ExpectedRecipients)
	groups := response.Assertion.AudienceRestrictions
	if len(groups) == 0 || everyAudienceGroupEmpty(groups) {
		return newResponseBindingBadRequest(
			"SAML_AUDIENCE_MISSING",
			"SAML assertion is missing an AudienceRestriction",
		)
	}
	for _, group := range groups {
		matched := false
		for _, audience := range group {
			if _, ok := expectedAudiences[audience]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return newResponseBindingBadRequest(
				"SAML_AUDIENCE_MISMATCH",
				"SAML assertion audience does not match this Service Provider",
			)
		}
	}

	var bearer []SubjectConfirmationData
	for _, confirmation := range response.Assertion.SubjectConfirmations {
		if confirmation.Method == BearerConfirmation {
			bearer = append(bearer, confirmation)
		}
	}
	if len(bearer) == 0 {
		return newResponseBindingBadRequest(
			"SAML_BEARER_CONFIRMATION_MISSING",
			"SAML assertion is missing bearer SubjectConfirmationData",
		)
	}
	hasRecipient := false
	matchedRecipient := false
	for _, confirmation := range bearer {
		if confirmation.Recipient == "" && !confirmation.RecipientSet {
			continue
		}
		hasRecipient = true
		if _, ok := expectedRecipients[confirmation.Recipient]; ok {
			matchedRecipient = true
		}
	}
	if !hasRecipient {
		return newResponseBindingBadRequest(
			"SAML_RECIPIENT_MISSING",
			"SAML bearer SubjectConfirmationData is missing a Recipient",
		)
	}
	if !matchedRecipient {
		return newResponseBindingBadRequest(
			"SAML_RECIPIENT_MISMATCH",
			"SAML bearer SubjectConfirmationData Recipient does not match this Service Provider",
		)
	}
	if response.Destination != "" {
		if _, ok := expectedRecipients[response.Destination]; !ok {
			return newResponseBindingBadRequest(
				"SAML_DESTINATION_MISMATCH",
				"SAML response Destination does not match this Service Provider",
			)
		}
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

func everyAudienceGroupEmpty(groups [][]string) bool {
	for _, group := range groups {
		if len(group) > 0 {
			return false
		}
	}
	return true
}

// HasEncryptedAssertion reports whether XML contains an EncryptedAssertion.
func HasEncryptedAssertion(xmlData []byte) bool {
	document, err := parseXML(xmlData, 0)
	return err == nil && len(descendantsByTag(document.Root(), "EncryptedAssertion")) > 0
}
