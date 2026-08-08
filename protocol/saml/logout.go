package saml

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/beevik/etree"
)

// LogoutRequest is the security-relevant SAML Single Logout request envelope.
type LogoutRequest struct {
	ID             string
	Version        string
	IssueInstant   string
	Destination    string
	Issuer         string
	NameID         string
	SessionIndexes []string
	XML            []byte

	element *etree.Element
}

// LogoutResponse is the security-relevant SAML Single Logout response envelope.
type LogoutResponse struct {
	ID           string
	Version      string
	IssueInstant string
	Destination  string
	InResponseTo string
	Issuer       string
	StatusCode   string
	XML          []byte

	element *etree.Element
}

// LogoutRequestOptions configures an outbound SAML LogoutRequest.
type LogoutRequestOptions struct {
	ID           string
	Issuer       string
	Destination  string
	NameID       string
	SessionIndex string
	IssueInstant time.Time
	IDGenerator  func() (string, error)
}

// LogoutResponseOptions configures an outbound SAML LogoutResponse.
type LogoutResponseOptions struct {
	ID           string
	Issuer       string
	Destination  string
	InResponseTo string
	StatusCode   string
	IssueInstant time.Time
	IDGenerator  func() (string, error)
}

// LogoutValidationOptions applies the common SLO trust-boundary checks.
type LogoutValidationOptions struct {
	ExpectedIssuer      string
	ExpectedDestination string
	RequireSignature    bool
	Certificates        []*x509.Certificate
	Algorithms          AlgorithmValidationOptions
	ClockSkew           time.Duration
	Now                 func() time.Time
	MaxMessageSize      int
}

// NewLogoutRequest creates an unsigned protocol request. Redirect-binding
// signatures are applied by BuildRedirectURL; POST XML signatures can be
// applied with SignXMLMessage.
func NewLogoutRequest(options LogoutRequestOptions) (LogoutRequest, error) {
	if options.Issuer == "" || options.Destination == "" || options.NameID == "" {
		return LogoutRequest{}, newError(
			"SAML_LOGOUT_REQUEST_INVALID",
			"SAML LogoutRequest requires Issuer, Destination, and NameID",
		)
	}
	id, err := logoutMessageID(options.ID, options.IDGenerator)
	if err != nil {
		return LogoutRequest{}, err
	}
	issuedAt := options.IssueInstant.UTC()
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}

	var document bytes.Buffer
	document.WriteString(`<samlp:LogoutRequest xmlns:samlp="`)
	writeXMLEscaped(&document, ProtocolNamespace)
	document.WriteString(`" xmlns:saml="`)
	writeXMLEscaped(&document, AssertionNamespace)
	document.WriteString(`" ID="`)
	writeXMLEscaped(&document, id)
	document.WriteString(`" Version="2.0" IssueInstant="`)
	writeXMLEscaped(&document, issuedAt.Format(time.RFC3339Nano))
	document.WriteString(`" Destination="`)
	writeXMLEscaped(&document, options.Destination)
	document.WriteString(`"><saml:Issuer>`)
	writeXMLText(&document, options.Issuer)
	document.WriteString(`</saml:Issuer><saml:NameID>`)
	writeXMLText(&document, options.NameID)
	document.WriteString(`</saml:NameID>`)
	if options.SessionIndex != "" {
		document.WriteString(`<samlp:SessionIndex>`)
		writeXMLText(&document, options.SessionIndex)
		document.WriteString(`</samlp:SessionIndex>`)
	}
	document.WriteString(`</samlp:LogoutRequest>`)
	return LogoutRequest{
		ID: id, Version: "2.0", IssueInstant: issuedAt.Format(time.RFC3339Nano),
		Destination: options.Destination, Issuer: options.Issuer,
		NameID: options.NameID, SessionIndexes: compactLogoutValues(options.SessionIndex),
		XML: append([]byte(nil), document.Bytes()...),
	}, nil
}

// NewLogoutResponse creates an unsigned Success response unless StatusCode is
// supplied explicitly.
func NewLogoutResponse(options LogoutResponseOptions) (LogoutResponse, error) {
	if options.Issuer == "" || options.Destination == "" || options.InResponseTo == "" {
		return LogoutResponse{}, newError(
			"SAML_LOGOUT_RESPONSE_INVALID",
			"SAML LogoutResponse requires Issuer, Destination, and InResponseTo",
		)
	}
	id, err := logoutMessageID(options.ID, options.IDGenerator)
	if err != nil {
		return LogoutResponse{}, err
	}
	issuedAt := options.IssueInstant.UTC()
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	status := options.StatusCode
	if status == "" {
		status = StatusSuccess
	}

	var document bytes.Buffer
	document.WriteString(`<samlp:LogoutResponse xmlns:samlp="`)
	writeXMLEscaped(&document, ProtocolNamespace)
	document.WriteString(`" xmlns:saml="`)
	writeXMLEscaped(&document, AssertionNamespace)
	document.WriteString(`" ID="`)
	writeXMLEscaped(&document, id)
	document.WriteString(`" Version="2.0" IssueInstant="`)
	writeXMLEscaped(&document, issuedAt.Format(time.RFC3339Nano))
	document.WriteString(`" Destination="`)
	writeXMLEscaped(&document, options.Destination)
	document.WriteString(`" InResponseTo="`)
	writeXMLEscaped(&document, options.InResponseTo)
	document.WriteString(`"><saml:Issuer>`)
	writeXMLText(&document, options.Issuer)
	document.WriteString(`</saml:Issuer><samlp:Status><samlp:StatusCode Value="`)
	writeXMLEscaped(&document, status)
	document.WriteString(`" /></samlp:Status></samlp:LogoutResponse>`)
	return LogoutResponse{
		ID: id, Version: "2.0", IssueInstant: issuedAt.Format(time.RFC3339Nano),
		Destination: options.Destination, InResponseTo: options.InResponseTo,
		Issuer: options.Issuer, StatusCode: status,
		XML: append([]byte(nil), document.Bytes()...),
	}, nil
}

// ParseLogoutRequest parses a decoded LogoutRequest with strict root,
// namespace, duplicate-ID, and direct-child checks.
func ParseLogoutRequest(xmlData []byte, maxBytes int) (LogoutRequest, error) {
	document, root, err := parseLogoutRoot(xmlData, maxBytes, "LogoutRequest")
	if err != nil {
		return LogoutRequest{}, err
	}
	request := LogoutRequest{
		ID: root.SelectAttrValue("ID", ""), Version: root.SelectAttrValue("Version", ""),
		IssueInstant: root.SelectAttrValue("IssueInstant", ""),
		Destination:  root.SelectAttrValue("Destination", ""),
		Issuer:       trimmedText(firstDirectChild(root, "Issuer", AssertionNamespace)),
		NameID:       trimmedText(firstDirectChild(root, "NameID", AssertionNamespace)),
		XML:          append([]byte(nil), xmlData...), element: root,
	}
	for _, index := range directChildren(root, "SessionIndex", ProtocolNamespace) {
		if value := trimmedText(index); value != "" {
			request.SessionIndexes = append(request.SessionIndexes, value)
		}
	}
	_ = document
	return request, nil
}

// ParseLogoutResponse parses a decoded LogoutResponse with strict structural
// checks.
func ParseLogoutResponse(xmlData []byte, maxBytes int) (LogoutResponse, error) {
	_, root, err := parseLogoutRoot(xmlData, maxBytes, "LogoutResponse")
	if err != nil {
		return LogoutResponse{}, err
	}
	response := LogoutResponse{
		ID: root.SelectAttrValue("ID", ""), Version: root.SelectAttrValue("Version", ""),
		IssueInstant: root.SelectAttrValue("IssueInstant", ""),
		Destination:  root.SelectAttrValue("Destination", ""),
		InResponseTo: root.SelectAttrValue("InResponseTo", ""),
		Issuer:       trimmedText(firstDirectChild(root, "Issuer", AssertionNamespace)),
		XML:          append([]byte(nil), xmlData...), element: root,
	}
	if status := firstDirectChild(root, "Status", ProtocolNamespace); status != nil {
		if code := firstDirectChild(status, "StatusCode", ProtocolNamespace); code != nil {
			response.StatusCode = code.SelectAttrValue("Value", "")
		}
	}
	return response, nil
}

// ValidateLogoutRequest verifies a parsed request after its transport binding
// has been decoded. A valid Redirect signature satisfies RequireSignature.
func ValidateLogoutRequest(
	ctx context.Context,
	request LogoutRequest,
	bindingSigned bool,
	options LogoutValidationOptions,
) error {
	if err := validateLogoutEnvelope(ctx, request.ID, request.Version, request.IssueInstant,
		request.Destination, request.Issuer, request.XML, request.element, bindingSigned, options); err != nil {
		return err
	}
	if request.NameID == "" {
		return newError("SAML_LOGOUT_NAME_ID_MISSING", "SAML LogoutRequest is missing NameID")
	}
	return nil
}

// ValidateLogoutResponse verifies a parsed response after its transport
// binding has been decoded.
func ValidateLogoutResponse(
	ctx context.Context,
	response LogoutResponse,
	bindingSigned bool,
	options LogoutValidationOptions,
) error {
	if err := validateLogoutEnvelope(ctx, response.ID, response.Version, response.IssueInstant,
		response.Destination, response.Issuer, response.XML, response.element, bindingSigned, options); err != nil {
		return err
	}
	if response.InResponseTo == "" {
		return newError("SAML_LOGOUT_IN_RESPONSE_TO_MISSING", "SAML LogoutResponse is missing InResponseTo")
	}
	if response.StatusCode == "" {
		return newError("SAML_LOGOUT_STATUS_MISSING", "SAML LogoutResponse is missing StatusCode")
	}
	return nil
}

func parseLogoutRoot(xmlData []byte, maxBytes int, tag string) (*etree.Document, *etree.Element, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseSize
	}
	document, err := parseXML(xmlData, maxBytes)
	if err != nil {
		return nil, nil, err
	}
	root := document.Root()
	if root.Tag != tag || !namespaceMatches(root, ProtocolNamespace) {
		return nil, nil, newError(
			"SAML_LOGOUT_ROOT_INVALID",
			fmt.Sprintf("SAML document root must be %s", tag),
		)
	}
	if err := validateUniqueIDs(root); err != nil {
		return nil, nil, err
	}
	return document, root, nil
}

func validateLogoutEnvelope(
	ctx context.Context,
	id, version, issueInstant, destination, issuer string,
	xmlData []byte,
	element *etree.Element,
	bindingSigned bool,
	options LogoutValidationOptions,
) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if id == "" {
		return newError("SAML_LOGOUT_ID_MISSING", "SAML logout message is missing ID")
	}
	if version != "2.0" {
		return newError("SAML_LOGOUT_VERSION_INVALID", "SAML logout message Version must be 2.0")
	}
	if issuer == "" {
		return newError("SAML_ISSUER_MISSING", "SAML logout message is missing Issuer")
	}
	if options.ExpectedIssuer != "" && issuer != options.ExpectedIssuer {
		return newError("SAML_ISSUER_MISMATCH", "SAML issuer does not match the configured Identity Provider")
	}
	if destination == "" || options.ExpectedDestination != "" && destination != options.ExpectedDestination {
		return newError("SAML_DESTINATION_MISMATCH", "SAML logout Destination does not match this Service Provider")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, issueInstant)
	if err != nil {
		return newError("SAML_ISSUE_INSTANT_INVALID", "SAML logout message has an invalid IssueInstant", err)
	}
	now := time.Now().UTC()
	if options.Now != nil {
		now = options.Now().UTC()
	}
	skew := options.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	if issuedAt.Before(now.Add(-skew)) || issuedAt.After(now.Add(skew)) {
		return newError("SAML_ISSUE_INSTANT_INVALID", "SAML logout message IssueInstant is outside the allowed clock skew")
	}
	if err := ValidateResponseAlgorithms("", xmlData, options.Algorithms); err != nil {
		return err
	}
	xmlSigned, err := verifyProtocolElementSignature(element, options.Certificates, options.Algorithms)
	if err != nil {
		return err
	}
	if options.RequireSignature && !bindingSigned && !xmlSigned {
		return newError("SAML_SIGNATURE_MISSING", "SAML logout message must be signed")
	}
	return nil
}

func logoutMessageID(configured string, generator func() (string, error)) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if generator == nil {
		generator = generateRequestID
	}
	id, err := generator()
	if err != nil {
		return "", newError("SAML_LOGOUT_ID_FAILED", "Failed to generate SAML logout message ID", err)
	}
	if id == "" {
		return "", newError("SAML_LOGOUT_ID_FAILED", "Generated SAML logout message ID is empty")
	}
	return id, nil
}

func compactLogoutValues(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func publicKeys(certificates []*x509.Certificate) []crypto.PublicKey {
	keys := make([]crypto.PublicKey, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate != nil {
			keys = append(keys, certificate.PublicKey)
		}
	}
	return keys
}
