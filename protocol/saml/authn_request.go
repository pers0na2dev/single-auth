package saml

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"time"
)

// AuthnRequestOptions configures an SP-initiated AuthnRequest.
type AuthnRequestOptions struct {
	ID                          string
	Destination                 string
	AssertionConsumerServiceURL string
	Issuer                      string
	IssueInstant                time.Time
	ProtocolBinding             string
	NameIDPolicyFormat          string
	AllowCreate                 *bool
	ForceAuthn                  bool
	IsPassive                   bool
	IDGenerator                 func() (string, error)
}

// AuthnRequest is the generated XML and correlation ID.
type AuthnRequest struct {
	ID           string
	IssueInstant time.Time
	XML          []byte
}

// NewAuthnRequest creates an unsigned AuthnRequest. Redirect-binding signing
// is applied by BuildRedirectURL because the signature covers the encoded
// query rather than the XML document.
func NewAuthnRequest(options AuthnRequestOptions) (AuthnRequest, error) {
	if options.Destination == "" || options.Issuer == "" {
		return AuthnRequest{}, newError(
			"SAML_AUTHN_REQUEST_INVALID",
			"SAML AuthnRequest requires Destination and Issuer",
		)
	}
	id := options.ID
	if id == "" {
		generator := options.IDGenerator
		if generator == nil {
			generator = generateRequestID
		}
		var err error
		id, err = generator()
		if err != nil {
			return AuthnRequest{}, newError(
				"SAML_AUTHN_REQUEST_ID_FAILED",
				"Failed to generate SAML AuthnRequest ID",
				err,
			)
		}
	}
	issuedAt := options.IssueInstant.UTC()
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	binding := options.ProtocolBinding
	if binding == "" {
		binding = HTTPPostBinding
	}

	var document bytes.Buffer
	document.WriteString(`<samlp:AuthnRequest xmlns:samlp="`)
	writeXMLEscaped(&document, ProtocolNamespace)
	document.WriteString(`" xmlns:saml="`)
	writeXMLEscaped(&document, AssertionNamespace)
	document.WriteString(`" ID="`)
	writeXMLEscaped(&document, id)
	document.WriteString(`" Version="2.0" IssueInstant="`)
	writeXMLEscaped(&document, issuedAt.Format(time.RFC3339Nano))
	document.WriteString(`" Destination="`)
	writeXMLEscaped(&document, options.Destination)
	document.WriteString(`" ProtocolBinding="`)
	writeXMLEscaped(&document, binding)
	if options.AssertionConsumerServiceURL != "" {
		document.WriteString(`" AssertionConsumerServiceURL="`)
		writeXMLEscaped(&document, options.AssertionConsumerServiceURL)
	}
	if options.ForceAuthn {
		document.WriteString(`" ForceAuthn="true`)
	}
	if options.IsPassive {
		document.WriteString(`" IsPassive="true`)
	}
	document.WriteString(`"><saml:Issuer>`)
	writeXMLText(&document, options.Issuer)
	document.WriteString(`</saml:Issuer>`)
	if options.NameIDPolicyFormat != "" || options.AllowCreate != nil {
		document.WriteString(`<samlp:NameIDPolicy`)
		if options.NameIDPolicyFormat != "" {
			document.WriteString(` Format="`)
			writeXMLEscaped(&document, options.NameIDPolicyFormat)
			document.WriteString(`"`)
		}
		if options.AllowCreate != nil {
			document.WriteString(fmt.Sprintf(` AllowCreate="%t"`, *options.AllowCreate))
		}
		document.WriteString(` />`)
	}
	document.WriteString(`</samlp:AuthnRequest>`)
	return AuthnRequest{ID: id, IssueInstant: issuedAt, XML: document.Bytes()}, nil
}

func generateRequestID() (string, error) {
	buffer := make([]byte, 20)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(buffer), nil
}

func writeXMLEscaped(buffer *bytes.Buffer, value string) {
	_ = xml.EscapeText(buffer, []byte(value))
}

func writeXMLText(buffer *bytes.Buffer, value string) {
	_ = xml.EscapeText(buffer, []byte(value))
}
