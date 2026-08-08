package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	dsig "github.com/russellhaering/goxmldsig"
)

// SignXMLMessage adds one enveloped XMLDSIG signature to a SAML protocol
// message. The signature is inserted after Issuer, as required by the SAML
// protocol schemas for AuthnRequest, LogoutRequest, and LogoutResponse.
func SignXMLMessage(xmlData []byte, options XMLSigningOptions) ([]byte, error) {
	if options.Signer == nil {
		return nil, newError(
			"SAML_SIGNING_KEY_MISSING",
			"SAML message signing key is not configured",
		)
	}
	document, err := parseXML(xmlData, DefaultMaxResponseSize)
	if err != nil {
		return nil, newError("SAML_MESSAGE_INVALID", "SAML message XML could not be parsed", err)
	}
	root := document.Root()
	if root.SelectAttrValue("ID", "") == "" {
		return nil, newError("SAML_MESSAGE_INVALID", "SAML message is missing ID")
	}
	if len(directXMLDSigChildren(root, "Signature")) != 0 {
		return nil, newError("SAML_SIGNATURE_INVALID", "SAML message is already signed")
	}
	if err := validateUniqueIDs(root); err != nil {
		return nil, err
	}
	algorithm := normalizeSignatureAlgorithm(options.SignatureAlgorithm)
	if algorithm == "" {
		algorithm, err = defaultSignatureAlgorithm(options.Signer)
		if err != nil {
			return nil, err
		}
	}
	if err := ValidateSignatureAlgorithm(algorithm, options.Algorithms); err != nil {
		return nil, err
	}
	certificateChain := make([][]byte, 0, len(options.Certificates))
	for _, certificate := range options.Certificates {
		if certificate != nil {
			certificateChain = append(certificateChain, certificate.Raw)
		}
	}
	signingContext, err := dsig.NewSigningContext(options.Signer, certificateChain)
	if err != nil {
		return nil, newError("SAML_SIGNING_KEY_INVALID", "Invalid SAML message signing key", err)
	}
	signingContext.Prefix = "ds"
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signingContext.SetSignatureMethod(algorithm); err != nil {
		return nil, newError("SAML_SIGNING_KEY_INVALID", "SAML signature algorithm is incompatible with the signing key", err)
	}
	if err := ValidateDigestAlgorithm(signingContext.GetDigestAlgorithmIdentifier(), options.Algorithms); err != nil {
		return nil, err
	}
	signature, err := signingContext.ConstructSignature(root, true)
	if err != nil {
		return nil, newError("SAML_SIGNATURE_FAILED", "Failed to sign SAML message", err)
	}
	if len(certificateChain) == 0 {
		if keyInfo := firstDirectChild(signature, "KeyInfo", XMLDSigNamespace); keyInfo != nil {
			signature.RemoveChild(keyInfo)
		}
	}
	insertIndex := 0
	if issuer := firstDirectChild(root, "Issuer", AssertionNamespace); issuer != nil {
		insertIndex = issuer.Index() + 1
	}
	root.InsertChildAt(insertIndex, signature)
	result, err := document.WriteToBytes()
	if err != nil {
		return nil, newError("SAML_SIGNATURE_FAILED", "Failed to serialize signed SAML message", err)
	}
	return result, nil
}

// XMLSigningOptions configures an enveloped AuthnRequest signature for the
// HTTP-POST binding. Redirect binding must instead be signed with
// BuildRedirectURL because its signature covers the encoded query string.
type XMLSigningOptions struct {
	Signer             crypto.Signer
	Certificates       []*x509.Certificate
	SignatureAlgorithm string
	Algorithms         AlgorithmValidationOptions
}

// SignAuthnRequest adds an enveloped XMLDSIG Signature immediately after the
// Issuer, which is the schema-defined position for a SAML AuthnRequest.
func SignAuthnRequest(
	request AuthnRequest,
	options XMLSigningOptions,
) (AuthnRequest, error) {
	if options.Signer == nil {
		return AuthnRequest{}, newError(
			"SAML_SIGNING_KEY_MISSING",
			"SAML AuthnRequest signing key is not configured",
		)
	}
	document, err := parseXML(request.XML, DefaultMaxResponseSize)
	if err != nil {
		return AuthnRequest{}, newError(
			"SAML_AUTHN_REQUEST_INVALID",
			"SAML AuthnRequest XML could not be parsed",
			err,
		)
	}
	root := document.Root()
	if root.Tag != "AuthnRequest" || !namespaceMatches(root, ProtocolNamespace) {
		return AuthnRequest{}, newError(
			"SAML_AUTHN_REQUEST_INVALID",
			"SAML AuthnRequest XML has an invalid root",
		)
	}
	if root.SelectAttrValue("ID", "") == "" {
		return AuthnRequest{}, newError(
			"SAML_AUTHN_REQUEST_INVALID",
			"SAML AuthnRequest is missing ID",
		)
	}
	if len(directXMLDSigChildren(root, "Signature")) != 0 {
		return AuthnRequest{}, newError(
			"SAML_SIGNATURE_INVALID",
			"SAML AuthnRequest is already signed",
		)
	}
	if err := validateUniqueIDs(root); err != nil {
		return AuthnRequest{}, err
	}

	algorithm := normalizeSignatureAlgorithm(options.SignatureAlgorithm)
	if algorithm == "" {
		algorithm, err = defaultSignatureAlgorithm(options.Signer)
		if err != nil {
			return AuthnRequest{}, err
		}
	}
	if err := ValidateSignatureAlgorithm(algorithm, options.Algorithms); err != nil {
		return AuthnRequest{}, err
	}
	certificateChain := make([][]byte, 0, len(options.Certificates))
	for _, certificate := range options.Certificates {
		if certificate != nil {
			certificateChain = append(certificateChain, certificate.Raw)
		}
	}
	signingContext, err := dsig.NewSigningContext(options.Signer, certificateChain)
	if err != nil {
		return AuthnRequest{}, newError(
			"SAML_SIGNING_KEY_INVALID",
			"Invalid SAML AuthnRequest signing key",
			err,
		)
	}
	signingContext.Prefix = "ds"
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signingContext.SetSignatureMethod(algorithm); err != nil {
		return AuthnRequest{}, newError(
			"SAML_SIGNING_KEY_INVALID",
			"SAML signature algorithm is incompatible with the signing key",
			err,
		)
	}
	if err := ValidateDigestAlgorithm(
		signingContext.GetDigestAlgorithmIdentifier(),
		options.Algorithms,
	); err != nil {
		return AuthnRequest{}, err
	}
	signature, err := signingContext.ConstructSignature(root, true)
	if err != nil {
		return AuthnRequest{}, newError(
			"SAML_SIGNATURE_FAILED",
			"Failed to sign SAML AuthnRequest",
			err,
		)
	}
	if len(certificateChain) == 0 {
		if keyInfo := firstDirectChild(signature, "KeyInfo", XMLDSigNamespace); keyInfo != nil {
			signature.RemoveChild(keyInfo)
		}
	}
	insertIndex := 0
	if issuer := firstDirectChild(root, "Issuer", AssertionNamespace); issuer != nil {
		insertIndex = issuer.Index() + 1
	}
	root.InsertChildAt(insertIndex, signature)
	signedXML, err := document.WriteToBytes()
	if err != nil {
		return AuthnRequest{}, newError(
			"SAML_SIGNATURE_FAILED",
			"Failed to serialize signed SAML AuthnRequest",
			err,
		)
	}
	request.XML = signedXML
	return request, nil
}

func defaultSignatureAlgorithm(signer crypto.Signer) (string, error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		return SignatureRSASHA256, nil
	case *ecdsa.PublicKey:
		return SignatureECDSASHA256, nil
	default:
		return "", newError(
			"SAML_SIGNING_KEY_INVALID",
			"Unsupported SAML signing key type",
		)
	}
}
