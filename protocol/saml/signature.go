package saml

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SignatureRequirement controls which XML elements must carry a valid
// enveloped signature. The zero value requires either the Response or its
// Assertion to be signed, matching common SAML interoperability behavior.
// Every signature that is present is always verified, even when it is not
// required by this setting.
type SignatureRequirement string

const (
	SignatureAny       SignatureRequirement = "any"
	SignatureAssertion SignatureRequirement = "assertion"
	SignatureResponse  SignatureRequirement = "response"
	SignatureBoth      SignatureRequirement = "both"
	SignatureNone      SignatureRequirement = "none"
)

// SignatureVerificationOptions configures XMLDSIG validation. Configured
// certificates are trust anchors. Certificate validity dates are ignored by
// default for conformance with the reference implementation's configured-certificate trust model;
// set CheckCertificateValidity to enforce them.
type SignatureVerificationOptions struct {
	Certificates             []*x509.Certificate
	Requirement              SignatureRequirement
	Algorithms               AlgorithmValidationOptions
	CheckCertificateValidity bool
	Now                      func() time.Time
}

// SignatureVerificationResult reports which protected elements were signed.
type SignatureVerificationResult struct {
	ResponseSigned              bool
	AssertionSigned             bool
	ResponseSignatureAlgorithm  string
	AssertionSignatureAlgorithm string
}

type xmlSignatureInfo struct {
	present            bool
	signatureAlgorithm string
}

// VerifyResponseSignatures validates all direct Response and Assertion
// signatures and then enforces the requested placement policy.
func VerifyResponseSignatures(
	response Response,
	options SignatureVerificationOptions,
) (SignatureVerificationResult, error) {
	var result SignatureVerificationResult
	var responseInfo xmlSignatureInfo
	var err error

	responseElement := response.signatureElement
	if responseElement == nil {
		responseElement = response.element
	}
	if responseElement != nil && responseElement.Tag == "Response" {
		responseInfo, err = inspectDirectSignature(responseElement, options.Algorithms)
		if err != nil {
			return result, err
		}
	}
	assertionInfo, err := inspectDirectSignature(response.Assertion.element, options.Algorithms)
	if err != nil {
		return result, err
	}

	result.ResponseSigned = responseInfo.present
	result.AssertionSigned = assertionInfo.present
	result.ResponseSignatureAlgorithm = responseInfo.signatureAlgorithm
	result.AssertionSignatureAlgorithm = assertionInfo.signatureAlgorithm

	if err := enforceSignatureRequirement(result, options.Requirement); err != nil {
		return SignatureVerificationResult{}, err
	}
	if !result.ResponseSigned && !result.AssertionSigned {
		return result, nil
	}
	certificates := nonNilCertificates(options.Certificates)
	if len(certificates) == 0 {
		return SignatureVerificationResult{}, newError(
			"SAML_SIGNING_CERTIFICATE_MISSING",
			"No trusted SAML signing certificate is configured",
		)
	}
	if result.ResponseSigned {
		if err := verifyElementSignature(responseElement, certificates, options); err != nil {
			return SignatureVerificationResult{}, err
		}
	}
	if result.AssertionSigned {
		if err := verifyElementSignature(response.Assertion.element, certificates, options); err != nil {
			return SignatureVerificationResult{}, err
		}
	}
	return result, nil
}

func inspectDirectSignature(
	element *etree.Element,
	algorithmOptions AlgorithmValidationOptions,
) (xmlSignatureInfo, error) {
	if element == nil {
		return xmlSignatureInfo{}, nil
	}
	signatures := directXMLDSigChildren(element, "Signature")
	if len(signatures) == 0 {
		return xmlSignatureInfo{}, nil
	}
	if len(signatures) != 1 {
		return xmlSignatureInfo{}, newError(
			"SAML_SIGNATURE_INVALID",
			"SAML element must contain at most one direct XML signature",
		)
	}
	signature := signatures[0]
	signedInfoChildren := directXMLDSigChildren(signature, "SignedInfo")
	if len(signedInfoChildren) != 1 {
		return xmlSignatureInfo{}, newError(
			"SAML_SIGNATURE_INVALID",
			"SAML XML signature has an invalid SignedInfo structure",
		)
	}
	signedInfo := signedInfoChildren[0]
	signatureMethods := directXMLDSigChildren(signedInfo, "SignatureMethod")
	if len(signatureMethods) != 1 {
		return xmlSignatureInfo{}, newError(
			"SAML_SIGNATURE_ALGORITHM_MISSING",
			"SAML XML signature is missing SignatureMethod",
		)
	}
	signatureAlgorithm := signatureMethods[0].SelectAttrValue("Algorithm", "")
	if signatureAlgorithm == "" {
		return xmlSignatureInfo{}, newError(
			"SAML_SIGNATURE_ALGORITHM_MISSING",
			"SAML XML signature is missing SignatureMethod",
		)
	}
	if err := ValidateSignatureAlgorithm(signatureAlgorithm, algorithmOptions); err != nil {
		return xmlSignatureInfo{}, err
	}

	references := directXMLDSigChildren(signedInfo, "Reference")
	if len(references) != 1 {
		return xmlSignatureInfo{}, newError(
			"SAML_SIGNATURE_INVALID",
			"SAML XML signature must contain exactly one Reference",
		)
	}
	elementID := element.SelectAttrValue("ID", "")
	if elementID == "" {
		return xmlSignatureInfo{}, newError(
			"SAML_SIGNATURE_INVALID",
			"Signed SAML element is missing ID",
		)
	}
	for _, candidate := range descendantsByTag(element, "Signature") {
		if candidate == signature || candidate.NamespaceURI() != XMLDSigNamespace {
			continue
		}
		if signatureReferencesElement(candidate, elementID) {
			return xmlSignatureInfo{}, newError(
				"SAML_SIGNATURE_REFERENCE_INVALID",
				"Multiple SAML XML signatures reference the same signed element",
			)
		}
	}
	if references[0].SelectAttrValue("URI", "") != "#"+elementID {
		return xmlSignatureInfo{}, newError(
			"SAML_SIGNATURE_REFERENCE_INVALID",
			"SAML XML signature does not reference the signed element",
		)
	}
	digestMethods := directXMLDSigChildren(references[0], "DigestMethod")
	if len(digestMethods) != 1 {
		return xmlSignatureInfo{}, newError(
			"SAML_DIGEST_ALGORITHM_MISSING",
			"SAML digest algorithm is missing",
		)
	}
	digestAlgorithm := digestMethods[0].SelectAttrValue("Algorithm", "")
	if err := ValidateDigestAlgorithm(digestAlgorithm, algorithmOptions); err != nil {
		return xmlSignatureInfo{}, err
	}
	return xmlSignatureInfo{
		present:            true,
		signatureAlgorithm: signatureAlgorithm,
	}, nil
}

func signatureReferencesElement(signature *etree.Element, elementID string) bool {
	for _, signedInfo := range directXMLDSigChildren(signature, "SignedInfo") {
		for _, reference := range directXMLDSigChildren(signedInfo, "Reference") {
			if reference.SelectAttrValue("URI", "") == "#"+elementID {
				return true
			}
		}
	}
	return false
}

func directXMLDSigChildren(parent *etree.Element, tag string) []*etree.Element {
	if parent == nil {
		return nil
	}
	var children []*etree.Element
	for _, child := range parent.ChildElements() {
		if child.Tag == tag && child.NamespaceURI() == XMLDSigNamespace {
			children = append(children, child)
		}
	}
	return children
}

func enforceSignatureRequirement(
	result SignatureVerificationResult,
	requirement SignatureRequirement,
) error {
	if requirement == "" {
		requirement = SignatureAny
	}
	valid := false
	switch requirement {
	case SignatureAny:
		valid = result.ResponseSigned || result.AssertionSigned
	case SignatureAssertion:
		valid = result.AssertionSigned
	case SignatureResponse:
		valid = result.ResponseSigned
	case SignatureBoth:
		valid = result.ResponseSigned && result.AssertionSigned
	case SignatureNone:
		return nil
	default:
		return newError(
			"SAML_SIGNATURE_POLICY_INVALID",
			fmt.Sprintf("Invalid SAML signature requirement: %s", requirement),
		)
	}
	if !valid {
		return newError(
			"SAML_SIGNATURE_MISSING",
			"SAML response does not satisfy the required signature placement",
		)
	}
	return nil
}

func verifyElementSignature(
	element *etree.Element,
	certificates []*x509.Certificate,
	options SignatureVerificationOptions,
) error {
	var lastError error
	for _, certificate := range certificates {
		store := &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{certificate},
		}
		validationContext := dsig.NewDefaultValidationContext(store)
		if options.CheckCertificateValidity {
			if options.Now != nil {
				validationContext.Clock = dsig.NewFakeClockAt(options.Now())
			}
		} else {
			validationContext.Clock = dsig.NewFakeClockAt(certificateTrustTime(certificate))
		}
		if _, err := validationContext.Validate(element); err == nil {
			return nil
		} else {
			lastError = err
		}
	}
	return newError(
		"SAML_SIGNATURE_INVALID",
		"Invalid SAML XML signature",
		lastError,
	)
}

func certificateTrustTime(certificate *x509.Certificate) time.Time {
	duration := certificate.NotAfter.Sub(certificate.NotBefore)
	if duration <= 0 {
		return certificate.NotBefore
	}
	return certificate.NotBefore.Add(duration / 2)
}

func nonNilCertificates(certificates []*x509.Certificate) []*x509.Certificate {
	result := make([]*x509.Certificate, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate != nil {
			result = append(result, certificate)
		}
	}
	return result
}

func verifyProtocolElementSignature(
	element *etree.Element,
	certificates []*x509.Certificate,
	algorithms AlgorithmValidationOptions,
) (bool, error) {
	info, err := inspectDirectSignature(element, algorithms)
	if err != nil || !info.present {
		return false, err
	}
	trusted := nonNilCertificates(certificates)
	if len(trusted) == 0 {
		return false, newError(
			"SAML_SIGNING_CERTIFICATE_MISSING",
			"No trusted SAML signing certificate is configured",
		)
	}
	if err := verifyElementSignature(element, trusted, SignatureVerificationOptions{
		Certificates: trusted, Algorithms: algorithms,
	}); err != nil {
		return false, err
	}
	return true, nil
}
