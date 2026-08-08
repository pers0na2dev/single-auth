package saml

import "time"

const (
	ProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	MetadataNamespace  = "urn:oasis:names:tc:SAML:2.0:metadata"
	XMLDSigNamespace   = "http://www.w3.org/2000/09/xmldsig#"
	XMLEncNamespace    = "http://www.w3.org/2001/04/xmlenc#"
)

const (
	HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPostBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BearerConfirmation  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

const (
	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

const (
	AuthnRequestKeyPrefix  = "saml-authn-request:"
	UsedAssertionKeyPrefix = "saml-used-assertion:"
)

const (
	DefaultAuthnRequestTTL = 5 * time.Minute
	DefaultAssertionTTL    = 15 * time.Minute
	DefaultClockSkew       = 5 * time.Minute
	DefaultMaxResponseSize = 256 * 1024
	DefaultMaxMetadataSize = 100 * 1024
)

const (
	SignatureRSASHA1     = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SignatureRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SignatureRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SignatureECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SignatureECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SignatureECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

const (
	DigestSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

const (
	KeyEncryptionRSA15         = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	KeyEncryptionRSAOAEP       = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyEncryptionRSAOAEPSHA256 = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

const (
	DataEncryptionTripleDESCBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	DataEncryptionAES128CBC    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	DataEncryptionAES192CBC    = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	DataEncryptionAES256CBC    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	DataEncryptionAES128GCM    = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	DataEncryptionAES192GCM    = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	DataEncryptionAES256GCM    = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
)
