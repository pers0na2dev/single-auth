---
title: "github.com/pers0na2dev/single-auth/protocol/saml"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/protocol/saml.

- Import path: `github.com/pers0na2dev/single-auth/protocol/saml`
- Package name: `saml`

Package saml implements transport-independent SAML 2.0 protocol primitives
and validation used by single-auth.

The package deliberately does not register authentication routes. It owns
wire bindings, AuthnRequest construction, metadata parsing, XML signature
verification, assertion validation, request correlation, and replay gates.

## Constants

```go
const (
	ProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	MetadataNamespace  = "urn:oasis:names:tc:SAML:2.0:metadata"
	XMLDSigNamespace   = "http://www.w3.org/2000/09/xmldsig#"
	XMLEncNamespace    = "http://www.w3.org/2001/04/xmlenc#"
)
```

```go
const (
	HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPostBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BearerConfirmation  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)
```

```go
const (
	AuthnRequestKeyPrefix  = "saml-authn-request:"
	UsedAssertionKeyPrefix = "saml-used-assertion:"
)
```

```go
const (
	DefaultAuthnRequestTTL = 5 * time.Minute
	DefaultAssertionTTL    = 15 * time.Minute
	DefaultClockSkew       = 5 * time.Minute
	DefaultMaxResponseSize = 256 * 1024
	DefaultMaxMetadataSize = 100 * 1024
)
```

```go
const (
	SignatureRSASHA1     = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SignatureRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SignatureRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SignatureECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SignatureECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SignatureECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)
```

```go
const (
	DigestSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)
```

```go
const (
	KeyEncryptionRSA15         = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	KeyEncryptionRSAOAEP       = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyEncryptionRSAOAEPSHA256 = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)
```

```go
const (
	DataEncryptionTripleDESCBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	DataEncryptionAES128CBC    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	DataEncryptionAES192CBC    = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	DataEncryptionAES256CBC    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	DataEncryptionAES128GCM    = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	DataEncryptionAES192GCM    = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	DataEncryptionAES256GCM    = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
)
```

```go
const (
	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
)
```

## Functions

### `BuildPOSTForm`

BuildPOSTForm returns the reference implementation's auto-submitting HTTP-POST binding form.

```go
func BuildPOSTForm(
	action string,
	parameter MessageParameter,
	encodedValue string,
	relayState string,
) (string, error)
```

### `BuildRedirectURL`

BuildRedirectURL creates a SAML HTTP-Redirect URL and optionally signs its
exact binding query string. Existing endpoint query parameters are retained
but are not part of the SAML signature input.

```go
func BuildRedirectURL(
	ctx context.Context,
	endpoint string,
	parameter MessageParameter,
	xmlData []byte,
	relayState string,
	signer crypto.Signer,
	signatureAlgorithm string,
) (string, error)
```

### `DecodePOSTMessage`

DecodePOSTMessage removes line-wrapping whitespace and decodes one base64
SAMLRequest or SAMLResponse value.

```go
func DecodePOSTMessage(encoded string, maxDecodedBytes int) ([]byte, error)
```

### `DecodeRedirectMessage`

DecodeRedirectMessage inflates a base64 Redirect-binding payload with a
strict decompressed size bound.

```go
func DecodeRedirectMessage(encoded string, maxDecodedBytes int) ([]byte, error)
```

### `DecryptResponseAssertion`

DecryptResponseAssertion replaces the single direct EncryptedAssertion in a
SAML Response with its plaintext Assertion. It implements the algorithms
accepted by Samlify 2.13.1 / @authenio/xml-encryption 2.0.2, the runtime used
by the reference implementation 1.6.26.

```go
func DecryptResponseAssertion(
	xmlData []byte,
	privateKey *rsa.PrivateKey,
	algorithms AlgorithmValidationOptions,
	maxBytes int,
) ([]byte, error)
```

### `EncodePOSTMessage`

EncodePOSTMessage encodes XML for the HTTP-POST binding.

```go
func EncodePOSTMessage(xmlData []byte) string
```

### `EncodeRedirectMessage`

EncodeRedirectMessage applies raw DEFLATE and base64 as required by SAML
Bindings section 3.4.

```go
func EncodeRedirectMessage(xmlData []byte) (string, error)
```

### `HasEncryptedAssertion`

HasEncryptedAssertion reports whether XML contains an EncryptedAssertion.

```go
func HasEncryptedAssertion(xmlData []byte) bool
```

### `IsErrorCode`

IsErrorCode reports whether err contains a SAML Error with code.

```go
func IsErrorCode(err error, code string) bool
```

### `ParseCertificatesPEM`

ParseCertificatesPEM parses one or more trusted signing certificates. Raw
base64 DER is also accepted for compatibility with SAML configuration UIs.

```go
func ParseCertificatesPEM(value []byte) ([]*x509.Certificate, error)
```

### `ParseDecryptionPrivateKeyPEM`

ParseDecryptionPrivateKeyPEM parses the RSA private key used to unwrap an
XML Encryption content key. Samlify's public encrypted-assertion contract is
RSA-only even though SAML signatures may also use ECDSA keys.

```go
func ParseDecryptionPrivateKeyPEM(value []byte, password string) (*rsa.PrivateKey, error)
```

### `ParsePrivateKeyPEM`

ParsePrivateKeyPEM parses RSA or ECDSA PKCS#1, SEC1, PKCS#8, legacy
encrypted PEM, and encrypted PKCS#8 keys used by SAML SP configurations.

```go
func ParsePrivateKeyPEM(value []byte, password string) (crypto.Signer, error)
```

### `PostAssertionConsumerServiceURLs`

PostAssertionConsumerServiceURLs extracts unique HTTP-POST ACS locations,
matching the reference implementation's metadata helper.

```go
func PostAssertionConsumerServiceURLs(xmlData []byte) []string
```

### `PublicKeys`

PublicKeys returns public keys from parsed trusted certificates.

```go
func PublicKeys(certificates []*x509.Certificate) []crypto.PublicKey
```

### `SignXMLMessage`

SignXMLMessage adds one enveloped XMLDSIG signature to a SAML protocol
message. The signature is inserted after Issuer, as required by the SAML
protocol schemas for AuthnRequest, LogoutRequest, and LogoutResponse.

```go
func SignXMLMessage(xmlData []byte, options XMLSigningOptions) ([]byte, error)
```

### `ValidateConfigAlgorithms`

ValidateConfigAlgorithms accepts the reference implementation's short algorithm names and
applies its exact allow-list/deprecation semantics.

```go
func ValidateConfigAlgorithms(
	config ConfigAlgorithms,
	options AlgorithmValidationOptions,
) error
```

### `ValidateDigestAlgorithm`

ValidateDigestAlgorithm validates one XMLDSIG DigestMethod URI.

```go
func ValidateDigestAlgorithm(
	algorithm string,
	options AlgorithmValidationOptions,
) error
```

### `ValidateEncryptionAlgorithms`

ValidateEncryptionAlgorithms applies the reference implementation's allow-list and legacy
algorithm policy to the exact key/data algorithm pair selected for
decryption. Keeping this separate from the loose response scanner prevents
an unrelated EncryptedKey node from bypassing a configured allow-list.

```go
func ValidateEncryptionAlgorithms(
	keyAlgorithm string,
	dataAlgorithm string,
	options AlgorithmValidationOptions,
) error
```

### `ValidateLogoutRequest`

ValidateLogoutRequest verifies a parsed request after its transport binding
has been decoded. A valid Redirect signature satisfies RequireSignature.

```go
func ValidateLogoutRequest(
	ctx context.Context,
	request LogoutRequest,
	bindingSigned bool,
	options LogoutValidationOptions,
) error
```

### `ValidateLogoutResponse`

ValidateLogoutResponse verifies a parsed response after its transport
binding has been decoded.

```go
func ValidateLogoutResponse(
	ctx context.Context,
	response LogoutResponse,
	bindingSigned bool,
	options LogoutValidationOptions,
) error
```

### `ValidateResponseAlgorithms`

ValidateResponseAlgorithms applies the reference implementation's response algorithm policy
and inspects encrypted assertions for deprecated key/data algorithms.

```go
func ValidateResponseAlgorithms(
	signatureAlgorithm string,
	xmlData []byte,
	options AlgorithmValidationOptions,
) error
```

### `ValidateResponseBinding`

ValidateResponseBinding enforces the reference implementation's exact audience-group and
bearer recipient semantics.

```go
func ValidateResponseBinding(
	response Response,
	options ResponseBindingValidationOptions,
) error
```

### `ValidateResponseBindingXML`

ValidateResponseBindingXML is the direct Go counterpart of the reference implementation's
validateSAMLResponseBinding. It parses only the binding-relevant fields and
returns the same HTTP-facing API errors as the upstream helper.

```go
func ValidateResponseBindingXML(
	xmlData []byte,
	options ResponseBindingValidationOptions,
) error
```

### `ValidateSignatureAlgorithm`

ValidateSignatureAlgorithm validates one XMLDSIG or Redirect-binding
SignatureMethod URI.

```go
func ValidateSignatureAlgorithm(
	algorithm string,
	options AlgorithmValidationOptions,
) error
```

### `ValidateSingleAssertion`

ValidateSingleAssertion applies the reference implementation's structural assertion guard to
a base64 HTTP-POST binding value and returns the decoded XML.

```go
func ValidateSingleAssertion(encoded string) ([]byte, error)
```

### `ValidateTimestamp`

ValidateTimestamp validates NotBefore and NotOnOrAfter with the reference implementation's
inclusive clock-skew boundaries.

```go
func ValidateTimestamp(conditions *Conditions, options TimestampValidationOptions) error
```

## Types

### `APIError`

APIError is the HTTP-facing validation error shape used by the reference implementation SSO
route helpers. Cause preserves the stable SAML error code for callers that
need protocol-level classification.

```go
type APIError struct {
	Status     string
	StatusCode int
	Message    string
	Body       map[string]any
	Cause      error
}
```

## Methods on `APIError`

### `Error`

```go
func (err *APIError) Error() string
```

### `Unwrap`

```go
func (err *APIError) Unwrap() error
```

### `AlgorithmValidationOptions`

AlgorithmValidationOptions mirrors the reference implementation's allow-list and deprecated
algorithm controls. Warn receives the complete security warning.

```go
type AlgorithmValidationOptions struct {
	OnDeprecated                    DeprecatedAlgorithmBehavior
	AllowedSignatureAlgorithms      []string
	AllowedDigestAlgorithms         []string
	AllowedKeyEncryptionAlgorithms  []string
	AllowedDataEncryptionAlgorithms []string
	Warn                            func(string)
}
```

### `Assertion`

Assertion is the security-relevant data extracted from the single direct
assertion in a SAML response.

```go
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
	// contains filtered or unexported fields
}
```

### `AssertionCounts`

AssertionCounts reports plain and encrypted assertion elements anywhere in
the document. Counting the complete tree prevents common XML signature
wrapping layouts from smuggling an additional assertion into Extensions or
an arbitrary wrapper.

```go
type AssertionCounts struct {
	Assertions          int
	EncryptedAssertions int
	Total               int
}
```

## Constructors and functions for `AssertionCounts`

### `CountAssertions`

CountAssertions parses XML and counts every Assertion and
EncryptedAssertion local name, matching the reference implementation's namespace-insensitive
structural guard.

```go
func CountAssertions(xmlData []byte) (AssertionCounts, error)
```

### `AssertionDecryptionOptions`

AssertionDecryptionOptions enables the encrypted-assertion path. Its
presence mirrors idpMetadata.isAssertionEncrypted=true; an encrypted
assertion is then required and is unwrapped with the SP's RSA key.

```go
type AssertionDecryptionOptions struct {
	PrivateKey *rsa.PrivateKey
}
```

### `AssertionReplayOptions`

AssertionReplayOptions configures the assertion replay reservation.

```go
type AssertionReplayOptions struct {
	ProviderID string
	Issuer     string
	ClockSkew  *time.Duration
	Store      AssertionReplayStore
	Now        func() time.Time
	Warn       func(message string, fields map[string]any)
}
```

### `AssertionReplayRecord`

AssertionReplayRecord is the atomic replay tombstone for an assertion ID.

```go
type AssertionReplayRecord struct {
	AssertionID string
	Issuer      string
	ProviderID  string
	UsedAt      time.Time
	ExpiresAt   time.Time
}
```

## Constructors and functions for `AssertionReplayRecord`

### `ReserveAssertionReplay`

ReserveAssertionReplay atomically reserves the assertion ID. A missing ID is
skipped with a warning for the reference implementation compatibility.

```go
func ReserveAssertionReplay(
	ctx context.Context,
	response Response,
	options AssertionReplayOptions,
) (AssertionReplayRecord, error)
```

### `AssertionReplayStore`

AssertionReplayStore must atomically reserve assertion IDs. It returns false
when an unexpired tombstone already exists.

```go
type AssertionReplayStore interface {
	ReserveAssertion(context.Context, AssertionReplayRecord) (bool, error)
}
```

### `AuthnRequest`

AuthnRequest is the generated XML and correlation ID.

```go
type AuthnRequest struct {
	ID           string
	IssueInstant time.Time
	XML          []byte
}
```

## Constructors and functions for `AuthnRequest`

### `NewAuthnRequest`

NewAuthnRequest creates an unsigned AuthnRequest. Redirect-binding signing
is applied by BuildRedirectURL because the signature covers the encoded
query rather than the XML document.

```go
func NewAuthnRequest(options AuthnRequestOptions) (AuthnRequest, error)
```

### `SignAuthnRequest`

SignAuthnRequest adds an enveloped XMLDSIG Signature immediately after the
Issuer, which is the schema-defined position for a SAML AuthnRequest.

```go
func SignAuthnRequest(
	request AuthnRequest,
	options XMLSigningOptions,
) (AuthnRequest, error)
```

### `AuthnRequestOptions`

AuthnRequestOptions configures an SP-initiated AuthnRequest.

```go
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
```

### `AuthnRequestRecord`

AuthnRequestRecord is the one-time correlation state created before an
SP-initiated redirect or POST.

```go
type AuthnRequestRecord struct {
	RequestID  string
	ProviderID string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}
```

## Constructors and functions for `AuthnRequestRecord`

### `RecordAuthnRequest`

RecordAuthnRequest writes a correlation record using the reference implementation's five
minute default TTL.

```go
func RecordAuthnRequest(
	ctx context.Context,
	store AuthnRequestStore,
	request AuthnRequest,
	providerID string,
	ttl time.Duration,
	now func() time.Time,
) (AuthnRequestRecord, error)
```

### `ValidateInResponseTo`

ValidateInResponseTo resolves the authenticated response correlation value
and consumes it atomically. The record is consumed even when its provider is
wrong, matching the reference implementation and preventing repeated probing.

```go
func ValidateInResponseTo(
	ctx context.Context,
	response Response,
	options InResponseToValidationOptions,
) (*AuthnRequestRecord, error)
```

### `AuthnRequestStore`

AuthnRequestStore must atomically consume request IDs. A read followed by a
delete is not a valid implementation because concurrent callbacks could both
succeed.

```go
type AuthnRequestStore interface {
	PutAuthnRequest(context.Context, AuthnRequestRecord) error
	ConsumeAuthnRequest(context.Context, string) (AuthnRequestRecord, bool, error)
}
```

### `Conditions`

Conditions are the temporal bounds extracted from an assertion.

```go
type Conditions struct {
	NotBefore    string
	NotOnOrAfter string
}
```

### `ConfigAlgorithms`

ConfigAlgorithms are the signature and digest algorithms selected for an
outgoing Service Provider configuration.

```go
type ConfigAlgorithms struct {
	SignatureAlgorithm string
	DigestAlgorithm    string
}
```

### `DeprecatedAlgorithmBehavior`

DeprecatedAlgorithmCompatibility controls compatibility with SHA-1, RSA1_5, and
3DES configurations.

```go
type DeprecatedAlgorithmBehavior string
```

## Constants associated with `DeprecatedAlgorithmBehavior`

```go
const (
	DeprecatedReject DeprecatedAlgorithmBehavior = "reject"
	DeprecatedWarn   DeprecatedAlgorithmBehavior = "warn"
	DeprecatedAllow  DeprecatedAlgorithmBehavior = "allow"
)
```

### `Endpoint`

Endpoint is one binding endpoint advertised by SAML metadata.

```go
type Endpoint struct {
	Binding          string
	Location         string
	ResponseLocation string
	Index            int
	HasIndex         bool
	IsDefault        bool
}
```

## Constructors and functions for `Endpoint`

### `EndpointForBinding`

EndpointForBinding returns the first endpoint for binding.

```go
func EndpointForBinding(endpoints []Endpoint, binding string) (Endpoint, bool)
```

### `EntityDescriptor`

EntityDescriptor is one EntityDescriptor from a metadata document.

```go
type EntityDescriptor struct {
	EntityID string
	IDP      *IDPDescriptor
	SP       *SPDescriptor
}
```

### `Error`

Error is a stable SAML validation failure. Cause is intended for server logs
and must not be copied into protocol responses.

```go
type Error struct {
	Code    string
	Message string
	Cause   error
}
```

## Methods on `Error`

### `Error`

```go
func (err *Error) Error() string
```

### `Unwrap`

```go
func (err *Error) Unwrap() error
```

### `IDPDescriptor`

IDPDescriptor contains the IdP metadata used by SSO response validation.

```go
type IDPDescriptor struct {
	WantAuthnRequestsSigned bool
	SingleSignOnServices    []Endpoint
	SingleLogoutServices    []Endpoint
	NameIDFormats           []string
	Keys                    []KeyDescriptor
}
```

## Methods on `IDPDescriptor`

### `SigningCertificates`

SigningCertificates returns IdP signing keys (use="signing" or unspecified)
with duplicates removed.

```go
func (descriptor IDPDescriptor) SigningCertificates() []*x509.Certificate
```

### `InResponseToValidationOptions`

InResponseToValidationOptions configures one-time AuthnRequest correlation.
Both validation and IdP-initiated SSO are enabled by default, as in Better
Auth. Use pointers when an explicit false value is needed.

```go
type InResponseToValidationOptions struct {
	EnableValidation   *bool
	AllowIDPInitiated  *bool
	ProviderID         string
	ExpectedRecipients []string
	Store              AuthnRequestStore
	Now                func() time.Time
}
```

### `KeyDescriptor`

KeyDescriptor is one metadata key and its intended use.

```go
type KeyDescriptor struct {
	Use          string
	Certificates []*x509.Certificate
}
```

### `LogoutRequest`

LogoutRequest is the security-relevant SAML Single Logout request envelope.

```go
type LogoutRequest struct {
	ID             string
	Version        string
	IssueInstant   string
	Destination    string
	Issuer         string
	NameID         string
	SessionIndexes []string
	XML            []byte
	// contains filtered or unexported fields
}
```

## Constructors and functions for `LogoutRequest`

### `NewLogoutRequest`

NewLogoutRequest creates an unsigned protocol request. Redirect-binding
signatures are applied by BuildRedirectURL; POST XML signatures can be
applied with SignXMLMessage.

```go
func NewLogoutRequest(options LogoutRequestOptions) (LogoutRequest, error)
```

### `ParseLogoutRequest`

ParseLogoutRequest parses a decoded LogoutRequest with strict root,
namespace, duplicate-ID, and direct-child checks.

```go
func ParseLogoutRequest(xmlData []byte, maxBytes int) (LogoutRequest, error)
```

### `LogoutRequestOptions`

LogoutRequestOptions configures an outbound SAML LogoutRequest.

```go
type LogoutRequestOptions struct {
	ID           string
	Issuer       string
	Destination  string
	NameID       string
	SessionIndex string
	IssueInstant time.Time
	IDGenerator  func() (string, error)
}
```

### `LogoutResponse`

LogoutResponse is the security-relevant SAML Single Logout response envelope.

```go
type LogoutResponse struct {
	ID           string
	Version      string
	IssueInstant string
	Destination  string
	InResponseTo string
	Issuer       string
	StatusCode   string
	XML          []byte
	// contains filtered or unexported fields
}
```

## Constructors and functions for `LogoutResponse`

### `NewLogoutResponse`

NewLogoutResponse creates an unsigned Success response unless StatusCode is
supplied explicitly.

```go
func NewLogoutResponse(options LogoutResponseOptions) (LogoutResponse, error)
```

### `ParseLogoutResponse`

ParseLogoutResponse parses a decoded LogoutResponse with strict structural
checks.

```go
func ParseLogoutResponse(xmlData []byte, maxBytes int) (LogoutResponse, error)
```

### `LogoutResponseOptions`

LogoutResponseOptions configures an outbound SAML LogoutResponse.

```go
type LogoutResponseOptions struct {
	ID           string
	Issuer       string
	Destination  string
	InResponseTo string
	StatusCode   string
	IssueInstant time.Time
	IDGenerator  func() (string, error)
}
```

### `LogoutValidationOptions`

LogoutValidationOptions applies the common SLO trust-boundary checks.

```go
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
```

### `MemoryStore`

MemoryStore is a process-local, concurrency-safe reference implementation of
both correlation stores. Distributed deployments should provide a shared
implementation with equivalent atomic consume/reserve operations.

```go
type MemoryStore struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MemoryStore`

### `NewMemoryStore`

NewMemoryStore creates an empty reference store. now may be nil.

```go
func NewMemoryStore(now func() time.Time) *MemoryStore
```

## Methods on `MemoryStore`

### `ConsumeAuthnRequest`

ConsumeAuthnRequest implements AuthnRequestStore as one mutex-protected
take operation.

```go
func (store *MemoryStore) ConsumeAuthnRequest(
	ctx context.Context,
	requestID string,
) (AuthnRequestRecord, bool, error)
```

### `PutAuthnRequest`

PutAuthnRequest implements AuthnRequestStore.

```go
func (store *MemoryStore) PutAuthnRequest(
	ctx context.Context,
	record AuthnRequestRecord,
) error
```

### `ReserveAssertion`

ReserveAssertion implements AssertionReplayStore as one mutex-protected
compare-and-insert operation.

```go
func (store *MemoryStore) ReserveAssertion(
	ctx context.Context,
	record AssertionReplayRecord,
) (bool, error)
```

### `MessageParameter`

MessageParameter identifies the SAML protocol message carried by a binding.

```go
type MessageParameter string
```

## Constants associated with `MessageParameter`

```go
const (
	SAMLRequestParameter  MessageParameter = "SAMLRequest"
	SAMLResponseParameter MessageParameter = "SAMLResponse"
)
```

### `MetadataDocument`

MetadataDocument supports both EntityDescriptor and an EntitiesDescriptor
containing multiple entities.

```go
type MetadataDocument struct {
	Entities []EntityDescriptor
}
```

## Constructors and functions for `MetadataDocument`

### `ParseMetadata`

ParseMetadata parses IdP/SP metadata with size and unsafe-XML guards.

```go
func ParseMetadata(xmlData []byte, maxBytes int) (MetadataDocument, error)
```

### `RedirectMessage`

RedirectMessage is a decoded HTTP-Redirect binding message.

```go
type RedirectMessage struct {
	Parameter  MessageParameter
	XML        []byte
	RelayState string
	SigAlg     string
	Signed     bool
}
```

## Constructors and functions for `RedirectMessage`

### `ParseRedirectBinding`

ParseRedirectBinding decodes a Redirect-binding request or response and, if
signed, verifies the signature against at least one trusted public key.

```go
func ParseRedirectBinding(
	rawQuery string,
	trustedKeys []crypto.PublicKey,
	algorithmOptions AlgorithmValidationOptions,
	maxDecodedBytes int,
) (RedirectMessage, error)
```

### `Response`

Response is the parsed protocol response and its single assertion.

```go
type Response struct {
	ID           string
	Version      string
	Issuer       string
	Destination  string
	InResponseTo string
	IssueInstant string
	StatusCode   string
	Assertion    Assertion
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Response`

### `ParseResponse`

ParseResponse parses a structurally guarded plain-text SAML response.

```go
func ParseResponse(xmlData []byte) (Response, error)
```

### `ParseResponseWithLimit`

ParseResponseWithLimit parses a response with a caller-selected decoded XML
size limit. A non-positive limit uses DefaultMaxResponseSize.

```go
func ParseResponseWithLimit(xmlData []byte, maxBytes int) (Response, error)
```

### `ResponseBindingValidationOptions`

ResponseBindingValidationOptions configures audience, bearer recipient, and
response Destination checks.

```go
type ResponseBindingValidationOptions struct {
	ExpectedAudiences  []string
	ExpectedRecipients []string
}
```

### `ResponseValidationOptions`

ResponseValidationOptions composes the protocol spike's independent
validation primitives into the order used by the reference implementation's SAML pipeline.

```go
type ResponseValidationOptions struct {
	MaxResponseSize        int
	ExpectedIssuer         string
	Signatures             SignatureVerificationOptions
	Timestamp              TimestampValidationOptions
	Binding                ResponseBindingValidationOptions
	InResponseTo           InResponseToValidationOptions
	Replay                 AssertionReplayOptions
	EnableReplayProtection *bool
	Decryption             *AssertionDecryptionOptions
}
```

### `SPDescriptor`

SPDescriptor contains the SP metadata used by AuthnRequest generation and
response audience/recipient validation.

```go
type SPDescriptor struct {
	AuthnRequestsSigned       bool
	WantAssertionsSigned      bool
	AssertionConsumerServices []Endpoint
	SingleLogoutServices      []Endpoint
	NameIDFormats             []string
	Keys                      []KeyDescriptor
}
```

## Methods on `SPDescriptor`

### `SigningCertificates`

SigningCertificates returns SP signing keys (use="signing" or unspecified)
with duplicates removed.

```go
func (descriptor SPDescriptor) SigningCertificates() []*x509.Certificate
```

### `SignatureRequirement`

SignatureRequirement controls which XML elements must carry a valid
enveloped signature. The zero value requires either the Response or its
Assertion to be signed, matching common SAML interoperability behavioral compatibility.
Every signature that is present is always verified, even when it is not
required by this setting.

```go
type SignatureRequirement string
```

## Constants associated with `SignatureRequirement`

```go
const (
	SignatureAny       SignatureRequirement = "any"
	SignatureAssertion SignatureRequirement = "assertion"
	SignatureResponse  SignatureRequirement = "response"
	SignatureBoth      SignatureRequirement = "both"
	SignatureNone      SignatureRequirement = "none"
)
```

### `SignatureVerificationOptions`

SignatureVerificationOptions configures XMLDSIG validation. Configured
certificates are trust anchors. Certificate validity dates are ignored by
default for conformance with the reference implementation's configured-certificate trust model;
set CheckCertificateValidity to enforce them.

```go
type SignatureVerificationOptions struct {
	Certificates             []*x509.Certificate
	Requirement              SignatureRequirement
	Algorithms               AlgorithmValidationOptions
	CheckCertificateValidity bool
	Now                      func() time.Time
}
```

### `SignatureVerificationResult`

SignatureVerificationResult reports which protected elements were signed.

```go
type SignatureVerificationResult struct {
	ResponseSigned              bool
	AssertionSigned             bool
	ResponseSignatureAlgorithm  string
	AssertionSignatureAlgorithm string
}
```

## Constructors and functions for `SignatureVerificationResult`

### `VerifyResponseSignatures`

VerifyResponseSignatures validates all direct Response and Assertion
signatures and then enforces the requested placement policy.

```go
func VerifyResponseSignatures(
	response Response,
	options SignatureVerificationOptions,
) (SignatureVerificationResult, error)
```

### `SubjectConfirmationData`

SubjectConfirmationData is one bearer confirmation target and correlation
tuple from an assertion.

```go
type SubjectConfirmationData struct {
	Method       string
	Recipient    string
	RecipientSet bool
	InResponseTo string
	NotBefore    string
	NotOnOrAfter string
}
```

### `TimestampValidationOptions`

TimestampValidationOptions configures assertion time validation.

```go
type TimestampValidationOptions struct {
	ClockSkew         *time.Duration
	RequireTimestamps bool
	Now               func() time.Time
	Warn              func(message string, fields map[string]any)
}
```

### `ValidatedResponse`

ValidatedResponse is returned only after signature, time, binding,
correlation, and replay gates have succeeded.

```go
type ValidatedResponse struct {
	Response      Response
	Signatures    SignatureVerificationResult
	BindingSigned bool
	RelayState    string
	AuthnRequest  *AuthnRequestRecord
	ReplayRecord  *AssertionReplayRecord
}
```

## Constructors and functions for `ValidatedResponse`

### `ValidatePOSTResponse`

ValidatePOSTResponse validates an HTTP-POST SAMLResponse. the reference implementation limits
the received base64 value before decoding, so this entry point applies both
encoded and decoded size bounds.

```go
func ValidatePOSTResponse(
	ctx context.Context,
	encodedResponse string,
	relayState string,
	options ResponseValidationOptions,
) (ValidatedResponse, error)
```

### `ValidateRedirectResponse`

ValidateRedirectResponse verifies the exact HTTP-Redirect query signature,
inflates the SAMLResponse, and runs the common response pipeline. A valid
Redirect-binding signature satisfies the default "any signature" policy;
explicit response/assertion/both XML placement policies remain in force.

```go
func ValidateRedirectResponse(
	ctx context.Context,
	rawQuery string,
	trustedKeys []crypto.PublicKey,
	options ResponseValidationOptions,
) (ValidatedResponse, error)
```

### `ValidateResponseXML`

ValidateResponseXML validates decoded XML. It is useful for framework
adapters that have already applied a SAML binding.

```go
func ValidateResponseXML(
	ctx context.Context,
	xmlData []byte,
	options ResponseValidationOptions,
) (ValidatedResponse, error)
```

### `XMLSigningOptions`

XMLSigningOptions configures an enveloped AuthnRequest signature for the
HTTP-POST binding. Redirect binding must instead be signed with
BuildRedirectURL because its signature covers the encoded query string.

```go
type XMLSigningOptions struct {
	Signer             crypto.Signer
	Certificates       []*x509.Certificate
	SignatureAlgorithm string
	Algorithms         AlgorithmValidationOptions
}
```

