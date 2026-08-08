---
title: "github.com/pers0na2dev/single-auth/protocol/webauthn"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/protocol/webauthn.

- Import path: `github.com/pers0na2dev/single-auth/protocol/webauthn`
- Package name: `webauthn`

Package webauthn implements the WebAuthn protocol layer used by Better
Auth's passkey plugin. It is transport and storage independent.

## Constants

```go
const (
	COSEKTYOKP = 1
	COSEKTYEC2 = 2
	COSEKTYRSA = 3

	COSECurveP256      = 1
	COSECurveP384      = 2
	COSECurveP521      = 3
	COSECurveEd25519   = 6
	COSECurveSecp256k1 = 8
)
```

```go
const (
	MaxClientDataJSONBytes      = 64 << 10
	MaxAttestationObjectBytes   = 2 << 20
	MaxAuthenticatorDataBytes   = 1 << 20
	MaxCredentialPublicKeyBytes = 16 << 10
	MaxCredentialIDBytes        = 1024
	MaxSignatureBytes           = 16 << 10
)
```

```go
const (
	PublicKeyCredentialType = "public-key"
	DefaultTimeoutMS        = 60_000

	COSEAlgEdDSA  = -8
	COSEAlgES256  = -7
	COSEAlgES384  = -35
	COSEAlgES512  = -36
	COSEAlgPS256  = -37
	COSEAlgPS384  = -38
	COSEAlgPS512  = -39
	COSEAlgES256K = -47
	COSEAlgRS256  = -257
	COSEAlgRS384  = -258
	COSEAlgRS512  = -259
	COSEAlgRS1    = -65535
)
```

## Variables

```go
var (
	ErrInvalidBase64URL = errors.New("invalid base64url value")
	ErrInputTooLarge    = errors.New("WebAuthn input exceeds size limit")
)
```

DefaultRegistrationAlgorithmIdentifiers is the smaller preference list
emitted in registration options. Ed25519 is intentionally preferred.

```go
var DefaultRegistrationAlgorithmIdentifiers = []int{COSEAlgEdDSA, COSEAlgES256, COSEAlgRS256}
```

SupportedCOSEAlgorithmIdentifiers is the complete algorithm allow-list used
by @simplewebauthn/server 13.2.3 when verifying registration responses.

```go
var SupportedCOSEAlgorithmIdentifiers = []int{
	COSEAlgEdDSA, COSEAlgES256, COSEAlgES512,
	COSEAlgPS256, COSEAlgPS384, COSEAlgPS512,
	COSEAlgRS256, COSEAlgRS384, COSEAlgRS512, COSEAlgRS1,
}
```

## Functions

### `ValidateSignCount`

ValidateSignCount applies SimpleWebAuthn's replay rule. Authenticators that
report zero forever are accepted only while both stored and reported values
remain zero; otherwise the new value must strictly increase.

```go
func ValidateSignCount(stored, reported uint32) error
```

### `VerifySignature`

```go
func VerifySignature(credentialPublicKey, signature, data []byte) (bool, error)
```

## Types

### `AdvancedFIDOConfig`

```go
type AdvancedFIDOConfig struct {
	UserVerification string
}
```

### `AssertionResponseJSON`

```go
type AssertionResponseJSON struct {
	ClientDataJSON    string  `json:"clientDataJSON"`
	AuthenticatorData string  `json:"authenticatorData"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle,omitempty"`
}
```

### `AttestationResponseJSON`

```go
type AttestationResponseJSON struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AttestationObject  string   `json:"attestationObject"`
	Transports         []string `json:"transports,omitempty"`
	PublicKey          string   `json:"publicKey,omitempty"`
	PublicKeyAlgorithm int      `json:"publicKeyAlgorithm,omitempty"`
	AuthenticatorData  string   `json:"authenticatorData,omitempty"`
}
```

### `AuthenticationInfo`

```go
type AuthenticationInfo struct {
	CredentialID                  string
	NewCounter                    uint32
	UserVerified                  bool
	CredentialDeviceType          CredentialDeviceType
	CredentialBackedUp            bool
	Origin                        string
	RPID                          string
	AuthenticatorExtensionResults map[string]any
}
```

### `AuthenticationResponseJSON`

```go
type AuthenticationResponseJSON struct {
	ID                      string                `json:"id"`
	RawID                   string                `json:"rawId"`
	Type                    string                `json:"type"`
	Response                AssertionResponseJSON `json:"response"`
	ClientExtensionResults  map[string]any        `json:"clientExtensionResults,omitempty"`
	AuthenticatorAttachment string                `json:"authenticatorAttachment,omitempty"`
}
```

### `AuthenticatorFlags`

```go
type AuthenticatorFlags struct {
	UP       bool
	UV       bool
	BE       bool
	BS       bool
	AT       bool
	ED       bool
	FlagsInt byte
}
```

### `AuthenticatorSelectionCriteria`

AuthenticatorSelectionCriteria keeps pointer fields where JavaScript
distinguishes an omitted value from false.

```go
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	RequireResidentKey      *bool  `json:"requireResidentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}
```

### `COSEPublicKey`

```go
type COSEPublicKey struct {
	KTY   int
	Alg   int
	Curve int
	X     []byte
	Y     []byte
	N     []byte
	E     []byte
	Raw   map[int64]any
}
```

## Constructors and functions for `COSEPublicKey`

### `DecodeCredentialPublicKey`

```go
func DecodeCredentialPublicKey(encoded []byte) (COSEPublicKey, error)
```

## Methods on `COSEPublicKey`

### `CryptoPublicKey`

```go
func (key COSEPublicKey) CryptoPublicKey() (crypto.PublicKey, error)
```

### `ChallengeVerifier`

```go
type ChallengeVerifier func(challenge string) (bool, error)
```

### `ClientDataJSON`

```go
type ClientDataJSON struct {
	Type         string        `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	CrossOrigin  bool          `json:"crossOrigin,omitempty"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}
```

## Constructors and functions for `ClientDataJSON`

### `DecodeClientDataJSON`

```go
func DecodeClientDataJSON(encoded string) (ClientDataJSON, []byte, error)
```

### `CreationOptionsJSON`

```go
type CreationOptionsJSON struct {
	Challenge              string                         `json:"challenge"`
	RP                     RelyingPartyEntity             `json:"rp"`
	User                   UserEntity                     `json:"user"`
	PubKeyCredParams       []CredentialParameter          `json:"pubKeyCredParams"`
	Timeout                int                            `json:"timeout"`
	Attestation            string                         `json:"attestation"`
	ExcludeCredentials     []CredentialDescriptor         `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelectionCriteria `json:"authenticatorSelection"`
	Extensions             map[string]any                 `json:"extensions"`
	Hints                  []string                       `json:"hints"`
}
```

## Constructors and functions for `CreationOptionsJSON`

### `GenerateRegistrationOptions`

```go
func GenerateRegistrationOptions(input GenerateRegistrationOptionsInput) (CreationOptionsJSON, error)
```

### `Credential`

```go
type Credential struct {
	ID         string
	PublicKey  []byte
	Counter    uint32
	Transports []string
}
```

### `CredentialDescriptor`

```go
type CredentialDescriptor struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}
```

### `CredentialDeviceType`

```go
type CredentialDeviceType string
```

## Constants associated with `CredentialDeviceType`

```go
const (
	SingleDevice CredentialDeviceType = "singleDevice"
	MultiDevice  CredentialDeviceType = "multiDevice"
)
```

## Constructors and functions for `CredentialDeviceType`

### `ParseBackupFlags`

```go
func ParseBackupFlags(flags AuthenticatorFlags) (CredentialDeviceType, bool, error)
```

### `CredentialParameter`

```go
type CredentialParameter struct {
	Alg  int    `json:"alg"`
	Type string `json:"type"`
}
```

### `GenerateAuthenticationOptionsInput`

```go
type GenerateAuthenticationOptionsInput struct {
	RPID             string
	AllowCredentials []CredentialDescriptor
	Challenge        any // nil, string (UTF-8), or []byte
	Timeout          int
	// TimeoutMS distinguishes an explicit zero from an omitted timeout.
	TimeoutMS        *int
	UserVerification string
	Extensions       map[string]any
	Random           io.Reader
}
```

### `GenerateRegistrationOptionsInput`

```go
type GenerateRegistrationOptionsInput struct {
	RPName          string
	RPID            string
	UserName        string
	UserID          []byte
	Challenge       any // nil, string (UTF-8), or []byte
	UserDisplayName string
	Timeout         int
	// TimeoutMS distinguishes an explicit zero from an omitted timeout.
	TimeoutMS                  *int
	AttestationType            string
	ExcludeCredentials         []CredentialDescriptor
	AuthenticatorSelection     *AuthenticatorSelectionCriteria
	Extensions                 map[string]any
	SupportedAlgorithmIDs      []int
	PreferredAuthenticatorType string
	Random                     io.Reader
}
```

### `ParsedAuthenticatorData`

```go
type ParsedAuthenticatorData struct {
	RPIDHash             []byte
	FlagsBuffer          []byte
	Flags                AuthenticatorFlags
	Counter              uint32
	CounterBuffer        []byte
	AAGUID               []byte
	CredentialID         []byte
	CredentialPublicKey  []byte
	ExtensionsData       map[string]any
	ExtensionsDataBuffer []byte
}
```

## Constructors and functions for `ParsedAuthenticatorData`

### `ParseAuthenticatorData`

```go
func ParseAuthenticatorData(authData []byte) (ParsedAuthenticatorData, error)
```

### `RegistrationInfo`

```go
type RegistrationInfo struct {
	Format                        string
	AAGUID                        string
	Credential                    Credential
	CredentialType                string
	AttestationObject             []byte
	UserVerified                  bool
	CredentialDeviceType          CredentialDeviceType
	CredentialBackedUp            bool
	Origin                        string
	RPID                          string
	AuthenticatorExtensionResults map[string]any
}
```

### `RegistrationResponseJSON`

```go
type RegistrationResponseJSON struct {
	ID                      string                  `json:"id"`
	RawID                   string                  `json:"rawId"`
	Type                    string                  `json:"type"`
	Response                AttestationResponseJSON `json:"response"`
	ClientExtensionResults  map[string]any          `json:"clientExtensionResults,omitempty"`
	AuthenticatorAttachment string                  `json:"authenticatorAttachment,omitempty"`
}
```

### `RelyingPartyEntity`

```go
type RelyingPartyEntity struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}
```

### `RequestOptionsJSON`

```go
type RequestOptionsJSON struct {
	RPID             string                 `json:"rpId"`
	Challenge        string                 `json:"challenge"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials,omitempty"`
	Timeout          int                    `json:"timeout"`
	UserVerification string                 `json:"userVerification"`
	Extensions       map[string]any         `json:"extensions,omitempty"`
}
```

## Constructors and functions for `RequestOptionsJSON`

### `GenerateAuthenticationOptions`

```go
func GenerateAuthenticationOptions(input GenerateAuthenticationOptionsInput) (RequestOptionsJSON, error)
```

### `TokenBinding`

```go
type TokenBinding struct {
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
}
```

### `UserEntity`

```go
type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}
```

### `VerifiedAuthenticationResponse`

```go
type VerifiedAuthenticationResponse struct {
	Verified           bool
	AuthenticationInfo AuthenticationInfo
}
```

## Constructors and functions for `VerifiedAuthenticationResponse`

### `VerifyAuthenticationResponse`

```go
func VerifyAuthenticationResponse(options VerifyAuthenticationOptions) (VerifiedAuthenticationResponse, error)
```

### `VerifiedRegistrationResponse`

```go
type VerifiedRegistrationResponse struct {
	Verified         bool
	RegistrationInfo *RegistrationInfo
}
```

## Constructors and functions for `VerifiedRegistrationResponse`

### `VerifyRegistrationResponse`

```go
func VerifyRegistrationResponse(options VerifyRegistrationOptions) (VerifiedRegistrationResponse, error)
```

### `VerifyAuthenticationOptions`

```go
type VerifyAuthenticationOptions struct {
	Response                AuthenticationResponseJSON
	ExpectedChallenge       string
	ChallengeVerifier       ChallengeVerifier
	ExpectedOrigins         []string
	ExpectedRPIDs           []string
	ExpectedTypes           []string
	Credential              Credential
	RequireUserVerification *bool
	AdvancedFIDOConfig      *AdvancedFIDOConfig
	// AdvancedUserVerification is a convenience alias for callers that don't
	// need to distinguish an omitted config from an empty config.
	AdvancedUserVerification string
}
```

### `VerifyRegistrationOptions`

```go
type VerifyRegistrationOptions struct {
	Response                            RegistrationResponseJSON
	ExpectedChallenge                   string
	ChallengeVerifier                   ChallengeVerifier
	ExpectedOrigins                     []string
	ExpectedRPIDs                       []string
	ExpectedTypes                       []string
	RequireUserPresence                 *bool
	RequireUserVerification             *bool
	SupportedAlgorithmIDs               []int
	AttestationSafetyNetEnforceCTSCheck *bool
	AttestationRoots                    map[string]*x509.CertPool
	Now                                 func() time.Time
}
```

