// Package webauthn implements the WebAuthn protocol layer used by Better
// Auth's passkey plugin. It is transport and storage independent.
package webauthn

import (
	"crypto/x509"
	"io"
	"time"
)

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

// SupportedCOSEAlgorithmIdentifiers is the complete algorithm allow-list used
// by @simplewebauthn/server 13.2.3 when verifying registration responses.
var SupportedCOSEAlgorithmIdentifiers = []int{
	COSEAlgEdDSA, COSEAlgES256, COSEAlgES512,
	COSEAlgPS256, COSEAlgPS384, COSEAlgPS512,
	COSEAlgRS256, COSEAlgRS384, COSEAlgRS512, COSEAlgRS1,
}

// DefaultRegistrationAlgorithmIdentifiers is the smaller preference list
// emitted in registration options. Ed25519 is intentionally preferred.
var DefaultRegistrationAlgorithmIdentifiers = []int{COSEAlgEdDSA, COSEAlgES256, COSEAlgRS256}

type CredentialDescriptor struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}

type CredentialParameter struct {
	Alg  int    `json:"alg"`
	Type string `json:"type"`
}

type RelyingPartyEntity struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// AuthenticatorSelectionCriteria keeps pointer fields where JavaScript
// distinguishes an omitted value from false.
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	RequireResidentKey      *bool  `json:"requireResidentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

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

type RequestOptionsJSON struct {
	RPID             string                 `json:"rpId"`
	Challenge        string                 `json:"challenge"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials,omitempty"`
	Timeout          int                    `json:"timeout"`
	UserVerification string                 `json:"userVerification"`
	Extensions       map[string]any         `json:"extensions,omitempty"`
}

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

type RegistrationResponseJSON struct {
	ID                      string                  `json:"id"`
	RawID                   string                  `json:"rawId"`
	Type                    string                  `json:"type"`
	Response                AttestationResponseJSON `json:"response"`
	ClientExtensionResults  map[string]any          `json:"clientExtensionResults,omitempty"`
	AuthenticatorAttachment string                  `json:"authenticatorAttachment,omitempty"`
}

type AttestationResponseJSON struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AttestationObject  string   `json:"attestationObject"`
	Transports         []string `json:"transports,omitempty"`
	PublicKey          string   `json:"publicKey,omitempty"`
	PublicKeyAlgorithm int      `json:"publicKeyAlgorithm,omitempty"`
	AuthenticatorData  string   `json:"authenticatorData,omitempty"`
}

type AuthenticationResponseJSON struct {
	ID                      string                `json:"id"`
	RawID                   string                `json:"rawId"`
	Type                    string                `json:"type"`
	Response                AssertionResponseJSON `json:"response"`
	ClientExtensionResults  map[string]any        `json:"clientExtensionResults,omitempty"`
	AuthenticatorAttachment string                `json:"authenticatorAttachment,omitempty"`
}

type AssertionResponseJSON struct {
	ClientDataJSON    string  `json:"clientDataJSON"`
	AuthenticatorData string  `json:"authenticatorData"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle,omitempty"`
}

type TokenBinding struct {
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
}

type ClientDataJSON struct {
	Type         string        `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	CrossOrigin  bool          `json:"crossOrigin,omitempty"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

type AuthenticatorFlags struct {
	UP       bool
	UV       bool
	BE       bool
	BS       bool
	AT       bool
	ED       bool
	FlagsInt byte
}

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

type CredentialDeviceType string

const (
	SingleDevice CredentialDeviceType = "singleDevice"
	MultiDevice  CredentialDeviceType = "multiDevice"
)

type Credential struct {
	ID         string
	PublicKey  []byte
	Counter    uint32
	Transports []string
}

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

type VerifiedRegistrationResponse struct {
	Verified         bool
	RegistrationInfo *RegistrationInfo
}

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

type VerifiedAuthenticationResponse struct {
	Verified           bool
	AuthenticationInfo AuthenticationInfo
}

type ChallengeVerifier func(challenge string) (bool, error)

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

type AdvancedFIDOConfig struct {
	UserVerification string
}
