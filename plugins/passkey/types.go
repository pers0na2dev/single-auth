package passkey

import (
	"context"
	"io"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

const (
	// Version is the frozen @single-auth/passkey package version.
	Version = "1.6.26"

	defaultChallengeAge = 5 * time.Minute
)

// Passkey is the public passkey model returned by the plugin endpoints.
type Passkey struct {
	ID           string                        `json:"id"`
	Name         string                        `json:"name,omitempty"`
	PublicKey    string                        `json:"publicKey"`
	UserID       string                        `json:"userId"`
	CredentialID string                        `json:"credentialID"`
	Counter      uint32                        `json:"counter"`
	DeviceType   webauthn.CredentialDeviceType `json:"deviceType"`
	BackedUp     bool                          `json:"backedUp"`
	Transports   string                        `json:"transports,omitempty"`
	CreatedAt    time.Time                     `json:"createdAt"`
	AAGUID       string                        `json:"aaguid,omitempty"`
}

// RegistrationUser is the account identity bound into a registration
// challenge. DisplayName falls back to Name and then ID.
type RegistrationUser struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// SessionState is the session/user pair resolved by the host runtime.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// SessionResolution tells the host how strongly an endpoint needs a session.
type SessionResolution uint8

const (
	SessionOptional SessionResolution = iota
	SessionRequired
	SessionFresh
)

// ResolveSessionFunc resolves the request's session. It returns nil, nil for an
// unauthenticated optional lookup. For SessionFresh, the host must apply its
// configured freshness policy and may return SESSION_NOT_FRESH.
type ResolveSessionFunc func(*engine.Context, SessionResolution) (*SessionState, error)

// IssueSessionFunc creates a session for userID, resolves its user, and writes
// the host's session cookies to ctx. A nil result means creation failed.
type IssueSessionFunc func(*engine.Context, string) (*SessionState, error)

// ExtensionsResolver computes WebAuthn extensions for one endpoint request.
type ExtensionsResolver func(*engine.Context) (map[string]any, error)

// ResolveRegistrationUserArgs is passed to passkey-first identity resolution.
type ResolveRegistrationUserArgs struct {
	Context *string
	Request *engine.Context
}

type ResolveRegistrationUserFunc func(ResolveRegistrationUserArgs) (RegistrationUser, error)

type AfterRegistrationVerificationArgs struct {
	Context      *engine.Context
	Verification webauthn.VerifiedRegistrationResponse
	User         RegistrationUser
	ClientData   webauthn.RegistrationResponseJSON
	FlowContext  *string
}

// AfterRegistrationVerificationResult optionally reassigns the credential and
// supplies a label. Empty values mean no override, matching upstream truthiness.
type AfterRegistrationVerificationResult struct {
	UserID string
	Name   string
}

type AfterRegistrationVerificationFunc func(AfterRegistrationVerificationArgs) (AfterRegistrationVerificationResult, error)

type AfterAuthenticationVerificationArgs struct {
	Context      *engine.Context
	Verification webauthn.VerifiedAuthenticationResponse
	ClientData   webauthn.AuthenticationResponseJSON
}

type AfterAuthenticationVerificationFunc func(AfterAuthenticationVerificationArgs) error

type RegistrationOptions struct {
	// RequireSession defaults to true. Use Bool(false) for passkey-first flows.
	RequireSession    *bool
	ResolveUser       ResolveRegistrationUserFunc
	Extensions        map[string]any
	ResolveExtensions ExtensionsResolver
	AfterVerification AfterRegistrationVerificationFunc
}

type AuthenticationOptions struct {
	Extensions        map[string]any
	ResolveExtensions ExtensionsResolver
	AfterVerification AfterAuthenticationVerificationFunc
}

// ChallengeCookie is the fully resolved cookie dependency. When omitted, New
// derives single-auth's default cookie from BaseURL and Advanced options.
type ChallengeCookie struct {
	Name       string
	Attributes cookies.Options
}

type ChallengeCookieResolver func(contract.Request) (ChallengeCookie, error)

type AdvancedOptions struct {
	// WebAuthnChallengeCookie is the createAuthCookie key. It defaults to
	// "single-auth-passkey" and is prefixed by CookiePrefix.
	WebAuthnChallengeCookie string
	CookiePrefix            string
	ChallengeCookie         *ChallengeCookie
}

type RegistrationVerifier func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error)
type AuthenticationVerifier func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error)
type CreateChallengeFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type ConsumeChallengeFunc func(context.Context, string) (storage.Record, error)

// Runtime contains dependencies that single-auth normally injects through its
// internal endpoint context. They are explicit until the Go root runtime
// exposes an equivalent public plugin dependency surface.
type Runtime struct {
	Adapter                storage.Adapter
	ResolveSession         ResolveSessionFunc
	IssueSession           IssueSessionFunc
	Clock                  func() time.Time
	Random                 io.Reader
	ResolveChallengeCookie ChallengeCookieResolver
	CreateChallenge        CreateChallengeFunc
	ConsumeChallenge       ConsumeChallengeFunc
	VerifyRegistration     RegistrationVerifier
	VerifyAuthentication   AuthenticationVerifier
}

// Options configures the single-auth-compatible passkey plugin.
type Options struct {
	RPID                   string
	RPName                 string
	Origin                 string
	Origins                []string
	BaseURL                string
	AppName                string
	Secret                 string
	AuthenticatorSelection *webauthn.AuthenticatorSelectionCriteria
	Advanced               AdvancedOptions
	Registration           RegistrationOptions
	Authentication         AuthenticationOptions
	Schema                 storage.Schema
	Runtime                Runtime
}

// Bool returns a pointer for options whose omitted and false states differ.
func Bool(value bool) *bool { return &value }
