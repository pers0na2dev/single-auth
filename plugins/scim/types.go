package scim

import (
	"context"
	"io"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	// Version is the frozen single-auth SCIM package version implemented here.
	Version = "1.6.26"

	EndpointPatchSCIMUser                = "patchSCIMUser"
	EndpointGenerateSCIMToken            = "generateSCIMToken"
	EndpointListSCIMProviderConnections  = "listSCIMProviderConnections"
	EndpointGetSCIMProviderConnection    = "getSCIMProviderConnection"
	EndpointDeleteSCIMProviderConnection = "deleteSCIMProviderConnection"
	EndpointCreateSCIMUser               = "createSCIMUser"
	EndpointListSCIMUsers                = "listSCIMUsers"
	EndpointGetSCIMUser                  = "getSCIMUser"
	EndpointUpdateSCIMUser               = "updateSCIMUser"
	EndpointDeleteSCIMUser               = "deleteSCIMUser"
	PatchOpSchema                        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	UserSchema                           = "urn:ietf:params:scim:schemas:core:2.0:User"
	ErrorSchema                          = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Provider is the token-bearing SCIM provider scope selected by middleware.
type Provider struct {
	ID             string `json:"id"`
	ProviderID     string `json:"providerId"`
	SCIMToken      string `json:"scimToken,omitempty"`
	OrganizationID string `json:"organizationId,omitempty"`
	UserID         string `json:"userId,omitempty"`
}

// ProviderOwnership controls the optional scimProvider.userId schema field.
type ProviderOwnership struct {
	Enabled bool
}

// TokenVerifier compares a persisted SCIM token with the presented secret.
// Applications using hashed or encrypted persistence can supply their own
// verifier; nil uses a constant-time plain-text comparison.
type TokenVerifier func(context.Context, string, string) (bool, error)

// TokenStorageMode selects how newly generated SCIM secrets are persisted.
// The zero value is the single-auth default, plain-text storage.
type TokenStorageMode string

const (
	TokenStoragePlain     TokenStorageMode = "plain"
	TokenStorageHashed    TokenStorageMode = "hashed"
	TokenStorageEncrypted TokenStorageMode = "encrypted"
)

// TokenTransform mirrors single-auth's custom hash/encrypt/decrypt callbacks.
type TokenTransform func(context.Context, string) (string, error)

// TokenStorage configures the persisted representation of generated tokens.
// Hash is selected when non-nil. Encrypt and Decrypt must be supplied together.
type TokenStorage struct {
	Mode    TokenStorageMode
	Hash    TokenTransform
	Encrypt TokenTransform
	Decrypt TokenTransform
}

// TokenGenerationPayload is passed to authorization and lifecycle hooks.
type TokenGenerationPayload struct {
	User           storage.Record
	Member         storage.Record
	ProviderID     string
	OrganizationID string
	SCIMToken      string
	SCIMProvider   *Provider
}

// CanGenerateTokenFunc applies an application-specific authorization gate
// after the built-in organization and role checks.
type CanGenerateTokenFunc func(context.Context, TokenGenerationPayload) (bool, error)

// TokenGenerationHook observes or rejects token generation. The after hook
// receives SCIMProvider; the before hook receives nil in that field.
type TokenGenerationHook func(context.Context, TokenGenerationPayload) error

// ExistingUserLinkInput describes an existing identity considered for an
// explicit SCIM account link.
type ExistingUserLinkInput struct {
	User           storage.Record
	Email          string
	ProviderID     string
	OrganizationID string
}

// LinkExistingUsersOptions opts into linking a SCIM account to a user found by
// email. The zero value rejects linking. When Enabled is true without further
// constraints every matching existing user may be linked, matching the
// provider boolean true option.
type LinkExistingUsersOptions struct {
	Enabled                      bool
	TrustedDomains               []string
	RequireExistingOrgMembership bool
	ShouldLinkUser               func(context.Context, ExistingUserLinkInput) (bool, error)
}

// Runtime contains the root services used by SCIM endpoints. NewFactory binds
// these fields to single-auth automatically.
type Runtime struct {
	Adapter                  storage.TransactionAdapter
	AdapterForContext        func(context.Context) storage.TransactionAdapter
	Random                   io.Reader
	EncryptSecret            func([]byte) (string, error)
	DecryptSecret            func(string) ([]byte, error)
	ReservedProviderID       func(string) bool
	UpdateUser               func(*engine.Context, string, storage.Record) (storage.Record, error)
	CreateUser               func(*engine.Context, storage.Record) (storage.Record, error)
	CreateAccount            func(context.Context, storage.Record) (storage.Record, error)
	DeleteUser               func(*engine.Context, string) error
	RevokeSessions           func(*engine.Context, string) error
	RemoveOrganizationMember func(
		context.Context,
		string,
		string,
		func(context.Context, storage.TransactionAdapter) error,
	) error
	HasPlugin func(string) bool
	Clock     func() time.Time
}

// Options configures the SCIM production surface.
type Options struct {
	ProviderOwnership        ProviderOwnership
	DefaultSCIM              []Provider
	RequiredRoles            []string
	CreatorRole              string
	ReservedProviderIDs      []string
	StoreSCIMToken           TokenStorage
	CanGenerateToken         CanGenerateTokenFunc
	BeforeSCIMTokenGenerated TokenGenerationHook
	AfterSCIMTokenGenerated  TokenGenerationHook
	LinkExistingUsers        LinkExistingUsersOptions
	VerifyToken              TokenVerifier
	Runtime                  Runtime
}

// Operation is one SCIM PatchOp operation. Value retains JSON scalar/object
// types, and Path accepts leading-slash and dot notation.
type Operation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value"`
}

// PatchRequest is the RFC 7644 PATCH User request body.
type PatchRequest struct {
	Schemas    []string    `json:"schemas"`
	Operations []Operation `json:"Operations"`
}

// PatchResources contains the canonical single-auth user and account updates.
type PatchResources struct {
	User    storage.Record
	Account storage.Record
}

type rootFactory struct{ options Options }

var _ singleauth.PluginFactory = (*rootFactory)(nil)
