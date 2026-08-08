---
title: "github.com/pers0na2dev/single-auth/plugins/organization"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/organization.

- Import path: `github.com/pers0na2dev/single-auth/plugins/organization`
- Package name: `organization`

Package organization implements the single-auth 1.6.26 organization plugin.

The package is transport neutral. A bound Plugin exposes the same create
operation to HTTP/direct dispatch and to database hooks, while keeping the
organization and initial owner membership in one storage transaction.

## Constants

```go
const (
	ErrorOrganizationAlreadyExists      = "ORGANIZATION_ALREADY_EXISTS"
	ErrorOrganizationNotFound           = "ORGANIZATION_NOT_FOUND"
	ErrorUserAlreadyMember              = "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION"
	ErrorUserAlreadyInvited             = "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION"
	ErrorNoActiveOrganization           = "NO_ACTIVE_ORGANIZATION"
	ErrorMemberNotFound                 = "MEMBER_NOT_FOUND"
	ErrorOnlyOwner                      = "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"
	ErrorMemberDeleteForbidden          = "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER"
	ErrorOrganizationCreateForbidden    = "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"
	ErrorOrganizationLimitReached       = "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"
	ErrorOrganizationSlugTaken          = "ORGANIZATION_SLUG_ALREADY_TAKEN"
	ErrorUserNotOrganizationMember      = "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"
	ErrorOrganizationUpdateForbidden    = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"
	ErrorOrganizationDeleteForbidden    = "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION"
	ErrorOrganizationDeletionDisabled   = "ORGANIZATION_DELETION_DISABLED"
	ErrorMemberUpdateForbidden          = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER"
	ErrorOrganizationWithoutOwner       = "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER"
	ErrorNotMemberOfOrganization        = "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION"
	ErrorRoleNotFound                   = "ROLE_NOT_FOUND"
	ErrorInvitationForbidden            = "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION"
	ErrorInvitationNotFound             = "INVITATION_NOT_FOUND"
	ErrorInvitationRecipientMismatch    = "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"
	ErrorInvitationEmailUnverified      = "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION"
	ErrorInvitationListUnverified       = "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION"
	ErrorInvitationCancelForbidden      = "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION"
	ErrorInvitationCreatorRoleForbidden = "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE"
	ErrorInviterNoLongerMember          = "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION"
	ErrorMembershipLimitReached         = "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"
	ErrorTeamNotFound                   = "TEAM_NOT_FOUND"
	ErrorInvalidTeamID                  = "INVALID_TEAM_ID"
	ErrorTeamCreateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION"
	ErrorTeamDeleteForbidden            = "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION"
	ErrorTeamUpdateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"
	ErrorTeamDeleteActiveForbidden      = "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM"
	ErrorMaximumTeamsReached            = "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"
	ErrorUnableToRemoveLastTeam         = "UNABLE_TO_REMOVE_LAST_TEAM"
	ErrorOrganizationAccessForbidden    = "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION"
	ErrorUserNotTeamMember              = "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"
	ErrorNoActiveTeam                   = "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM"
	ErrorTeamMemberCreateForbidden      = "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER"
	ErrorTeamMemberRemoveForbidden      = "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER"
	ErrorTeamMemberLimitReached         = "TEAM_MEMBER_LIMIT_REACHED"
	ErrorMissingAccessControl           = "MISSING_AC_INSTANCE"
	ErrorRoleOrganizationRequired       = "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE"
	ErrorRoleCreateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"
	ErrorRoleUpdateForbidden            = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE"
	ErrorRoleDeleteForbidden            = "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE"
	ErrorRoleReadForbidden              = "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE"
	ErrorRoleListForbidden              = "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE"
	ErrorRoleGetForbidden               = "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE"
	ErrorTooManyRoles                   = "TOO_MANY_ROLES"
	ErrorInvalidRoleResource            = "INVALID_RESOURCE"
	ErrorRoleNameTaken                  = "ROLE_NAME_IS_ALREADY_TAKEN"
	ErrorCannotDeletePredefinedRole     = "CANNOT_DELETE_A_PRE_DEFINED_ROLE"
	ErrorRoleAssignedToMembers          = "ROLE_IS_ASSIGNED_TO_MEMBERS"
)
```

```go
const Version = "1.6.26"
```

## Variables

DefaultStatements is single-auth 1.6.26's organization permission
vocabulary. Applications can extend this map before constructing their own
authorization.AccessControl.

```go
var DefaultStatements = authorization.Statements{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
}
```

## Functions

### `DefaultAccessControl`

DefaultAccessControl returns independent built-in role values on each call.

```go
func DefaultAccessControl() (*authorization.AccessControl, map[string]*authorization.Role)
```

### `Schema`

Schema returns the canonical single-auth organization storage extension.

```go
func Schema(options Options) (storage.Schema, error)
```

### `VerifiedMemberFromContext`

VerifiedMemberFromContext returns the member record established by
RequireOrgRole. The returned map is independent from request-local state.

```go
func VerifiedMemberFromContext(ctx *engine.Context) (storage.Record, bool)
```

## Types

### `AcceptInvitationInput`

```go
type AcceptInvitationInput struct {
	InvitationID  string
	UserID        string
	UserEmail     string
	EmailVerified bool
	SessionToken  string
}
```

### `AcceptInvitationResult`

```go
type AcceptInvitationResult struct {
	Invitation Invitation `json:"invitation"`
	Member     Member     `json:"member"`
}
```

### `ActiveMemberRoleResult`

```go
type ActiveMemberRoleResult struct {
	Role string `json:"role"`
}
```

### `AddMemberInput`

AddMemberInput is accepted by the server-only addMember API. Roles are
persisted in single-auth's canonical comma-separated representation.

```go
type AddMemberInput struct {
	OrganizationID string
	UserID         string
	Roles          []string
}
```

### `AfterAcceptInvitationData`

```go
type AfterAcceptInvitationData struct {
	Invitation   Invitation
	Member       Member
	User         storage.Record
	Organization Organization
}
```

### `AfterAddMemberData`

```go
type AfterAddMemberData struct {
	Member       Member
	User         storage.Record
	Organization Organization
}
```

### `AfterCreateInvitationData`

```go
type AfterCreateInvitationData struct {
	Invitation   Invitation
	Inviter      storage.Record
	Organization Organization
}
```

### `AfterCreateOrganizationData`

```go
type AfterCreateOrganizationData struct {
	Organization Organization
	Member       Member
	User         storage.Record
}
```

### `AfterCreateTeamData`

```go
type AfterCreateTeamData struct {
	Team               Team
	TeamRecord         storage.Record
	User               storage.Record
	Organization       Organization
	OrganizationRecord storage.Record
}
```

### `AfterUpdateTeamData`

```go
type AfterUpdateTeamData struct {
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}
```

### `BeforeAddMemberData`

```go
type BeforeAddMemberData struct {
	Member       storage.Record
	User         storage.Record
	Organization Organization
}
```

### `BeforeAddTeamMemberData`

```go
type BeforeAddTeamMemberData struct {
	TeamMember   storage.Record
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}
```

### `BeforeCreateInvitationData`

```go
type BeforeCreateInvitationData struct {
	Invitation   storage.Record
	Inviter      storage.Record
	Organization Organization
}
```

### `BeforeCreateOrganizationData`

```go
type BeforeCreateOrganizationData struct {
	Organization storage.Record
	User         storage.Record
}
```

### `BeforeCreateTeamData`

```go
type BeforeCreateTeamData struct {
	Team               storage.Record
	User               storage.Record
	Organization       Organization
	OrganizationRecord storage.Record
}
```

### `BeforeUpdateTeamData`

```go
type BeforeUpdateTeamData struct {
	Team         storage.Record
	Updates      storage.Record
	User         storage.Record
	Organization storage.Record
}
```

### `CancelInvitationData`

```go
type CancelInvitationData struct {
	Invitation   Invitation
	CancelledBy  storage.Record
	Organization Organization
}
```

### `CancelInvitationInput`

```go
type CancelInvitationInput struct {
	InvitationID string
	UserID       string
}
```

### `CheckOrganizationSlugResult`

```go
type CheckOrganizationSlugResult struct {
	Status bool `json:"status"`
}
```

### `CreateInvitationInput`

```go
type CreateInvitationInput struct {
	OrganizationID       string
	ActiveOrganizationID string
	InviterID            string
	Email                string
	Role                 string
	TeamIDs              []string
}
```

### `CreateOrganizationInput`

CreateOrganizationInput is accepted by the server API and can also be used
directly from a database hook with DatabaseHookContext.Context.

```go
type CreateOrganizationInput struct {
	Name     string
	Slug     string
	UserID   string
	Logo     *string
	Metadata map[string]any
	// Additional carries schema-defined organization input fields. Canonical
	// organization fields above always take precedence.
	Additional storage.Record
	// Internal bypasses AllowUserToCreateOrganization for trusted server calls.
	Internal bool
}
```

### `CreateOrganizationResult`

```go
type CreateOrganizationResult struct {
	Organization
	Members []Member `json:"members"`
	// contains filtered or unexported fields
}
```

## Methods on `CreateOrganizationResult`

### `MarshalJSON`

The result types below anonymously embed custom-marshaling base values.
Explicit marshalers prevent method promotion from hiding their outer fields.

```go
func (value CreateOrganizationResult) MarshalJSON() ([]byte, error)
```

### `DeleteOrganizationHookData`

DeleteOrganizationHookData retains configured additional organization
fields for both delete lifecycle hooks.

```go
type DeleteOrganizationHookData struct {
	Organization storage.Record
	User         storage.Record
}
```

### `DynamicAccessControlOptions`

```go
type DynamicAccessControlOptions struct {
	Enabled bool
	// MaximumRolesPerOrganization is nil for unlimited. A non-nil zero value
	// intentionally prevents creation of any dynamic roles.
	MaximumRolesPerOrganization *int
	// MaximumRolesPerOrganizationFunc takes precedence over the static limit.
	MaximumRolesPerOrganizationFunc func(context.Context, string) (int, error)
}
```

### `FullOrganization`

```go
type FullOrganization struct {
	Organization
	Members     []Member     `json:"members"`
	Invitations []Invitation `json:"invitations"`
	Teams       []Team       `json:"teams,omitempty"`
}
```

## Methods on `FullOrganization`

### `MarshalJSON`

```go
func (value FullOrganization) MarshalJSON() ([]byte, error)
```

### `GetFullOrganizationInput`

```go
type GetFullOrganizationInput struct {
	UserID               string
	ActiveOrganizationID string
	OrganizationID       string
	OrganizationSlug     string
	MembersLimit         *int
}
```

### `GetInvitationInput`

```go
type GetInvitationInput struct {
	InvitationID  string
	UserEmail     string
	EmailVerified bool
}
```

### `HasPermissionResult`

```go
type HasPermissionResult struct {
	Error   any  `json:"error"`
	Success bool `json:"success"`
}
```

### `Invitation`

```go
type Invitation struct {
	ID               string       `json:"id"`
	OrganizationID   string       `json:"organizationId"`
	Email            string       `json:"email"`
	Role             string       `json:"role"`
	Status           string       `json:"status"`
	TeamID           *string      `json:"teamId,omitempty"`
	InviterID        string       `json:"inviterId"`
	ExpiresAt        time.Time    `json:"expiresAt"`
	CreatedAt        time.Time    `json:"createdAt"`
	AdditionalFields model.Fields `json:"-"`
}
```

## Methods on `Invitation`

### `MarshalJSON`

```go
func (value Invitation) MarshalJSON() ([]byte, error)
```

### `InvitationActionData`

```go
type InvitationActionData struct {
	Invitation   Invitation
	User         storage.Record
	Organization Organization
}
```

### `InvitationDetails`

```go
type InvitationDetails struct {
	Invitation
	OrganizationName string `json:"organizationName"`
	OrganizationSlug string `json:"organizationSlug"`
	InviterEmail     string `json:"inviterEmail"`
}
```

## Methods on `InvitationDetails`

### `MarshalJSON`

```go
func (value InvitationDetails) MarshalJSON() ([]byte, error)
```

### `ListMembersResult`

```go
type ListMembersResult struct {
	Members []storage.Record `json:"members"`
	Total   int64            `json:"total"`
}
```

### `MaximumMembersPerTeamData`

```go
type MaximumMembersPerTeamData struct {
	TeamID         string
	OrganizationID string
	Session        TeamSessionData
}
```

### `MaximumTeamsData`

```go
type MaximumTeamsData struct {
	OrganizationID string
	Session        *TeamSessionData
}
```

### `Member`

```go
type Member struct {
	ID               string       `json:"id"`
	OrganizationID   string       `json:"organizationId"`
	UserID           string       `json:"userId"`
	Role             string       `json:"role"`
	CreatedAt        time.Time    `json:"createdAt"`
	User             *MemberUser  `json:"user,omitempty"`
	AdditionalFields model.Fields `json:"-"`
}
```

## Methods on `Member`

### `MarshalJSON`

```go
func (value Member) MarshalJSON() ([]byte, error)
```

### `MemberUser`

MemberUser is the public user projection single-auth attaches to members
returned by organization read APIs. Authentication-only user fields and
configured private fields are intentionally not exposed here.

```go
type MemberUser struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Email string  `json:"email"`
	Image *string `json:"image"`
}
```

### `OptionalNullableString`

```go
type OptionalNullableString struct {
	Present bool
	Value   *string
}
```

## Methods on `OptionalNullableString`

### `UnmarshalJSON`

```go
func (value *OptionalNullableString) UnmarshalJSON(raw []byte) error
```

### `Options`

Options configures the single-auth-compatible organization plugin slice.

```go
type Options struct {
	// CreatorRole defaults to single-auth's "owner" role.
	CreatorRole string
	// AllowUserToCreateOrganization defaults to true. A nil pointer preserves
	// the upstream default while permitting an explicit false value.
	AllowUserToCreateOrganization *bool
	// OrganizationLimit is zero for unlimited.
	OrganizationLimit int
	// DisableOrganizationDeletion removes the delete operation at runtime while
	// keeping the endpoint contract registered, matching single-auth.
	DisableOrganizationDeletion bool
	// MembershipLimit defaults to 100.
	MembershipLimit int
	// InvitationExpiresIn defaults to 48 hours.
	InvitationExpiresIn time.Duration
	// RequireEmailVerificationOnInvitation requires the signed-in recipient to
	// have a verified email before invitation-by-ID actions. A nil value keeps
	// the single-auth default for opaque generated IDs: matching the session
	// email is sufficient. Listing a user's invitations always requires a
	// verified session email because it exposes invitation IDs.
	RequireEmailVerificationOnInvitation *bool
	// AccessControl declares every resource and action understood by custom and
	// dynamic organization roles. single-auth requires this value for dynamic
	// role creation and updates, while ordinary built-in roles work without it.
	AccessControl *authorization.AccessControl
	// Roles replaces the built-in permission-role map when non-nil, matching
	// single-auth's hasPermission resolver. Assignment validation still accepts
	// built-in names plus these configured role names.
	Roles map[string]*authorization.Role
	// DynamicAccessControl enables organization-scoped roles persisted in the
	// organizationRole model and registers the five role CRUD endpoints.
	DynamicAccessControl DynamicAccessControlOptions
	Teams                TeamsOptions
	Hooks                OrganizationHooks
	SendInvitationEmail  func(context.Context, Invitation) error
	// Schema optionally overrides canonical model or field metadata.
	Schema storage.Schema
}
```

### `OrgIDSource`

OrgIDSource selects where RequireOrgRole reads the organization ID.

```go
type OrgIDSource string
```

## Constants associated with `OrgIDSource`

```go
const (
	OrgIDSourceBody  OrgIDSource = "body"
	OrgIDSourceQuery OrgIDSource = "query"
)
```

### `Organization`

```go
type Organization struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Slug             string         `json:"slug"`
	Logo             *string        `json:"logo"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	CreatedAt        time.Time      `json:"createdAt"`
	AdditionalFields model.Fields   `json:"-"`
}
```

## Methods on `Organization`

### `MarshalJSON`

```go
func (value Organization) MarshalJSON() ([]byte, error)
```

### `OrganizationHooks`

OrganizationHooks mirrors the mutation points used by single-auth's
organization CRUD lifecycle. A before hook may return fields to merge into
the pending record; nil means no override.

```go
type OrganizationHooks struct {
	BeforeCreateOrganization func(context.Context, BeforeCreateOrganizationData) (storage.Record, error)
	AfterCreateOrganization  func(context.Context, AfterCreateOrganizationData) error
	BeforeAddMember          func(context.Context, BeforeAddMemberData) (storage.Record, error)
	AfterAddMember           func(context.Context, AfterAddMemberData) error
	BeforeRemoveMember       RemoveMemberHook
	AfterRemoveMember        RemoveMemberHook
	BeforeDeleteOrganization func(context.Context, DeleteOrganizationHookData) error
	AfterDeleteOrganization  func(context.Context, DeleteOrganizationHookData) error
	BeforeUpdateMemberRole   func(context.Context, UpdateMemberRoleBeforeData) (storage.Record, error)
	AfterUpdateMemberRole    func(context.Context, UpdateMemberRoleAfterData) error
	BeforeCreateTeam         func(context.Context, BeforeCreateTeamData) (storage.Record, error)
	AfterCreateTeam          func(context.Context, AfterCreateTeamData) error
	BeforeUpdateTeam         func(context.Context, BeforeUpdateTeamData) (storage.Record, error)
	AfterUpdateTeam          func(context.Context, AfterUpdateTeamData) error
	BeforeDeleteTeam         func(context.Context, TeamLifecycleHookData) error
	AfterDeleteTeam          func(context.Context, TeamLifecycleHookData) error
	BeforeAddTeamMember      func(context.Context, BeforeAddTeamMemberData) (storage.Record, error)
	AfterAddTeamMember       func(context.Context, TeamMemberLifecycleHookData) error
	BeforeRemoveTeamMember   func(context.Context, TeamMemberLifecycleHookData) error
	AfterRemoveTeamMember    func(context.Context, TeamMemberLifecycleHookData) error
	BeforeCreateInvitation   func(context.Context, BeforeCreateInvitationData) (storage.Record, error)
	AfterCreateInvitation    func(context.Context, AfterCreateInvitationData) error
	BeforeAcceptInvitation   func(context.Context, InvitationActionData) error
	AfterAcceptInvitation    func(context.Context, AfterAcceptInvitationData) error
	BeforeRejectInvitation   func(context.Context, InvitationActionData) error
	AfterRejectInvitation    func(context.Context, InvitationActionData) error
	BeforeCancelInvitation   func(context.Context, CancelInvitationData) error
	AfterCancelInvitation    func(context.Context, CancelInvitationData) error
}
```

### `OrganizationRole`

OrganizationRole is the public dynamic-role representation. Additional
schema fields are retained by endpoint responses as storage.Record values.

```go
type OrganizationRole struct {
	ID               string                   `json:"id"`
	OrganizationID   string                   `json:"organizationId"`
	Role             string                   `json:"role"`
	Permission       authorization.Statements `json:"permission"`
	CreatedAt        time.Time                `json:"createdAt"`
	UpdatedAt        *time.Time               `json:"updatedAt,omitempty"`
	AdditionalFields model.Fields             `json:"-"`
}
```

## Methods on `OrganizationRole`

### `MarshalJSON`

```go
func (value OrganizationRole) MarshalJSON() ([]byte, error)
```

### `OrganizationUpdate`

```go
type OrganizationUpdate struct {
	Name     *string
	Slug     *string
	Logo     OptionalNullableString
	Metadata *map[string]any
	// Additional carries schema-defined organization fields for a partial
	// update. Canonical fields above always take precedence.
	Additional storage.Record
}
```

### `Plugin`

Plugin is both the root PluginFactory and the bound server-side API used by
hooks. One Plugin belongs to one single-auth runtime.

```go
type Plugin struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Plugin`

### `MustNew`

```go
func MustNew(options Options) *Plugin
```

### `New`

New validates a reusable organization plugin factory.

```go
func New(options Options) (*Plugin, error)
```

### `NewFactory`

NewFactory is the convenient root-runtime constructor.

```go
func NewFactory(options Options) *Plugin
```

## Methods on `Plugin`

### `AddMember`

AddMember exposes single-auth's server-only addMember API to trusted server
code. Endpoint callers can invoke the same operation by direct API name.

```go
func (plugin *Plugin) AddMember(ctx context.Context, input AddMemberInput) (Member, error)
```

### `Build`

```go
func (plugin *Plugin) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `CreateInvitation`

```go
func (plugin *Plugin) CreateInvitation(
	ctx context.Context,
	input CreateInvitationInput,
) (Invitation, error)
```

### `CreateOrganization`

CreateOrganization exposes single-auth's server-side createOrganization API
to application hooks. Pass DatabaseHookContext.Context to retain request
cancellation and endpoint context.

```go
func (plugin *Plugin) CreateOrganization(
	ctx context.Context,
	input CreateOrganizationInput,
) (CreateOrganizationResult, error)
```

### `GetActiveMember`

```go
func (plugin *Plugin) GetActiveMember(
	ctx context.Context,
	userID string,
	organizationID string,
) (*Member, error)
```

### `GetFullOrganization`

```go
func (plugin *Plugin) GetFullOrganization(
	ctx context.Context,
	input GetFullOrganizationInput,
) (*FullOrganization, error)
```

### `ListOrganizationTeams`

```go
func (plugin *Plugin) ListOrganizationTeams(
	ctx context.Context,
	organizationID string,
) ([]Team, error)
```

### `OrganizationCreatorRole`

OrganizationCreatorRole exposes the configured creator role to peer
authorization plugins without coupling them to organization internals.

```go
func (plugin *Plugin) OrganizationCreatorRole() string
```

### `OrganizationTeamsEnabled`

OrganizationTeamsEnabled exposes whether the optional team models are
present so peer plugins can perform scoped membership cleanup safely.

```go
func (plugin *Plugin) OrganizationTeamsEnabled() bool
```

### `PluginID`

```go
func (*Plugin) PluginID() string
```

### `RemoveMember`

RemoveMember exposes the common trusted member-removal lifecycle to peer
plugins. The before/after hooks surround one transaction containing member
deletion, organization-scoped team cleanup, and the optional related
mutation.

```go
func (plugin *Plugin) RemoveMember(ctx context.Context, input RemoveMemberInput) (Member, error)
```

### `RequireOrgRole`

RequireOrgRole builds endpoint-local middleware equivalent to single-auth's
requireOrgRole. The Plugin must also be installed on the Auth runtime that
owns the endpoint.

```go
func (plugin *Plugin) RequireOrgRole(options RequireOrgRoleOptions) (engine.EndpointMiddlewareFunc, error)
```

### `Schema`

```go
func (plugin *Plugin) Schema() (storage.Schema, error)
```

### `SetActiveOrganization`

```go
func (plugin *Plugin) SetActiveOrganization(
	ctx context.Context,
	input SetActiveOrganizationInput,
) (*Organization, error)
```

### `UpdateOrganization`

```go
func (plugin *Plugin) UpdateOrganization(
	ctx context.Context,
	input UpdateOrganizationInput,
) (Organization, error)
```

### `RejectInvitationInput`

```go
type RejectInvitationInput struct {
	InvitationID  string
	UserID        string
	UserEmail     string
	EmailVerified bool
}
```

### `RejectInvitationResult`

```go
type RejectInvitationResult struct {
	Invitation Invitation `json:"invitation"`
	Member     *Member    `json:"member"`
}
```

### `RemoveMemberHook`

RemoveMemberHook observes or rejects organization member removal. Hooks do
not override data.

```go
type RemoveMemberHook func(context.Context, RemoveMemberHookData) error
```

### `RemoveMemberHookData`

RemoveMemberHookData is the exact pre-removal database payload shared by
beforeRemoveMember and afterRemoveMember. Records intentionally retain
configured additional fields, matching single-auth's intersection types.

```go
type RemoveMemberHookData struct {
	Member       storage.Record
	User         storage.Record
	Organization storage.Record
}
```

### `RemoveMemberInput`

RemoveMemberInput is the trusted server-side organization member removal
contract. TransactionMutation lets a peer plugin include its own related
storage mutation in the exact same transaction as member and team cleanup;
it must use only the supplied transaction adapter. AfterTransaction runs
after commit and before AfterRemoveMember.

```go
type RemoveMemberInput struct {
	MemberID            string
	OrganizationID      string
	UserID              string
	TransactionMutation func(context.Context, storage.TransactionAdapter) error
	AfterTransaction    func(context.Context) error
}
```

### `RequireOrgRoleOptions`

RequireOrgRoleOptions configures organization membership authorization for
one endpoint. An empty AllowedRoles slice accepts any organization member.

```go
type RequireOrgRoleOptions struct {
	OrgIDParam   string
	OrgIDSource  OrgIDSource
	AllowedRoles []string
}
```

### `SessionAdditionalFields`

SessionAdditionalFields is the statically inferred session contribution of
the organization plugin.

```go
type SessionAdditionalFields struct {
	ActiveOrganizationID model.Value[string]
}
```

## Constructors and functions for `SessionAdditionalFields`

### `DecodeSessionAdditionalFields`

```go
func DecodeSessionAdditionalFields(fields model.Fields) (SessionAdditionalFields, error)
```

### `SetActiveOrganizationInput`

```go
type SetActiveOrganizationInput struct {
	UserID           string
	SessionToken     string
	OrganizationID   *string
	OrganizationSlug string
	Clear            bool
}
```

### `Team`

```go
type Team struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	OrganizationID   string       `json:"organizationId"`
	CreatedAt        time.Time    `json:"createdAt"`
	UpdatedAt        *time.Time   `json:"updatedAt,omitempty"`
	AdditionalFields model.Fields `json:"-"`
}
```

## Methods on `Team`

### `MarshalJSON`

```go
func (value Team) MarshalJSON() ([]byte, error)
```

### `TeamLifecycleHookData`

```go
type TeamLifecycleHookData struct {
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}
```

### `TeamMember`

```go
type TeamMember struct {
	ID               string       `json:"id"`
	TeamID           string       `json:"teamId"`
	UserID           string       `json:"userId"`
	CreatedAt        *time.Time   `json:"createdAt,omitempty"`
	AdditionalFields model.Fields `json:"-"`
}
```

## Methods on `TeamMember`

### `MarshalJSON`

```go
func (value TeamMember) MarshalJSON() ([]byte, error)
```

### `TeamMemberLifecycleHookData`

```go
type TeamMemberLifecycleHookData struct {
	TeamMember   storage.Record
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}
```

### `TeamSessionData`

```go
type TeamSessionData struct {
	Session storage.Record
	User    storage.Record
}
```

### `TeamsOptions`

```go
type TeamsOptions struct {
	Enabled            bool
	DefaultTeamEnabled *bool
	// CustomCreateDefaultTeam replaces the built-in default-team insert. The
	// transaction adapter is supplied so implementations remain atomic with
	// organization creation.
	CustomCreateDefaultTeam func(context.Context, storage.TransactionAdapter, storage.Record) (storage.Record, error)
	// MaximumTeams is zero for unlimited. MaximumTeamsFunc takes precedence
	// when configured and is evaluated for every create-team request.
	MaximumTeams     int
	MaximumTeamsFunc func(context.Context, MaximumTeamsData) (int, error)
	// MaximumMembersPerTeam distinguishes an unset unlimited value from an
	// explicit zero-member limit. The callback takes precedence when present.
	MaximumMembersPerTeam     *int
	MaximumMembersPerTeamFunc func(context.Context, MaximumMembersPerTeamData) (int, error)
	AllowRemovingAllTeams     bool
}
```

### `TypedDirectAPI`

TypedDirectAPI preserves organization-specific server methods as a concrete
API value suitable for composition with other differently shaped plugins.

```go
type TypedDirectAPI struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedDirectAPI`

### `BindTypedDirectAPI`

```go
func BindTypedDirectAPI(plugin *Plugin) TypedDirectAPI
```

## Methods on `TypedDirectAPI`

### `CreateOrganization`

```go
func (api TypedDirectAPI) CreateOrganization(
	ctx context.Context,
	input CreateOrganizationInput,
) (CreateOrganizationResult, error)
```

### `UpdateMemberRoleAfterData`

```go
type UpdateMemberRoleAfterData struct {
	Member       storage.Record
	PreviousRole string
	User         storage.Record
	Organization storage.Record
}
```

### `UpdateMemberRoleBeforeData`

UpdateMemberRoleBeforeData is passed to BeforeUpdateMemberRole. Returning a
record containing role overrides the canonical role selected by the caller.

```go
type UpdateMemberRoleBeforeData struct {
	Member       storage.Record
	NewRole      string
	User         storage.Record
	Organization storage.Record
}
```

### `UpdateOrganizationInput`

```go
type UpdateOrganizationInput struct {
	OrganizationID       string
	ActiveOrganizationID string
	UserID               string
	Data                 OrganizationUpdate
}
```

### `UserInvitation`

```go
type UserInvitation struct {
	Invitation
	OrganizationName string `json:"organizationName"`
}
```

## Methods on `UserInvitation`

### `MarshalJSON`

```go
func (value UserInvitation) MarshalJSON() ([]byte, error)
```

