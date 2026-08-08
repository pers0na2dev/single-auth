package organization

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// Options configures the single-auth-compatible organization plugin slice.
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

type DynamicAccessControlOptions struct {
	Enabled bool
	// MaximumRolesPerOrganization is nil for unlimited. A non-nil zero value
	// intentionally prevents creation of any dynamic roles.
	MaximumRolesPerOrganization *int
	// MaximumRolesPerOrganizationFunc takes precedence over the static limit.
	MaximumRolesPerOrganizationFunc func(context.Context, string) (int, error)
}

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

type TeamSessionData struct {
	Session storage.Record
	User    storage.Record
}

type MaximumTeamsData struct {
	OrganizationID string
	Session        *TeamSessionData
}

type MaximumMembersPerTeamData struct {
	TeamID         string
	OrganizationID string
	Session        TeamSessionData
}

type BeforeCreateOrganizationData struct {
	Organization storage.Record
	User         storage.Record
}

type AfterCreateOrganizationData struct {
	Organization Organization
	Member       Member
	User         storage.Record
}

type BeforeAddMemberData struct {
	Member       storage.Record
	User         storage.Record
	Organization Organization
}

type AfterAddMemberData struct {
	Member       Member
	User         storage.Record
	Organization Organization
}

// RemoveMemberHookData is the exact pre-removal database payload shared by
// beforeRemoveMember and afterRemoveMember. Records intentionally retain
// configured additional fields, matching single-auth's intersection types.
type RemoveMemberHookData struct {
	Member       storage.Record
	User         storage.Record
	Organization storage.Record
}

// RemoveMemberHook observes or rejects organization member removal. Hooks do
// not override data.
type RemoveMemberHook func(context.Context, RemoveMemberHookData) error

// DeleteOrganizationHookData retains configured additional organization
// fields for both delete lifecycle hooks.
type DeleteOrganizationHookData struct {
	Organization storage.Record
	User         storage.Record
}

// UpdateMemberRoleBeforeData is passed to BeforeUpdateMemberRole. Returning a
// record containing role overrides the canonical role selected by the caller.
type UpdateMemberRoleBeforeData struct {
	Member       storage.Record
	NewRole      string
	User         storage.Record
	Organization storage.Record
}

type UpdateMemberRoleAfterData struct {
	Member       storage.Record
	PreviousRole string
	User         storage.Record
	Organization storage.Record
}

type BeforeCreateTeamData struct {
	Team               storage.Record
	User               storage.Record
	Organization       Organization
	OrganizationRecord storage.Record
}

type AfterCreateTeamData struct {
	Team               Team
	TeamRecord         storage.Record
	User               storage.Record
	Organization       Organization
	OrganizationRecord storage.Record
}

type BeforeUpdateTeamData struct {
	Team         storage.Record
	Updates      storage.Record
	User         storage.Record
	Organization storage.Record
}

type AfterUpdateTeamData struct {
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}

type TeamLifecycleHookData struct {
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}

type BeforeAddTeamMemberData struct {
	TeamMember   storage.Record
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}

type TeamMemberLifecycleHookData struct {
	TeamMember   storage.Record
	Team         storage.Record
	User         storage.Record
	Organization storage.Record
}

type BeforeCreateInvitationData struct {
	Invitation   storage.Record
	Inviter      storage.Record
	Organization Organization
}

type AfterCreateInvitationData struct {
	Invitation   Invitation
	Inviter      storage.Record
	Organization Organization
}

type InvitationActionData struct {
	Invitation   Invitation
	User         storage.Record
	Organization Organization
}

type AfterAcceptInvitationData struct {
	Invitation   Invitation
	Member       Member
	User         storage.Record
	Organization Organization
}

type CancelInvitationData struct {
	Invitation   Invitation
	CancelledBy  storage.Record
	Organization Organization
}

// OrganizationHooks mirrors the mutation points used by single-auth's
// organization CRUD lifecycle. A before hook may return fields to merge into
// the pending record; nil means no override.
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

// CreateOrganizationInput is accepted by the server API and can also be used
// directly from a database hook with DatabaseHookContext.Context.
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

type Organization struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Slug             string         `json:"slug"`
	Logo             *string        `json:"logo"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	CreatedAt        time.Time      `json:"createdAt"`
	AdditionalFields model.Fields   `json:"-"`
}

type Member struct {
	ID               string       `json:"id"`
	OrganizationID   string       `json:"organizationId"`
	UserID           string       `json:"userId"`
	Role             string       `json:"role"`
	CreatedAt        time.Time    `json:"createdAt"`
	User             *MemberUser  `json:"user,omitempty"`
	AdditionalFields model.Fields `json:"-"`
}

// MemberUser is the public user projection single-auth attaches to members
// returned by organization read APIs. Authentication-only user fields and
// configured private fields are intentionally not exposed here.
type MemberUser struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Email string  `json:"email"`
	Image *string `json:"image"`
}

type CreateOrganizationResult struct {
	Organization
	Members []Member `json:"members"`

	defaultTeamID string
}

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

type InvitationDetails struct {
	Invitation
	OrganizationName string `json:"organizationName"`
	OrganizationSlug string `json:"organizationSlug"`
	InviterEmail     string `json:"inviterEmail"`
}

type UserInvitation struct {
	Invitation
	OrganizationName string `json:"organizationName"`
}

type AcceptInvitationResult struct {
	Invitation Invitation `json:"invitation"`
	Member     Member     `json:"member"`
}

type RejectInvitationResult struct {
	Invitation Invitation `json:"invitation"`
	Member     *Member    `json:"member"`
}

type Team struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	OrganizationID   string       `json:"organizationId"`
	CreatedAt        time.Time    `json:"createdAt"`
	UpdatedAt        *time.Time   `json:"updatedAt,omitempty"`
	AdditionalFields model.Fields `json:"-"`
}

type TeamMember struct {
	ID               string       `json:"id"`
	TeamID           string       `json:"teamId"`
	UserID           string       `json:"userId"`
	CreatedAt        *time.Time   `json:"createdAt,omitempty"`
	AdditionalFields model.Fields `json:"-"`
}

// OrganizationRole is the public dynamic-role representation. Additional
// schema fields are retained by endpoint responses as storage.Record values.
type OrganizationRole struct {
	ID               string                   `json:"id"`
	OrganizationID   string                   `json:"organizationId"`
	Role             string                   `json:"role"`
	Permission       authorization.Statements `json:"permission"`
	CreatedAt        time.Time                `json:"createdAt"`
	UpdatedAt        *time.Time               `json:"updatedAt,omitempty"`
	AdditionalFields model.Fields             `json:"-"`
}

type FullOrganization struct {
	Organization
	Members     []Member     `json:"members"`
	Invitations []Invitation `json:"invitations"`
	Teams       []Team       `json:"teams,omitempty"`
}

type CheckOrganizationSlugResult struct {
	Status bool `json:"status"`
}

type ListMembersResult struct {
	Members []storage.Record `json:"members"`
	Total   int64            `json:"total"`
}

type ActiveMemberRoleResult struct {
	Role string `json:"role"`
}

type HasPermissionResult struct {
	Error   any  `json:"error"`
	Success bool `json:"success"`
}

type GetFullOrganizationInput struct {
	UserID               string
	ActiveOrganizationID string
	OrganizationID       string
	OrganizationSlug     string
	MembersLimit         *int
}

type SetActiveOrganizationInput struct {
	UserID           string
	SessionToken     string
	OrganizationID   *string
	OrganizationSlug string
	Clear            bool
}

type OptionalNullableString struct {
	Present bool
	Value   *string
}

func (value *OptionalNullableString) UnmarshalJSON(raw []byte) error {
	value.Present = true
	if string(raw) == "null" {
		value.Value = nil
		return nil
	}
	var decoded string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	value.Value = &decoded
	return nil
}

type OrganizationUpdate struct {
	Name     *string
	Slug     *string
	Logo     OptionalNullableString
	Metadata *map[string]any
	// Additional carries schema-defined organization fields for a partial
	// update. Canonical fields above always take precedence.
	Additional storage.Record
}

type UpdateOrganizationInput struct {
	OrganizationID       string
	ActiveOrganizationID string
	UserID               string
	Data                 OrganizationUpdate
}

type CreateInvitationInput struct {
	OrganizationID       string
	ActiveOrganizationID string
	InviterID            string
	Email                string
	Role                 string
	TeamIDs              []string
}

type AcceptInvitationInput struct {
	InvitationID  string
	UserID        string
	UserEmail     string
	EmailVerified bool
	SessionToken  string
}

type RejectInvitationInput struct {
	InvitationID  string
	UserID        string
	UserEmail     string
	EmailVerified bool
}

type CancelInvitationInput struct {
	InvitationID string
	UserID       string
}

type GetInvitationInput struct {
	InvitationID  string
	UserEmail     string
	EmailVerified bool
}

// AddMemberInput is accepted by the server-only addMember API. Roles are
// persisted in single-auth's canonical comma-separated representation.
type AddMemberInput struct {
	OrganizationID string
	UserID         string
	Roles          []string
}

// RemoveMemberInput is the trusted server-side organization member removal
// contract. TransactionMutation lets a peer plugin include its own related
// storage mutation in the exact same transaction as member and team cleanup;
// it must use only the supplied transaction adapter. AfterTransaction runs
// after commit and before AfterRemoveMember.
type RemoveMemberInput struct {
	MemberID            string
	OrganizationID      string
	UserID              string
	TransactionMutation func(context.Context, storage.TransactionAdapter) error
	AfterTransaction    func(context.Context) error
}

// OrgIDSource selects where RequireOrgRole reads the organization ID.
type OrgIDSource string

const (
	OrgIDSourceBody  OrgIDSource = "body"
	OrgIDSourceQuery OrgIDSource = "query"
)

// RequireOrgRoleOptions configures organization membership authorization for
// one endpoint. An empty AllowedRoles slice accepts any organization member.
type RequireOrgRoleOptions struct {
	OrgIDParam   string
	OrgIDSource  OrgIDSource
	AllowedRoles []string
}

// Plugin is both the root PluginFactory and the bound server-side API used by
// hooks. One Plugin belongs to one single-auth runtime.
type Plugin struct {
	options Options
	schema  storage.Schema

	mu      sync.RWMutex
	runtime *runtime
}

type runtime struct {
	adapter                              storage.Adapter
	schema                               storage.Schema
	resolveSession                       sessionResolver
	hasPlugin                            func(string) bool
	clock                                func() time.Time
	creatorRole                          string
	requireEmailVerificationOnInvitation bool
	options                              Options
	refreshSession                       func(*engine.Context, storage.Record, storage.Record) error

	invitationLocks   [64]sync.Mutex
	organizationLocks [64]sync.Mutex
}

type resolvedSession struct {
	Session storage.Record
	User    storage.Record
}

type sessionResolver func(*engine.Context, bool) (*resolvedSession, error)

const verifiedMemberContextKey = "organization.verifiedMember"

// VerifiedMemberFromContext returns the member record established by
// RequireOrgRole. The returned map is independent from request-local state.
func VerifiedMemberFromContext(ctx *engine.Context) (storage.Record, bool) {
	if ctx == nil {
		return nil, false
	}
	value, ok := ctx.Value(verifiedMemberContextKey)
	member, ok := value.(storage.Record)
	if !ok || member == nil {
		return nil, false
	}
	return cloneRecord(member), true
}

func cloneRecord(input storage.Record) storage.Record {
	if input == nil {
		return nil
	}
	result := make(storage.Record, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
