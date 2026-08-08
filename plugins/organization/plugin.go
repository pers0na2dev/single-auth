package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/storage"
)

// New validates a reusable organization plugin factory.
func New(options Options) (*Plugin, error) {
	if options.MembershipLimit < 0 {
		return nil, errors.New("organization: membership limit must not be negative")
	}
	if options.OrganizationLimit < 0 {
		return nil, errors.New("organization: organization limit must not be negative")
	}
	if options.InvitationExpiresIn < 0 {
		return nil, errors.New("organization: invitation expiry must not be negative")
	}
	if options.Teams.MaximumTeams < 0 {
		return nil, errors.New("organization: maximum teams must not be negative")
	}
	if options.Teams.MaximumMembersPerTeam != nil && *options.Teams.MaximumMembersPerTeam < 0 {
		return nil, errors.New("organization: maximum team members must not be negative")
	}
	if options.DynamicAccessControl.MaximumRolesPerOrganization != nil &&
		*options.DynamicAccessControl.MaximumRolesPerOrganization < 0 {
		return nil, errors.New("organization: maximum roles must not be negative")
	}
	options.Roles = cloneOrganizationRoles(options.Roles)
	if options.AccessControl != nil {
		options.AccessControl = authorization.CreateAccessControl(options.AccessControl.Statements())
	}
	schema, err := Schema(options)
	if err != nil {
		return nil, err
	}
	options.Schema = options.Schema.Clone()
	if options.CreatorRole == "" {
		options.CreatorRole = "owner"
	}
	if options.AllowUserToCreateOrganization == nil {
		allowed := true
		options.AllowUserToCreateOrganization = &allowed
	}
	if options.MembershipLimit == 0 {
		options.MembershipLimit = 100
	}
	if options.InvitationExpiresIn == 0 {
		options.InvitationExpiresIn = 48 * time.Hour
	}
	return &Plugin{options: options, schema: schema}, nil
}

// NewFactory is the convenient root-runtime constructor.
func NewFactory(options Options) *Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

func MustNew(options Options) *Plugin { return NewFactory(options) }

func (*Plugin) PluginID() string { return "organization" }

// OrganizationCreatorRole exposes the configured creator role to peer
// authorization plugins without coupling them to organization internals.
func (plugin *Plugin) OrganizationCreatorRole() string {
	if plugin == nil || plugin.options.CreatorRole == "" {
		return "owner"
	}
	return plugin.options.CreatorRole
}

// OrganizationTeamsEnabled exposes whether the optional team models are
// present so peer plugins can perform scoped membership cleanup safely.
func (plugin *Plugin) OrganizationTeamsEnabled() bool {
	return plugin != nil && plugin.options.Teams.Enabled
}

func (plugin *Plugin) Schema() (storage.Schema, error) {
	if plugin == nil {
		return storage.Schema{}, errors.New("organization: plugin is nil")
	}
	return plugin.schema.Clone(), nil
}

func (plugin *Plugin) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if plugin == nil {
		return engine.Plugin{}, errors.New("organization: plugin is nil")
	}
	if host.Adapter == nil {
		return engine.Plugin{}, errors.New("organization: host adapter is required")
	}
	clock := host.Clock
	if clock == nil {
		clock = time.Now
	}
	implementation := &runtime{
		adapter: host.Adapter, schema: plugin.schema.Clone(), clock: clock,
		creatorRole: plugin.options.CreatorRole,
		hasPlugin:   host.HasPlugin,
		options:     plugin.options,
	}
	implementation.requireEmailVerificationOnInvitation = host.Options.GenerateID != nil
	if plugin.options.RequireEmailVerificationOnInvitation != nil {
		implementation.requireEmailVerificationOnInvitation =
			*plugin.options.RequireEmailVerificationOnInvitation
	}
	implementation.resolveSession = func(endpoint *engine.Context, required bool) (*resolvedSession, error) {
		if endpoint == nil {
			return nil, contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		}
		mode := singleauth.PluginSessionOptional
		if required {
			mode = singleauth.PluginSessionRequired
		}
		state, err := host.ResolveSession(endpoint, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &resolvedSession{
			Session: cloneRecord(state.Session),
			User:    cloneRecord(state.User),
		}, nil
	}
	implementation.refreshSession = func(endpoint *engine.Context, session, user storage.Record) error {
		return host.RefreshSession(endpoint, singleauth.PluginSessionState{
			Session: cloneRecord(session), User: cloneRecord(user),
		}, false)
	}

	plugin.mu.Lock()
	if plugin.runtime != nil {
		plugin.mu.Unlock()
		return engine.Plugin{}, errors.New("organization: plugin factory is already bound")
	}
	plugin.runtime = implementation
	plugin.mu.Unlock()

	built := engine.Plugin{
		ID: "organization", Version: Version, Schema: plugin.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{
				Name: "checkOrganizationSlug", Path: "/organization/check-slug",
				Methods: []string{http.MethodPost}, OperationID: "checkOrganizationSlug",
				Handler: implementation.checkOrganizationSlugEndpoint,
			},
			{
				Name: "createOrganization", Path: "/organization/create",
				Methods: []string{http.MethodPost}, OperationID: "createOrganization",
				Handler: implementation.createOrganizationEndpoint,
			},
			{
				Name: "getFullOrganization", Path: "/organization/get-full-organization",
				Methods: []string{http.MethodGet}, OperationID: "getOrganization",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.getFullOrganizationEndpoint,
			},
			{
				Name: "setActiveOrganization", Path: "/organization/set-active",
				Methods: []string{http.MethodPost}, OperationID: "setActiveOrganization",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.setActiveOrganizationEndpoint,
			},
			{
				Name: "updateOrganization", Path: "/organization/update",
				Methods: []string{http.MethodPost}, OperationID: "updateOrganization",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.updateOrganizationEndpoint,
			},
			{
				Name: "deleteOrganization", Path: "/organization/delete",
				Methods: []string{http.MethodPost}, OperationID: "deleteOrganization",
				Handler: implementation.deleteOrganizationEndpoint,
			},
			{
				Name: "listOrganizations", Path: "/organization/list",
				Methods: []string{http.MethodGet}, OperationID: "listOrganizations",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.listOrganizationsEndpoint,
			},
			{
				Name: "createInvitation", Path: "/organization/invite-member",
				Methods: []string{http.MethodPost}, OperationID: "createOrganizationInvitation",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.createInvitationEndpoint,
			},
			{
				Name: "acceptInvitation", Path: "/organization/accept-invitation",
				Methods: []string{http.MethodPost}, OperationID: "acceptInvitation",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.acceptInvitationEndpoint,
			},
			{
				Name: "rejectInvitation", Path: "/organization/reject-invitation",
				Methods: []string{http.MethodPost}, OperationID: "rejectInvitation",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.rejectInvitationEndpoint,
			},
			{
				Name: "cancelInvitation", Path: "/organization/cancel-invitation",
				Methods: []string{http.MethodPost}, OperationID: "cancelOrganizationInvitation",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.cancelInvitationEndpoint,
			},
			{
				Name: "getInvitation", Path: "/organization/get-invitation",
				Methods: []string{http.MethodGet}, OperationID: "getInvitation",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.getInvitationEndpoint,
			},
			{
				Name: "listInvitations", Path: "/organization/list-invitations",
				Methods: []string{http.MethodGet}, OperationID: "listInvitations",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.listInvitationsEndpoint,
			},
			{
				Name: "listUserInvitations", Path: "/organization/list-user-invitations",
				Methods: []string{http.MethodGet}, OperationID: "listUserInvitations",
				Handler: implementation.listUserInvitationsEndpoint,
			},
			{
				Name: "createTeam", Path: "/organization/create-team",
				Methods: []string{http.MethodPost}, OperationID: "createTeam",
				Handler: implementation.createTeamEndpoint,
			},
			{
				Name: "removeTeam", Path: "/organization/remove-team",
				Methods: []string{http.MethodPost}, OperationID: "removeTeam",
				Handler: implementation.removeTeamEndpoint,
			},
			{
				Name: "updateTeam", Path: "/organization/update-team",
				Methods: []string{http.MethodPost}, OperationID: "updateTeam",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.updateTeamEndpoint,
			},
			{
				Name: "listOrganizationTeams", Path: "/organization/list-teams",
				Methods: []string{http.MethodGet}, OperationID: "listOrganizationTeams",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.listOrganizationTeamsEndpoint,
			},
			{
				Name: "setActiveTeam", Path: "/organization/set-active-team",
				Methods: []string{http.MethodPost}, OperationID: "setActiveTeam",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.setActiveTeamEndpoint,
			},
			{
				Name: "listUserTeams", Path: "/organization/list-user-teams",
				Methods: []string{http.MethodGet}, OperationID: "listUserTeams",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.listUserTeamsEndpoint,
			},
			{
				Name: "listTeamMembers", Path: "/organization/list-team-members",
				Methods: []string{http.MethodGet}, OperationID: "listTeamMembers",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.listTeamMembersEndpoint,
			},
			{
				Name: "addTeamMember", Path: "/organization/add-team-member",
				Methods: []string{http.MethodPost}, OperationID: "addTeamMember",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.addTeamMemberEndpoint,
			},
			{
				Name: "removeTeamMember", Path: "/organization/remove-team-member",
				Methods: []string{http.MethodPost}, OperationID: "removeTeamMember",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.removeTeamMemberEndpoint,
			},
			{
				Name: "getActiveMember", Path: "/organization/get-active-member",
				Methods: []string{http.MethodGet}, OperationID: "getActiveMember",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.getActiveMemberEndpoint,
			},
			{
				Name: "updateMemberRole", Path: "/organization/update-member-role",
				Methods: []string{http.MethodPost}, OperationID: "updateOrganizationMemberRole",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.updateMemberRoleEndpoint,
			},
			{
				Name: "leaveOrganization", Path: "/organization/leave",
				Methods: []string{http.MethodPost}, OperationID: "leaveOrganization",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.leaveOrganizationEndpoint,
			},
			{
				Name: "listMembers", Path: "/organization/list-members",
				Methods: []string{http.MethodGet}, OperationID: "listOrganizationMembers",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.listMembersEndpoint,
			},
			{
				Name: "getActiveMemberRole", Path: "/organization/get-active-member-role",
				Methods: []string{http.MethodGet}, OperationID: "getActiveMemberRole",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.getActiveMemberRoleEndpoint,
			},
			{
				Name: "hasPermission", Path: "/organization/has-permission",
				Methods: []string{http.MethodPost}, OperationID: "hasOrganizationPermission",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.hasPermissionEndpoint,
			},
			{
				Name: "addMember", ServerOnly: true,
				Methods: []string{http.MethodPost}, OperationID: "addOrganizationMember",
				Handler: implementation.addMemberEndpoint,
			},
			{
				Name: "removeMember", Path: "/organization/remove-member",
				Methods: []string{http.MethodPost}, OperationID: "removeOrganizationMember",
				Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
				Handler: implementation.removeMemberEndpoint,
			},
		},
		ErrorCodes: pluginErrorCodes(),
	}
	if !plugin.options.Teams.Enabled {
		filtered := make([]engine.Endpoint, 0, len(built.Endpoints)-9)
		for _, endpoint := range built.Endpoints {
			switch endpoint.Name {
			case "createTeam", "removeTeam", "updateTeam", "listOrganizationTeams",
				"setActiveTeam", "listUserTeams", "listTeamMembers", "addTeamMember", "removeTeamMember":
				continue
			default:
				filtered = append(filtered, endpoint)
			}
		}
		built.Endpoints = filtered
	}
	if plugin.options.DynamicAccessControl.Enabled {
		built.Endpoints = append(built.Endpoints, dynamicAccessControlEndpoints(implementation)...)
	}
	return built, nil
}

// CreateOrganization exposes single-auth's server-side createOrganization API
// to application hooks. Pass DatabaseHookContext.Context to retain request
// cancellation and endpoint context.
func (plugin *Plugin) CreateOrganization(
	ctx context.Context,
	input CreateOrganizationInput,
) (CreateOrganizationResult, error) {
	if plugin == nil {
		return CreateOrganizationResult{}, errors.New("organization: plugin is nil")
	}
	plugin.mu.RLock()
	implementation := plugin.runtime
	plugin.mu.RUnlock()
	if implementation == nil {
		return CreateOrganizationResult{}, errors.New("organization: plugin is not bound to single-auth")
	}
	input.Internal = true
	return implementation.createOrganization(ctx, input)
}

// AddMember exposes single-auth's server-only addMember API to trusted server
// code. Endpoint callers can invoke the same operation by direct API name.
func (plugin *Plugin) AddMember(ctx context.Context, input AddMemberInput) (Member, error) {
	if plugin == nil {
		return Member{}, errors.New("organization: plugin is nil")
	}
	plugin.mu.RLock()
	implementation := plugin.runtime
	plugin.mu.RUnlock()
	if implementation == nil {
		return Member{}, errors.New("organization: plugin is not bound to single-auth")
	}
	return implementation.addMember(ctx, input)
}

// RemoveMember exposes the common trusted member-removal lifecycle to peer
// plugins. The before/after hooks surround one transaction containing member
// deletion, organization-scoped team cleanup, and the optional related
// mutation.
func (plugin *Plugin) RemoveMember(ctx context.Context, input RemoveMemberInput) (Member, error) {
	if plugin == nil {
		return Member{}, errors.New("organization: plugin is nil")
	}
	plugin.mu.RLock()
	implementation := plugin.runtime
	plugin.mu.RUnlock()
	if implementation == nil {
		return Member{}, errors.New("organization: plugin is not bound to single-auth")
	}
	return implementation.removeMemberLifecycle(ctx, input)
}

type createOrganizationBody struct {
	Name                          string         `json:"name"`
	Slug                          string         `json:"slug"`
	UserID                        string         `json:"userId"`
	Logo                          *string        `json:"logo"`
	Metadata                      map[string]any `json:"metadata"`
	KeepCurrentActiveOrganization bool           `json:"keepCurrentActiveOrganization"`
}

func (runtime *runtime) createOrganizationEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body createOrganizationBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		).WithCause(err)
	}
	rawBody, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	userID := ""
	internal := false
	var session *resolvedSession
	state, err := runtime.resolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if state != nil && state.Session != nil && state.User != nil {
		session = state
		userID, _ = recordString(session.User, "id")
	} else if ctx.IsDirect() && body.UserID != "" {
		userID = body.UserID
		internal = true
	} else {
		return contract.Response{}, unauthorizedOrganization()
	}
	result, err := runtime.createOrganization(ctx.GoContext(), CreateOrganizationInput{
		Name: body.Name, Slug: body.Slug, UserID: userID,
		Logo: body.Logo, Metadata: cloneMap(body.Metadata), Additional: rawBody, Internal: internal,
	})
	if err != nil {
		return contract.Response{}, err
	}
	if session != nil && !body.KeepCurrentActiveOrganization {
		token, _ := recordString(session.Session, "token")
		if err := runtime.setSessionActiveOrganization(ctx.GoContext(), token, &result.ID); err != nil {
			return contract.Response{}, err
		}
		if result.defaultTeamID != "" {
			if err := runtime.setSessionActiveTeam(ctx.GoContext(), token, &result.defaultTeamID); err != nil {
				return contract.Response{}, err
			}
		}
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) createOrganization(
	ctx context.Context,
	input CreateOrganizationInput,
) (CreateOrganizationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if input.Name == "" || input.Slug == "" {
		return CreateOrganizationResult{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		)
	}
	if input.UserID == "" {
		return CreateOrganizationResult{}, contract.NewAPIError(
			contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized",
		)
	}
	if !input.Internal && runtime.options.AllowUserToCreateOrganization != nil && !*runtime.options.AllowUserToCreateOrganization {
		return CreateOrganizationResult{}, organizationError(
			contract.StatusForbidden, ErrorOrganizationCreateForbidden,
		)
	}
	additional, err := runtime.organizationAdditionalInput(input.Additional, false)
	if err != nil {
		return CreateOrganizationResult{}, err
	}

	var result CreateOrganizationResult
	create := func(adapter storage.TransactionAdapter) error {
		user, err := adapter.FindOne(ctx, storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: input.UserID}},
		})
		if err != nil {
			return err
		}
		if user == nil {
			return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		}
		if runtime.options.OrganizationLimit > 0 {
			memberships, listErr := adapter.FindMany(ctx, storage.FindManyParams{
				Model: "member", Where: []storage.Where{{Field: "userId", Value: input.UserID}},
			})
			if listErr != nil {
				return listErr
			}
			if len(memberships) >= runtime.options.OrganizationLimit {
				return organizationError(contract.StatusForbidden, ErrorOrganizationLimitReached)
			}
		}
		existing, err := adapter.FindOne(ctx, storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "slug", Value: input.Slug}},
		})
		if err != nil {
			return err
		}
		if existing != nil {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationAlreadyExists)
		}

		organizationData := cloneRecord(additional)
		if organizationData == nil {
			organizationData = storage.Record{}
		}
		organizationData["name"] = input.Name
		organizationData["slug"] = input.Slug
		if input.Logo != nil {
			organizationData["logo"] = *input.Logo
		}
		if input.Metadata != nil {
			organizationData["metadata"] = cloneMap(input.Metadata)
		}
		if runtime.options.Hooks.BeforeCreateOrganization != nil {
			override, hookErr := runtime.options.Hooks.BeforeCreateOrganization(ctx, BeforeCreateOrganizationData{
				Organization: cloneRecord(organizationData), User: cloneRecord(user),
			})
			if hookErr != nil {
				return hookErr
			}
			mergeRecord(organizationData, override)
		}
		if metadata, ok := organizationData["metadata"].(map[string]any); ok {
			encoded, encodeErr := json.Marshal(metadata)
			if encodeErr != nil {
				return encodeErr
			}
			organizationData["metadata"] = string(encoded)
		}
		// single-auth appends createdAt only after beforeCreateOrganization has
		// returned, so the hook neither observes nor overrides this lifecycle
		// field.
		organizationData["createdAt"] = runtime.clock()
		createdOrganization, err := adapter.Create(ctx, storage.CreateParams{
			Model: "organization", Data: organizationData,
		})
		if errors.Is(err, storage.ErrUniqueConstraint) {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationAlreadyExists)
		}
		if err != nil {
			return err
		}
		organizationID, _ := recordString(createdOrganization, "id")
		memberData := storage.Record{
			"organizationId": organizationID,
			"userId":         input.UserID,
			"role":           runtime.creatorRole,
		}
		organization := runtime.organizationFromRecord(createdOrganization)
		if runtime.options.Hooks.BeforeAddMember != nil {
			override, hookErr := runtime.options.Hooks.BeforeAddMember(ctx, BeforeAddMemberData{
				Member: cloneRecord(memberData), User: cloneRecord(user), Organization: organization,
			})
			if hookErr != nil {
				return hookErr
			}
			mergeRecord(memberData, override)
		}
		memberData["createdAt"] = runtime.clock()
		createdMember, err := adapter.Create(ctx, storage.CreateParams{
			Model: "member",
			Data:  memberData,
		})
		if err != nil {
			return err
		}
		member := runtime.memberFromRecord(createdMember)
		if runtime.options.Hooks.AfterAddMember != nil {
			if hookErr := runtime.options.Hooks.AfterAddMember(ctx, AfterAddMemberData{
				Member: member, User: cloneRecord(user), Organization: organization,
			}); hookErr != nil {
				return hookErr
			}
		}
		defaultTeamID := ""
		if runtime.options.Teams.Enabled && defaultTeamEnabled(runtime.options.Teams) {
			teamCreatedAt := runtime.clock()
			teamData := storage.Record{
				"name": organization.Name, "organizationId": organization.ID,
			}
			if runtime.options.Hooks.BeforeCreateTeam != nil {
				override, hookErr := runtime.options.Hooks.BeforeCreateTeam(ctx, BeforeCreateTeamData{
					Team: cloneRecord(teamData), User: cloneRecord(user), Organization: organization,
					OrganizationRecord: parseOrganizationMetadata(runtime.publicRecord("organization", createdOrganization)),
				})
				if hookErr != nil {
					return hookErr
				}
				mergeRecord(teamData, override)
			}
			if _, overridden := teamData["createdAt"]; !overridden {
				teamData["createdAt"] = teamCreatedAt
			}
			var createdTeam storage.Record
			var teamErr error
			if runtime.options.Teams.CustomCreateDefaultTeam != nil {
				createdTeam, teamErr = runtime.options.Teams.CustomCreateDefaultTeam(
					ctx, adapter, parseOrganizationMetadata(runtime.publicRecord("organization", createdOrganization)),
				)
			} else {
				createdTeam, teamErr = adapter.Create(ctx, storage.CreateParams{
					Model: "team", Data: teamData, ForceAllowID: teamData["id"] != nil,
				})
			}
			if teamErr != nil {
				return teamErr
			}
			team := runtime.teamFromRecord(createdTeam)
			if team.ID == "" {
				return errors.New("organization: custom default team creator returned a team without id")
			}
			defaultTeamID = team.ID
			if _, teamMemberErr := adapter.Create(ctx, storage.CreateParams{
				Model: "teamMember", Data: storage.Record{
					"teamId": team.ID, "userId": input.UserID, "createdAt": runtime.clock(),
				},
			}); teamMemberErr != nil && !errors.Is(teamMemberErr, storage.ErrUniqueConstraint) {
				return teamMemberErr
			}
			if runtime.options.Hooks.AfterCreateTeam != nil {
				if hookErr := runtime.options.Hooks.AfterCreateTeam(ctx, AfterCreateTeamData{
					Team: team, TeamRecord: runtime.publicRecord("team", createdTeam),
					User: cloneRecord(user), Organization: organization,
					OrganizationRecord: parseOrganizationMetadata(runtime.publicRecord("organization", createdOrganization)),
				}); hookErr != nil {
					return hookErr
				}
			}
		}
		if runtime.options.Hooks.AfterCreateOrganization != nil {
			if hookErr := runtime.options.Hooks.AfterCreateOrganization(ctx, AfterCreateOrganizationData{
				Organization: organization, Member: member, User: cloneRecord(user),
			}); hookErr != nil {
				return hookErr
			}
		}
		result = CreateOrganizationResult{
			Organization:  organization,
			Members:       []Member{member},
			defaultTeamID: defaultTeamID,
		}
		return nil
	}

	err = runtime.adapter.Transaction(ctx, create)
	if errors.Is(err, storage.ErrTransactionsUnsupported) {
		err = create(runtime.adapter)
	}
	if err != nil {
		if _, ok := contract.AsAPIError(err); ok {
			return CreateOrganizationResult{}, err
		}
		return CreateOrganizationResult{}, fmt.Errorf("organization: create organization: %w", err)
	}
	return result, nil
}

func organizationFromRecord(record storage.Record) Organization {
	result := Organization{}
	result.ID, _ = recordString(record, "id")
	result.Name, _ = recordString(record, "name")
	result.Slug, _ = recordString(record, "slug")
	if logo, ok := recordString(record, "logo"); ok {
		result.Logo = &logo
	}
	if createdAt, ok := record["createdAt"].(time.Time); ok {
		result.CreatedAt = createdAt
	}
	if metadata, ok := recordString(record, "metadata"); ok && strings.TrimSpace(metadata) != "" {
		_ = json.Unmarshal([]byte(metadata), &result.Metadata)
	} else if metadata, ok := record["metadata"].(map[string]any); ok {
		result.Metadata = cloneMap(metadata)
	}
	return result
}

func memberFromRecord(record storage.Record) Member {
	result := Member{}
	result.ID, _ = recordString(record, "id")
	result.OrganizationID, _ = recordString(record, "organizationId")
	result.UserID, _ = recordString(record, "userId")
	result.Role, _ = recordString(record, "role")
	if createdAt, ok := record["createdAt"].(time.Time); ok {
		result.CreatedAt = createdAt
	}
	if user, ok := record["user"].(storage.Record); ok {
		result.User = memberUserFromRecord(user)
	}
	return result
}

func recordString(record storage.Record, key string) (string, bool) {
	value, ok := record[key].(string)
	return value, ok
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func mergeRecord(target storage.Record, source storage.Record) {
	for key, value := range source {
		target[key] = value
	}
}

func defaultTeamEnabled(options TeamsOptions) bool {
	return options.DefaultTeamEnabled == nil || *options.DefaultTeamEnabled
}
