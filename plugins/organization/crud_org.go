package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/storage"
)

func (plugin *Plugin) GetFullOrganization(
	ctx context.Context,
	input GetFullOrganizationInput,
) (*FullOrganization, error) {
	implementation, err := plugin.boundRuntime()
	if err != nil {
		return nil, err
	}
	return implementation.getFullOrganization(ctx, input)
}

func (plugin *Plugin) SetActiveOrganization(
	ctx context.Context,
	input SetActiveOrganizationInput,
) (*Organization, error) {
	implementation, err := plugin.boundRuntime()
	if err != nil {
		return nil, err
	}
	return implementation.setActiveOrganization(ctx, input)
}

func (plugin *Plugin) UpdateOrganization(
	ctx context.Context,
	input UpdateOrganizationInput,
) (Organization, error) {
	implementation, err := plugin.boundRuntime()
	if err != nil {
		return Organization{}, err
	}
	return implementation.updateOrganization(ctx, input)
}

func (plugin *Plugin) CreateInvitation(
	ctx context.Context,
	input CreateInvitationInput,
) (Invitation, error) {
	implementation, err := plugin.boundRuntime()
	if err != nil {
		return Invitation{}, err
	}
	return implementation.createInvitation(ctx, input)
}

func (plugin *Plugin) ListOrganizationTeams(
	ctx context.Context,
	organizationID string,
) ([]Team, error) {
	implementation, err := plugin.boundRuntime()
	if err != nil {
		return nil, err
	}
	return implementation.listOrganizationTeams(ctx, organizationID)
}

func (plugin *Plugin) GetActiveMember(
	ctx context.Context,
	userID string,
	organizationID string,
) (*Member, error) {
	implementation, err := plugin.boundRuntime()
	if err != nil {
		return nil, err
	}
	return implementation.getActiveMember(ctx, userID, organizationID)
}

func (plugin *Plugin) boundRuntime() (*runtime, error) {
	if plugin == nil {
		return nil, errors.New("organization: plugin is nil")
	}
	plugin.mu.RLock()
	implementation := plugin.runtime
	plugin.mu.RUnlock()
	if implementation == nil {
		return nil, errors.New("organization: plugin is not bound to single-auth")
	}
	return implementation, nil
}

func (runtime *runtime) getFullOrganizationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters",
		).WithCause(err)
	}
	var membersLimit *int
	if raw := strings.TrimSpace(query.Get("membersLimit")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 0 {
			return contract.Response{}, contract.NewAPIError(
				contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid membersLimit",
			).WithCause(parseErr)
		}
		membersLimit = &value
	}
	userID, _ := recordString(session.User, "id")
	activeOrganizationID, _ := recordString(session.Session, "activeOrganizationId")
	result, err := runtime.getFullOrganization(ctx.GoContext(), GetFullOrganizationInput{
		UserID: userID, ActiveOrganizationID: activeOrganizationID,
		OrganizationID: query.Get("organizationId"), OrganizationSlug: query.Get("organizationSlug"),
		MembersLimit: membersLimit,
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) getFullOrganization(
	ctx context.Context,
	input GetFullOrganizationInput,
) (*FullOrganization, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	lookup := strings.TrimSpace(input.OrganizationSlug)
	isSlug := lookup != ""
	if lookup == "" {
		lookup = strings.TrimSpace(input.OrganizationID)
	}
	if lookup == "" {
		lookup = strings.TrimSpace(input.ActiveOrganizationID)
	}
	if lookup == "" {
		return nil, nil
	}
	field := "id"
	if isSlug {
		field = "slug"
	}
	record, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: field, Value: lookup}},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: get full organization: find organization: %w", err)
	}
	if record == nil {
		return nil, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	organization := runtime.organizationFromRecord(record)
	member, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: input.UserID},
			{Field: "organizationId", Value: organization.ID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: get full organization: find membership: %w", err)
	}
	if member == nil {
		return nil, organizationError(contract.StatusForbidden, ErrorUserNotOrganizationMember)
	}
	limit := runtime.options.MembershipLimit
	if input.MembersLimit != nil {
		limit = *input.MembersLimit
	}
	members, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "organizationId", Value: organization.ID}},
		Limit: storage.Int(limit), SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Ascending},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: get full organization: list members: %w", err)
	}
	usersByID := make(map[string]storage.Record, len(members))
	if len(members) > 0 {
		userIDs := make([]string, 0, len(members))
		for _, memberRecord := range members {
			if userID, ok := recordString(memberRecord, "userId"); ok && userID != "" {
				userIDs = append(userIDs, userID)
			}
		}
		users, usersErr := runtime.adapter.FindMany(ctx, storage.FindManyParams{
			Model: "user",
			Where: []storage.Where{{Field: "id", Value: userIDs, Operator: storage.OpIn}},
			Limit: storage.Int(runtime.options.MembershipLimit),
		})
		if usersErr != nil {
			return nil, fmt.Errorf("organization: get full organization: list member users: %w", usersErr)
		}
		for _, user := range users {
			if userID, ok := recordString(user, "id"); ok {
				usersByID[userID] = user
			}
		}
	}
	invitations, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "invitation", Where: []storage.Where{{Field: "organizationId", Value: organization.ID}},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Ascending},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: get full organization: list invitations: %w", err)
	}
	result := &FullOrganization{
		Organization: organization,
		Members:      make([]Member, len(members)),
		Invitations:  make([]Invitation, len(invitations)),
	}
	for index, value := range members {
		member := runtime.memberFromRecord(value)
		user := usersByID[member.UserID]
		if user == nil {
			return nil, fmt.Errorf("organization: get full organization: user not found for member %q", member.ID)
		}
		member.User = memberUserFromRecord(user)
		result.Members[index] = member
	}
	for index, value := range invitations {
		result.Invitations[index] = runtime.invitationFromRecord(value)
	}
	if runtime.options.Teams.Enabled {
		result.Teams, err = runtime.listOrganizationTeams(ctx, organization.ID)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

type setActiveOrganizationBody struct {
	OrganizationID   *string `json:"organizationId"`
	OrganizationSlug string  `json:"organizationSlug"`
}

func (runtime *runtime) setActiveOrganizationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	var body setActiveOrganizationBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	clear := false
	if value, exists := raw["organizationId"]; exists && string(value) == "null" {
		clear = true
	}
	userID, _ := recordString(session.User, "id")
	token, _ := recordString(session.Session, "token")
	organization, err := runtime.setActiveOrganization(ctx.GoContext(), SetActiveOrganizationInput{
		UserID: userID, SessionToken: token, OrganizationID: body.OrganizationID,
		OrganizationSlug: body.OrganizationSlug, Clear: clear,
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, organization)
}

func (runtime *runtime) setActiveOrganization(
	ctx context.Context,
	input SetActiveOrganizationInput,
) (*Organization, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if input.Clear {
		if err := runtime.setSessionActiveOrganization(ctx, input.SessionToken, nil); err != nil {
			return nil, err
		}
		return nil, nil
	}
	var record storage.Record
	var err error
	if input.OrganizationID != nil && strings.TrimSpace(*input.OrganizationID) != "" {
		record, err = runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: strings.TrimSpace(*input.OrganizationID)}},
		})
	} else if strings.TrimSpace(input.OrganizationSlug) != "" {
		record, err = runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "slug", Value: strings.TrimSpace(input.OrganizationSlug)}},
		})
	} else {
		if err := runtime.setSessionActiveOrganization(ctx, input.SessionToken, nil); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("organization: set active: find organization: %w", err)
	}
	if record == nil {
		return nil, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	organization := runtime.organizationFromRecord(record)
	member, err := runtime.getActiveMember(ctx, input.UserID, organization.ID)
	if err != nil {
		return nil, err
	}
	if member == nil {
		_ = runtime.setSessionActiveOrganization(ctx, input.SessionToken, nil)
		return nil, organizationError(contract.StatusForbidden, ErrorUserNotOrganizationMember)
	}
	if err := runtime.setSessionActiveOrganization(ctx, input.SessionToken, &organization.ID); err != nil {
		return nil, err
	}
	return &organization, nil
}

func (runtime *runtime) setSessionActiveOrganization(
	ctx context.Context,
	sessionToken string,
	organizationID *string,
) error {
	if strings.TrimSpace(sessionToken) == "" {
		return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	value := any(nil)
	if organizationID != nil {
		value = *organizationID
	}
	updated, err := runtime.adapter.Update(ctx, storage.UpdateParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: sessionToken}},
		Update: storage.Record{"activeOrganizationId": value},
	})
	if err != nil {
		return fmt.Errorf("organization: set active: update session: %w", err)
	}
	if updated == nil {
		return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	return nil
}

func (runtime *runtime) setSessionActiveTeam(
	ctx context.Context,
	sessionToken string,
	teamID *string,
) error {
	if strings.TrimSpace(sessionToken) == "" {
		return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	value := any(nil)
	if teamID != nil {
		value = *teamID
	}
	updated, err := runtime.adapter.Update(ctx, storage.UpdateParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: sessionToken}},
		Update: storage.Record{"activeTeamId": value},
	})
	if err != nil {
		return fmt.Errorf("organization: set active team: update session: %w", err)
	}
	if updated == nil {
		return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	return nil
}

type updateOrganizationBody struct {
	OrganizationID string `json:"organizationId"`
	Data           struct {
		Name     *string                `json:"name"`
		Slug     *string                `json:"slug"`
		Logo     OptionalNullableString `json:"logo"`
		Metadata *map[string]any        `json:"metadata"`
	} `json:"data"`
}

func (runtime *runtime) updateOrganizationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	var body updateOrganizationBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	rawBody, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	additional := storage.Record{}
	if rawData, exists := rawBody["data"]; exists && rawData != nil {
		data, ok := rawData.(map[string]any)
		if !ok {
			return contract.Response{}, invalidOrganizationBody(errors.New("data must be an object"))
		}
		additional = storage.Record(data)
	}
	userID, _ := recordString(session.User, "id")
	activeOrganizationID, _ := recordString(session.Session, "activeOrganizationId")
	updated, err := runtime.updateOrganization(ctx.GoContext(), UpdateOrganizationInput{
		OrganizationID: body.OrganizationID, ActiveOrganizationID: activeOrganizationID, UserID: userID,
		Data: OrganizationUpdate{
			Name: body.Data.Name, Slug: body.Data.Slug, Logo: body.Data.Logo,
			Metadata: body.Data.Metadata, Additional: additional,
		},
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, updated)
}

func (runtime *runtime) updateOrganization(
	ctx context.Context,
	input UpdateOrganizationInput,
) (Organization, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	organizationID := strings.TrimSpace(input.OrganizationID)
	if organizationID == "" {
		organizationID = strings.TrimSpace(input.ActiveOrganizationID)
	}
	if organizationID == "" {
		return Organization{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	member, err := runtime.getActiveMember(ctx, input.UserID, organizationID)
	if err != nil {
		return Organization{}, err
	}
	if member == nil {
		return Organization{}, organizationError(contract.StatusBadRequest, ErrorUserNotOrganizationMember)
	}
	allowed, err := runtime.hasOrganizationPermission(
		ctx, organizationID, member.Role,
		authorization.Statements{"organization": {"update"}}, false,
	)
	if err != nil {
		return Organization{}, err
	}
	if !allowed {
		return Organization{}, organizationError(contract.StatusForbidden, ErrorOrganizationUpdateForbidden)
	}
	additional, err := runtime.organizationAdditionalInput(input.Data.Additional, true)
	if err != nil {
		return Organization{}, err
	}
	update := cloneRecord(additional)
	if update == nil {
		update = storage.Record{}
	}
	if input.Data.Name != nil {
		if strings.TrimSpace(*input.Data.Name) == "" {
			return Organization{}, invalidOrganizationBody(errors.New("name is empty"))
		}
		update["name"] = *input.Data.Name
	}
	if input.Data.Slug != nil {
		if strings.TrimSpace(*input.Data.Slug) == "" {
			return Organization{}, invalidOrganizationBody(errors.New("slug is empty"))
		}
		existing, findErr := runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "slug", Value: *input.Data.Slug}},
		})
		if findErr != nil {
			return Organization{}, findErr
		}
		if existing != nil {
			existingID, _ := recordString(existing, "id")
			if existingID != organizationID {
				return Organization{}, organizationError(contract.StatusBadRequest, ErrorOrganizationSlugTaken)
			}
		}
		update["slug"] = *input.Data.Slug
	}
	if input.Data.Logo.Present {
		if input.Data.Logo.Value == nil {
			update["logo"] = nil
		} else {
			update["logo"] = *input.Data.Logo.Value
		}
	}
	if input.Data.Metadata != nil {
		encoded, encodeErr := json.Marshal(*input.Data.Metadata)
		if encodeErr != nil {
			return Organization{}, encodeErr
		}
		update["metadata"] = string(encoded)
	}
	updated, err := runtime.adapter.Update(ctx, storage.UpdateParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}}, Update: update,
	})
	if err != nil {
		return Organization{}, fmt.Errorf("organization: update: %w", err)
	}
	if updated == nil {
		return Organization{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	return runtime.organizationFromRecord(updated), nil
}

type createInvitationBody struct {
	OrganizationID string `json:"organizationId"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	TeamID         any    `json:"teamId"`
}

func (runtime *runtime) createInvitationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	var body createInvitationBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	inviterID, _ := recordString(session.User, "id")
	activeOrganizationID, _ := recordString(session.Session, "activeOrganizationId")
	invitation, err := runtime.createInvitation(ctx.GoContext(), CreateInvitationInput{
		OrganizationID: body.OrganizationID, ActiveOrganizationID: activeOrganizationID,
		InviterID: inviterID, Email: body.Email, Role: body.Role,
		TeamIDs: invitationTeamIDs(body.TeamID),
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, invitation)
}

func (runtime *runtime) createInvitation(
	ctx context.Context,
	input CreateInvitationInput,
) (Invitation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	organizationID := strings.TrimSpace(input.OrganizationID)
	if organizationID == "" {
		organizationID = strings.TrimSpace(input.ActiveOrganizationID)
	}
	roles := normalizeRoleStrings([]string{input.Role})
	if organizationID == "" || strings.TrimSpace(input.Email) == "" || len(roles) == 0 {
		return Invitation{}, invalidOrganizationBody(errors.New("missing invitation fields"))
	}
	roleValue := strings.Join(roles, ",")
	member, err := runtime.getActiveMember(ctx, input.InviterID, organizationID)
	if err != nil {
		return Invitation{}, err
	}
	if member == nil {
		return Invitation{}, organizationError(contract.StatusForbidden, ErrorInvitationForbidden)
	}
	allowed, err := runtime.hasOrganizationPermission(
		ctx, organizationID, member.Role,
		authorization.Statements{"invitation": {"create"}}, false,
	)
	if err != nil {
		return Invitation{}, err
	}
	if !allowed {
		return Invitation{}, organizationError(contract.StatusForbidden, ErrorInvitationForbidden)
	}
	if err := runtime.validateOrganizationRoles(ctx, organizationID, roles); err != nil {
		return Invitation{}, err
	}
	if !roleIncludes(member.Role, runtime.creatorRole) && stringSliceContains(roles, runtime.creatorRole) {
		return Invitation{}, organizationError(
			contract.StatusForbidden, ErrorInvitationCreatorRoleForbidden,
		)
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(input.Email))
	invitedUser, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: normalizedEmail}},
	})
	if err != nil {
		return Invitation{}, fmt.Errorf("organization: create invitation: find invited user: %w", err)
	}
	if invitedUser != nil {
		invitedUserID, _ := recordString(invitedUser, "id")
		existingMember, findErr := runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "member", Where: []storage.Where{
				{Field: "organizationId", Value: organizationID},
				{Field: "userId", Value: invitedUserID},
			},
		})
		if findErr != nil {
			return Invitation{}, fmt.Errorf("organization: create invitation: find existing membership: %w", findErr)
		}
		if existingMember != nil {
			return Invitation{}, organizationError(contract.StatusBadRequest, ErrorUserAlreadyMember)
		}
	}
	pendingInvitations, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "invitation", Where: []storage.Where{
			{Field: "organizationId", Value: organizationID},
			{Field: "email", Value: normalizedEmail},
			{Field: "status", Value: invitationStatusPending},
		},
	})
	if err != nil {
		return Invitation{}, fmt.Errorf("organization: create invitation: find pending invitation: %w", err)
	}
	for _, pending := range pendingInvitations {
		if expiresAt, ok := invitationRecordTime(pending, "expiresAt"); ok && expiresAt.After(runtime.clock()) {
			return Invitation{}, organizationError(contract.StatusBadRequest, ErrorUserAlreadyInvited)
		}
	}
	organizationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if err != nil {
		return Invitation{}, err
	}
	if organizationRecord == nil {
		return Invitation{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	teamIDs, err := runtime.validateInvitationTeamIDs(ctx, organizationID, input.TeamIDs)
	if err != nil {
		return Invitation{}, err
	}
	inviter, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: input.InviterID}},
	})
	if err != nil {
		return Invitation{}, err
	}
	if inviter == nil {
		return Invitation{}, unauthorizedOrganization()
	}
	invitationData := storage.Record{
		"organizationId": organizationID,
		"email":          normalizedEmail,
		"role":           roleValue,
		"teamIds":        teamIDs,
	}
	organization := runtime.organizationFromRecord(organizationRecord)
	if runtime.options.Hooks.BeforeCreateInvitation != nil {
		hookInvitation := cloneRecord(invitationData)
		hookInvitation["inviterId"] = input.InviterID
		if len(input.TeamIDs) > 0 {
			hookInvitation["teamId"] = input.TeamIDs[0]
		}
		override, hookErr := runtime.options.Hooks.BeforeCreateInvitation(ctx, BeforeCreateInvitationData{
			Invitation: hookInvitation, Inviter: cloneRecord(inviter), Organization: organization,
		})
		if hookErr != nil {
			return Invitation{}, hookErr
		}
		mergeRecord(invitationData, override)
	}
	now := runtime.clock()
	data := storage.Record{
		"status":    "pending",
		"expiresAt": now.Add(runtime.options.InvitationExpiresIn),
		"createdAt": now,
		"inviterId": input.InviterID,
	}
	mergeRecord(data, invitationData)
	teamIDs = invitationTeamIDs(data["teamIds"])
	delete(data, "teamIds")
	if len(teamIDs) > 0 {
		data["teamId"] = strings.Join(teamIDs, ",")
	}
	created, err := runtime.adapter.Create(ctx, storage.CreateParams{
		Model: "invitation", Data: data, ForceAllowID: data["id"] != nil,
	})
	if err != nil {
		return Invitation{}, fmt.Errorf("organization: create invitation: %w", err)
	}
	invitation := runtime.invitationFromRecord(created)
	if runtime.options.SendInvitationEmail != nil {
		if err := runtime.options.SendInvitationEmail(ctx, invitation); err != nil {
			return Invitation{}, err
		}
	}
	if runtime.options.Hooks.AfterCreateInvitation != nil {
		if hookErr := runtime.options.Hooks.AfterCreateInvitation(ctx, AfterCreateInvitationData{
			Invitation: invitation, Inviter: cloneRecord(inviter), Organization: organization,
		}); hookErr != nil {
			return Invitation{}, hookErr
		}
	}
	return invitation, nil
}

func (runtime *runtime) listOrganizationTeamsEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	organizationID := strings.TrimSpace(query.Get("organizationId"))
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.findOrganizationMemberRecord(ctx.GoContext(), userID, organizationID)
	if err != nil {
		return contract.Response{}, err
	}
	if member == nil {
		return contract.Response{}, organizationError(contract.StatusForbidden, ErrorOrganizationAccessForbidden)
	}
	teams, err := runtime.listOrganizationTeamRecords(ctx.GoContext(), organizationID)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, teams)
}

func (runtime *runtime) listOrganizationTeams(ctx context.Context, organizationID string) ([]Team, error) {
	if !runtime.options.Teams.Enabled {
		return []Team{}, nil
	}
	records, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Ascending},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: list teams: %w", err)
	}
	result := make([]Team, len(records))
	for index, record := range records {
		result[index] = runtime.teamFromRecord(record)
	}
	return result, nil
}

func (runtime *runtime) getActiveMemberEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	userID, _ := recordString(session.User, "id")
	organizationID, _ := recordString(session.Session, "activeOrganizationId")
	member, err := runtime.getActiveMember(ctx.GoContext(), userID, organizationID)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, member)
}

func (runtime *runtime) getActiveMember(
	ctx context.Context,
	userID string,
	organizationID string,
) (*Member, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, nil
	}
	record, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: get active member: %w", err)
	}
	if record == nil {
		return nil, nil
	}
	member := runtime.memberFromRecord(record)
	user, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: member.UserID}},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: get active member: find user: %w", err)
	}
	if user == nil {
		return nil, nil
	}
	member.User = memberUserFromRecord(user)
	return &member, nil
}

func invitationFromRecord(record storage.Record) Invitation {
	result := Invitation{}
	result.ID, _ = recordString(record, "id")
	result.OrganizationID, _ = recordString(record, "organizationId")
	result.Email, _ = recordString(record, "email")
	result.Role, _ = recordString(record, "role")
	result.Status, _ = recordString(record, "status")
	if teamID, ok := recordString(record, "teamId"); ok {
		result.TeamID = &teamID
	}
	result.InviterID, _ = recordString(record, "inviterId")
	result.ExpiresAt, _ = record["expiresAt"].(time.Time)
	result.CreatedAt, _ = record["createdAt"].(time.Time)
	return result
}

func memberUserFromRecord(record storage.Record) *MemberUser {
	if record == nil {
		return nil
	}
	user := &MemberUser{}
	user.ID, _ = recordString(record, "id")
	user.Name, _ = recordString(record, "name")
	user.Email, _ = recordString(record, "email")
	if image, ok := recordString(record, "image"); ok {
		user.Image = &image
	}
	return user
}

func invitationTeamIDs(value any) []string {
	switch typed := value.(type) {
	case nil:
		return []string{}
	case string:
		if strings.TrimSpace(typed) == "" {
			return []string{}
		}
		return []string{typed}
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		return []string{}
	}
}

func teamFromRecord(record storage.Record) Team {
	result := Team{}
	result.ID, _ = recordString(record, "id")
	result.Name, _ = recordString(record, "name")
	result.OrganizationID, _ = recordString(record, "organizationId")
	result.CreatedAt, _ = record["createdAt"].(time.Time)
	if updatedAt, ok := record["updatedAt"].(time.Time); ok {
		result.UpdatedAt = &updatedAt
	}
	return result
}

func unauthorizedOrganization() *contract.APIError {
	return contract.NewAPIError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}

func invalidOrganizationBody(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
	).WithCause(err)
}
