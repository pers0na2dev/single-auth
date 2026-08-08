package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/storage"
)

var teamBaseInputFields = map[string]struct{}{
	"id": {}, "name": {}, "organizationId": {}, "createdAt": {}, "updatedAt": {},
}

func (runtime *runtime) createTeamEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	name, exists := body["name"].(string)
	if !exists {
		return contract.Response{}, invalidOrganizationBody(errors.New("name must be a string"))
	}
	organizationID := optionalTeamString(body, "organizationId")
	additional, err := runtime.teamAdditionalInput(body, false)
	if err != nil {
		return contract.Response{}, err
	}

	session, err := runtime.resolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if session != nil && organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if session == nil && !trustedDirectTeamCall(ctx) {
		return contract.Response{}, unauthorizedOrganization()
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}

	var created storage.Record
	var organization storage.Record
	lock := runtime.organizationLock(organizationID)
	err = func() error {
		lock.Lock()
		defer lock.Unlock()

		if session != nil {
			actorID, _ := recordString(session.User, "id")
			member, findErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), actorID, organizationID)
			if findErr != nil {
				return findErr
			}
			if member == nil {
				return organizationError(contract.StatusForbidden, ErrorInvitationForbidden)
			}
			role, _ := recordString(member, "role")
			allowed, permissionErr := runtime.hasOrganizationPermission(
				ctx.GoContext(), organizationID, role,
				authorization.Statements{"team": {"create"}}, false,
			)
			if permissionErr != nil {
				return permissionErr
			}
			if !allowed {
				return organizationError(contract.StatusForbidden, ErrorTeamCreateForbidden)
			}
		}

		maximum, limitErr := runtime.resolveMaximumTeams(ctx.GoContext(), organizationID, session)
		if limitErr != nil {
			return limitErr
		}
		if maximum != 0 {
			count, countErr := runtime.adapter.Count(ctx.GoContext(), storage.CountParams{
				Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
			})
			if countErr != nil {
				return fmt.Errorf("organization: create team: count teams: %w", countErr)
			}
			if count >= int64(maximum) {
				return organizationError(contract.StatusBadRequest, ErrorMaximumTeamsReached)
			}
		}

		organization, err = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
		})
		if err != nil {
			return fmt.Errorf("organization: create team: find organization: %w", err)
		}
		if organization == nil {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
		}

		now := runtime.clock()
		teamData := storage.Record{
			"name": name, "organizationId": organizationID, "createdAt": now, "updatedAt": now,
		}
		mergeRecord(teamData, additional)
		if runtime.options.Hooks.BeforeCreateTeam != nil {
			var user storage.Record
			if session != nil {
				user = cloneRecord(session.User)
			}
			override, hookErr := runtime.options.Hooks.BeforeCreateTeam(ctx.GoContext(), BeforeCreateTeamData{
				Team:               cloneRecordWithout(teamData, "createdAt", "updatedAt"),
				User:               user,
				Organization:       runtime.organizationFromRecord(organization),
				OrganizationRecord: parseOrganizationMetadata(cloneRecord(organization)),
			})
			if hookErr != nil {
				return hookErr
			}
			mergeRecord(teamData, override)
		}
		created, err = runtime.adapter.Create(ctx.GoContext(), storage.CreateParams{
			Model: "team", Data: teamData, ForceAllowID: teamData["id"] != nil,
		})
		if err != nil {
			return fmt.Errorf("organization: create team: create: %w", err)
		}
		return nil
	}()
	if err != nil {
		return contract.Response{}, err
	}
	if runtime.options.Hooks.AfterCreateTeam != nil {
		var user storage.Record
		if session != nil {
			user = cloneRecord(session.User)
		}
		if err := runtime.options.Hooks.AfterCreateTeam(ctx.GoContext(), AfterCreateTeamData{
			Team: runtime.teamFromRecord(created), TeamRecord: cloneRecord(created), User: user,
			Organization:       runtime.organizationFromRecord(organization),
			OrganizationRecord: parseOrganizationMetadata(cloneRecord(organization)),
		}); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(contract.StatusOK, runtime.publicRecord("team", created))
}

func (runtime *runtime) resolveMaximumTeams(
	ctx context.Context,
	organizationID string,
	session *resolvedSession,
) (int, error) {
	if runtime.options.Teams.MaximumTeamsFunc == nil {
		return runtime.options.Teams.MaximumTeams, nil
	}
	data := MaximumTeamsData{OrganizationID: organizationID}
	if session != nil {
		data.Session = &TeamSessionData{Session: cloneRecord(session.Session), User: cloneRecord(session.User)}
	}
	maximum, err := runtime.options.Teams.MaximumTeamsFunc(ctx, data)
	if err != nil {
		return 0, err
	}
	return maximum, nil
}

func (runtime *runtime) removeTeamEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	teamID, ok := body["teamId"].(string)
	if !ok {
		return contract.Response{}, invalidOrganizationBody(errors.New("teamId must be a string"))
	}
	organizationID := optionalTeamString(body, "organizationId")
	session, err := runtime.resolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if session != nil && organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	if session == nil && !trustedDirectTeamCall(ctx) {
		return contract.Response{}, unauthorizedOrganization()
	}

	var team storage.Record
	var organization storage.Record
	lock := runtime.organizationLock(organizationID)
	err = func() error {
		lock.Lock()
		defer lock.Unlock()
		if session != nil {
			actorID, _ := recordString(session.User, "id")
			member, findErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), actorID, organizationID)
			if findErr != nil {
				return findErr
			}
			activeTeamID, _ := recordString(session.Session, "activeTeamId")
			if member == nil || activeTeamID == teamID {
				return organizationError(contract.StatusForbidden, ErrorTeamDeleteActiveForbidden)
			}
			role, _ := recordString(member, "role")
			allowed, permissionErr := runtime.hasOrganizationPermission(
				ctx.GoContext(), organizationID, role,
				authorization.Statements{"team": {"delete"}}, false,
			)
			if permissionErr != nil {
				return permissionErr
			}
			if !allowed {
				return organizationError(contract.StatusForbidden, ErrorTeamDeleteForbidden)
			}
		}

		team, err = runtime.findTeamRecord(ctx.GoContext(), teamID, organizationID)
		if err != nil {
			return err
		}
		if team == nil {
			return organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
		}
		if !runtime.options.Teams.AllowRemovingAllTeams {
			count, countErr := runtime.adapter.Count(ctx.GoContext(), storage.CountParams{
				Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
			})
			if countErr != nil {
				return fmt.Errorf("organization: remove team: count teams: %w", countErr)
			}
			if count <= 1 {
				return organizationError(contract.StatusBadRequest, ErrorUnableToRemoveLastTeam)
			}
		}
		organization, err = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
		})
		if err != nil {
			return fmt.Errorf("organization: remove team: find organization: %w", err)
		}
		if organization == nil {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
		}
		if runtime.options.Hooks.BeforeDeleteTeam != nil {
			var user storage.Record
			if session != nil {
				user = cloneRecord(session.User)
			}
			if hookErr := runtime.options.Hooks.BeforeDeleteTeam(ctx.GoContext(), TeamLifecycleHookData{
				Team: cloneRecord(team), User: user, Organization: parseOrganizationMetadata(cloneRecord(organization)),
			}); hookErr != nil {
				return hookErr
			}
		}
		return runtime.deleteTeamCascade(ctx.GoContext(), organizationID, team)
	}()
	if err != nil {
		return contract.Response{}, err
	}
	if runtime.options.Hooks.AfterDeleteTeam != nil {
		var user storage.Record
		if session != nil {
			user = cloneRecord(session.User)
		}
		if err := runtime.options.Hooks.AfterDeleteTeam(ctx.GoContext(), TeamLifecycleHookData{
			Team: cloneRecord(team), User: user, Organization: parseOrganizationMetadata(cloneRecord(organization)),
		}); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(contract.StatusOK, map[string]string{"message": "Team removed successfully."})
}

func (runtime *runtime) deleteTeamCascade(
	ctx context.Context,
	organizationID string,
	team storage.Record,
) error {
	teamID, _ := recordString(team, "id")
	mutation := func(adapter storage.TransactionAdapter) error {
		if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
			Model: "teamMember", Where: []storage.Where{{Field: "teamId", Value: teamID}},
		}); err != nil {
			return fmt.Errorf("organization: remove team: delete team members: %w", err)
		}
		if err := adapter.Delete(ctx, storage.DeleteParams{
			Model: "team", Where: []storage.Where{{Field: "id", Value: teamID}},
		}); err != nil {
			return fmt.Errorf("organization: remove team: delete team: %w", err)
		}
		pending, err := findAllOrganizationRecords(ctx, adapter, "invitation", []storage.Where{
			{Field: "organizationId", Value: organizationID}, {Field: "status", Value: "pending"},
		})
		if err != nil {
			return fmt.Errorf("organization: remove team: list invitations: %w", err)
		}
		for _, invitation := range pending {
			current, ok := recordString(invitation, "teamId")
			if !ok || current == "" {
				continue
			}
			remaining, removed := removeCSVTeamID(current, teamID)
			if !removed {
				continue
			}
			var value any
			if remaining != "" {
				value = remaining
			}
			invitationID, _ := recordString(invitation, "id")
			if _, err := adapter.Update(ctx, storage.UpdateParams{
				Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
				Update: storage.Record{"teamId": value},
			}); err != nil {
				return fmt.Errorf("organization: remove team: update invitation: %w", err)
			}
		}
		return nil
	}
	err := runtime.adapter.Transaction(ctx, mutation)
	if !errors.Is(err, storage.ErrTransactionsUnsupported) {
		return err
	}
	return runtime.deleteTeamCascadeWithoutTransaction(ctx, organizationID, team, mutation)
}

func (runtime *runtime) deleteTeamCascadeWithoutTransaction(
	ctx context.Context,
	organizationID string,
	team storage.Record,
	mutation func(storage.TransactionAdapter) error,
) error {
	teamID, _ := recordString(team, "id")
	members, err := findAllOrganizationRecords(ctx, runtime.adapter, "teamMember", []storage.Where{
		{Field: "teamId", Value: teamID},
	})
	if err != nil {
		return err
	}
	pending, err := findAllOrganizationRecords(ctx, runtime.adapter, "invitation", []storage.Where{
		{Field: "organizationId", Value: organizationID}, {Field: "status", Value: "pending"},
	})
	if err != nil {
		return err
	}
	affected := make([]storage.Record, 0, len(pending))
	for _, invitation := range pending {
		value, ok := recordString(invitation, "teamId")
		if ok && csvContainsTeamID(value, teamID) {
			affected = append(affected, cloneRecord(invitation))
		}
	}
	if err := mutation(runtime.adapter); err != nil {
		if restoreErr := runtime.restoreRemovedTeam(ctx, team, members, affected); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return err
	}
	return nil
}

func (runtime *runtime) restoreRemovedTeam(
	ctx context.Context,
	team storage.Record,
	members []storage.Record,
	invitations []storage.Record,
) error {
	var restoreErrors []error
	teamID, _ := recordString(team, "id")
	existing, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "team", Where: []storage.Where{{Field: "id", Value: teamID}},
	})
	if err != nil {
		restoreErrors = append(restoreErrors, err)
	} else if existing == nil {
		if _, err := runtime.adapter.Create(ctx, storage.CreateParams{
			Model: "team", Data: cloneRecord(team), ForceAllowID: true,
		}); err != nil && !errors.Is(err, storage.ErrUniqueConstraint) {
			restoreErrors = append(restoreErrors, err)
		}
	}
	for _, member := range members {
		memberID, _ := recordString(member, "id")
		existing, findErr := runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "teamMember", Where: []storage.Where{{Field: "id", Value: memberID}},
		})
		if findErr != nil {
			restoreErrors = append(restoreErrors, findErr)
			continue
		}
		if existing == nil {
			if _, createErr := runtime.adapter.Create(ctx, storage.CreateParams{
				Model: "teamMember", Data: cloneRecord(member), ForceAllowID: memberID != "",
			}); createErr != nil && !errors.Is(createErr, storage.ErrUniqueConstraint) {
				restoreErrors = append(restoreErrors, createErr)
			}
		}
	}
	for _, invitation := range invitations {
		invitationID, _ := recordString(invitation, "id")
		if _, updateErr := runtime.adapter.Update(ctx, storage.UpdateParams{
			Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
			Update: storage.Record{"teamId": invitation["teamId"]},
		}); updateErr != nil {
			restoreErrors = append(restoreErrors, updateErr)
		}
	}
	return errors.Join(restoreErrors...)
}

func (runtime *runtime) updateTeamEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	teamID, ok := body["teamId"].(string)
	if !ok {
		return contract.Response{}, invalidOrganizationBody(errors.New("teamId must be a string"))
	}
	data, ok := body["data"].(map[string]any)
	if !ok {
		return contract.Response{}, invalidOrganizationBody(errors.New("data must be an object"))
	}
	if name, present := data["name"]; present {
		value, valid := name.(string)
		if !valid || value == "" {
			return contract.Response{}, invalidOrganizationBody(errors.New("data.name must be a non-empty string"))
		}
	}
	if organizationValue, present := data["organizationId"]; present {
		if _, valid := organizationValue.(string); !valid {
			return contract.Response{}, invalidOrganizationBody(errors.New("data.organizationId must be a string"))
		}
	}
	additional, err := runtime.teamAdditionalInput(storage.Record(data), true)
	if err != nil {
		return contract.Response{}, err
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	organizationID := optionalTeamString(storage.Record(data), "organizationId")
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}

	var updated storage.Record
	var organization storage.Record
	lock := runtime.organizationLock(organizationID)
	err = func() error {
		lock.Lock()
		defer lock.Unlock()
		actorID, _ := recordString(session.User, "id")
		member, findErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), actorID, organizationID)
		if findErr != nil {
			return findErr
		}
		if member == nil {
			return organizationError(contract.StatusForbidden, ErrorTeamUpdateForbidden)
		}
		role, _ := recordString(member, "role")
		allowed, permissionErr := runtime.hasOrganizationPermission(
			ctx.GoContext(), organizationID, role,
			authorization.Statements{"team": {"update"}}, false,
		)
		if permissionErr != nil {
			return permissionErr
		}
		if !allowed {
			return organizationError(contract.StatusForbidden, ErrorTeamUpdateForbidden)
		}
		team, findErr := runtime.findTeamRecord(ctx.GoContext(), teamID, organizationID)
		if findErr != nil {
			return findErr
		}
		if team == nil {
			return organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
		}
		organization, err = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
		})
		if err != nil {
			return fmt.Errorf("organization: update team: find organization: %w", err)
		}
		if organization == nil {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
		}
		updates := cloneRecord(additional)
		if name, present := data["name"].(string); present {
			updates["name"] = name
		}
		if runtime.options.Hooks.BeforeUpdateTeam != nil {
			override, hookErr := runtime.options.Hooks.BeforeUpdateTeam(ctx.GoContext(), BeforeUpdateTeamData{
				Team: cloneRecord(team), Updates: cloneRecord(updates), User: cloneRecord(session.User),
				Organization: parseOrganizationMetadata(cloneRecord(organization)),
			})
			if hookErr != nil {
				return hookErr
			}
			if override != nil {
				updates = cloneRecord(override)
			}
		}
		delete(updates, "id")
		updated, err = runtime.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "team", Where: []storage.Where{{Field: "id", Value: teamID}}, Update: updates,
		})
		if err != nil {
			return fmt.Errorf("organization: update team: update: %w", err)
		}
		return nil
	}()
	if err != nil {
		return contract.Response{}, err
	}
	if runtime.options.Hooks.AfterUpdateTeam != nil {
		if err := runtime.options.Hooks.AfterUpdateTeam(ctx.GoContext(), AfterUpdateTeamData{
			Team: cloneRecord(updated), User: cloneRecord(session.User),
			Organization: parseOrganizationMetadata(cloneRecord(organization)),
		}); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(contract.StatusOK, runtime.publicRecord("team", updated))
}

func (runtime *runtime) setActiveTeamEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	requested, present := body["teamId"]
	if present && requested == nil {
		current, _ := recordString(session.Session, "activeTeamId")
		if current == "" {
			return contract.JSONResponse(contract.StatusOK, nil)
		}
		updatedSession, updateErr := runtime.updateSessionActiveTeam(ctx.GoContext(), session.Session, nil)
		if updateErr != nil {
			return contract.Response{}, updateErr
		}
		if err := runtime.refreshEndpointTeamSession(ctx, updatedSession, session.User); err != nil {
			return contract.Response{}, err
		}
		return contract.JSONResponse(contract.StatusOK, nil)
	}

	teamID := ""
	if present {
		value, valid := requested.(string)
		if !valid {
			return contract.Response{}, invalidOrganizationBody(errors.New("teamId must be a string or null"))
		}
		teamID = value
	}
	if teamID == "" {
		teamID, _ = recordString(session.Session, "activeTeamId")
		if teamID == "" {
			return contract.JSONResponse(contract.StatusOK, nil)
		}
	}
	organizationID, _ := recordString(session.Session, "activeOrganizationId")
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	team, err := runtime.findTeamRecord(ctx.GoContext(), teamID, organizationID)
	if err != nil {
		return contract.Response{}, err
	}
	if team == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.findTeamMemberRecord(ctx.GoContext(), teamID, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if member == nil {
		return contract.Response{}, organizationError(contract.StatusForbidden, ErrorUserNotTeamMember)
	}
	updatedSession, err := runtime.updateSessionActiveTeam(ctx.GoContext(), session.Session, &teamID)
	if err != nil {
		return contract.Response{}, err
	}
	if err := runtime.refreshEndpointTeamSession(ctx, updatedSession, session.User); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, runtime.publicRecord("team", team))
}

func (runtime *runtime) updateSessionActiveTeam(
	ctx context.Context,
	session storage.Record,
	teamID *string,
) (storage.Record, error) {
	token, _ := recordString(session, "token")
	if token == "" {
		return nil, unauthorizedOrganization()
	}
	var value any
	if teamID != nil {
		value = *teamID
	}
	updated, err := runtime.adapter.Update(ctx, storage.UpdateParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
		Update: storage.Record{"activeTeamId": value},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: set active team: update session: %w", err)
	}
	if updated == nil {
		return nil, unauthorizedOrganization()
	}
	return updated, nil
}

func (runtime *runtime) refreshEndpointTeamSession(
	ctx *engine.Context,
	session storage.Record,
	user storage.Record,
) error {
	singleauth.SetEndpointSession(ctx, &singleauth.PluginSessionState{
		Session: cloneRecord(session), User: cloneRecord(user),
	})
	if runtime.refreshSession == nil {
		return nil
	}
	return runtime.refreshSession(ctx, session, user)
}

func (runtime *runtime) listUserTeamsEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	userID, _ := recordString(session.User, "id")
	memberships, err := runtime.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "teamMember", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: list user teams: list memberships: %w", err)
	}
	result := make([]storage.Record, 0, len(memberships))
	membershipByOrganization := make(map[string]bool)
	for _, membership := range memberships {
		teamID, _ := recordString(membership, "teamId")
		team, findErr := runtime.findTeamRecord(ctx.GoContext(), teamID, "")
		if findErr != nil {
			return contract.Response{}, findErr
		}
		if team == nil {
			continue
		}
		organizationID, _ := recordString(team, "organizationId")
		allowed, known := membershipByOrganization[organizationID]
		if !known {
			member, memberErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), userID, organizationID)
			if memberErr != nil {
				return contract.Response{}, memberErr
			}
			allowed = member != nil
			membershipByOrganization[organizationID] = allowed
		}
		if allowed {
			result = append(result, runtime.publicRecord("team", team))
		}
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) listTeamMembersEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidOrganizationQuery(err)
	}
	teamID := strings.TrimSpace(query.Get("teamId"))
	if teamID == "" {
		teamID, _ = recordString(session.Session, "activeTeamId")
	}
	if teamID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveTeam)
	}
	team, err := runtime.findTeamRecord(ctx.GoContext(), teamID, "")
	if err != nil {
		return contract.Response{}, err
	}
	if team == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
	}
	userID, _ := recordString(session.User, "id")
	organizationID, _ := recordString(team, "organizationId")
	organizationMember, err := runtime.findOrganizationMemberRecord(ctx.GoContext(), userID, organizationID)
	if err != nil {
		return contract.Response{}, err
	}
	if organizationMember == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorUserNotTeamMember)
	}
	teamMember, err := runtime.findTeamMemberRecord(ctx.GoContext(), teamID, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if teamMember == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorUserNotTeamMember)
	}
	members, err := runtime.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "teamMember", Where: []storage.Where{{Field: "teamId", Value: teamID}},
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: list team members: %w", err)
	}
	result := make([]storage.Record, len(members))
	for index, member := range members {
		result[index] = runtime.publicRecord("teamMember", member)
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) addTeamMemberEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	teamID, ok := body["teamId"].(string)
	if !ok {
		return contract.Response{}, invalidOrganizationBody(errors.New("teamId must be a string"))
	}
	userID, ok := coerceTeamUserID(body["userId"])
	if !ok {
		return contract.Response{}, invalidOrganizationBody(errors.New("userId is required"))
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	organizationID := optionalTeamString(body, "organizationId")
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}

	var teamMember storage.Record
	var team storage.Record
	var organization storage.Record
	var targetUser storage.Record
	lock := runtime.organizationLock(organizationID)
	err = func() error {
		lock.Lock()
		defer lock.Unlock()
		actorID, _ := recordString(session.User, "id")
		actor, findErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), actorID, organizationID)
		if findErr != nil {
			return findErr
		}
		if actor == nil {
			return organizationError(contract.StatusBadRequest, ErrorUserNotOrganizationMember)
		}
		role, _ := recordString(actor, "role")
		allowed, permissionErr := runtime.hasOrganizationPermission(
			ctx.GoContext(), organizationID, role,
			authorization.Statements{"member": {"update"}}, false,
		)
		if permissionErr != nil {
			return permissionErr
		}
		if !allowed {
			return organizationError(contract.StatusForbidden, ErrorTeamMemberCreateForbidden)
		}
		targetMember, findErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), userID, organizationID)
		if findErr != nil {
			return findErr
		}
		if targetMember == nil {
			return organizationError(contract.StatusBadRequest, ErrorUserNotOrganizationMember)
		}
		team, findErr = runtime.findTeamRecord(ctx.GoContext(), teamID, organizationID)
		if findErr != nil {
			return findErr
		}
		if team == nil {
			return organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
		}
		organization, findErr = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
		})
		if findErr != nil {
			return fmt.Errorf("organization: add team member: find organization: %w", findErr)
		}
		if organization == nil {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
		}
		targetUser, findErr = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if findErr != nil {
			return fmt.Errorf("organization: add team member: find user: %w", findErr)
		}
		if targetUser == nil {
			return contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "User not found")
		}
		if runtime.options.Hooks.BeforeAddTeamMember != nil {
			// single-auth 1.6.26 invokes this hook but intentionally ignores the
			// returned data override.
			_, hookErr := runtime.options.Hooks.BeforeAddTeamMember(ctx.GoContext(), BeforeAddTeamMemberData{
				TeamMember: storage.Record{"teamId": teamID, "userId": userID},
				Team:       cloneRecord(team), User: cloneRecord(targetUser),
				Organization: parseOrganizationMetadata(cloneRecord(organization)),
			})
			if hookErr != nil {
				return hookErr
			}
		}

		maximum, limited, limitErr := runtime.resolveMaximumMembersPerTeam(
			ctx.GoContext(), teamID, organizationID, session,
		)
		if limitErr != nil {
			return limitErr
		}
		create := func(adapter storage.TransactionAdapter) error {
			existing, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
				Model: "teamMember", Where: []storage.Where{
					{Field: "teamId", Value: teamID}, {Field: "userId", Value: userID},
				},
			})
			if findErr != nil {
				return findErr
			}
			if existing != nil {
				teamMember = existing
				return nil
			}
			if limited {
				count, countErr := adapter.Count(ctx.GoContext(), storage.CountParams{
					Model: "teamMember", Where: []storage.Where{{Field: "teamId", Value: teamID}},
				})
				if countErr != nil {
					return countErr
				}
				if count >= int64(maximum) {
					return organizationError(contract.StatusForbidden, ErrorTeamMemberLimitReached)
				}
			}
			created, createErr := adapter.Create(ctx.GoContext(), storage.CreateParams{
				Model: "teamMember", Data: storage.Record{
					"teamId": teamID, "userId": userID, "createdAt": runtime.clock(),
				},
			})
			if createErr != nil {
				return createErr
			}
			teamMember = created
			return nil
		}
		if limited {
			transactionErr := runtime.adapter.Transaction(ctx.GoContext(), create)
			if errors.Is(transactionErr, storage.ErrTransactionsUnsupported) {
				transactionErr = create(runtime.adapter)
			}
			if transactionErr != nil {
				return transactionErr
			}
		} else if createErr := create(runtime.adapter); createErr != nil {
			return createErr
		}
		return nil
	}()
	if err != nil {
		return contract.Response{}, err
	}
	if runtime.options.Hooks.AfterAddTeamMember != nil {
		if err := runtime.options.Hooks.AfterAddTeamMember(ctx.GoContext(), TeamMemberLifecycleHookData{
			TeamMember: cloneRecord(teamMember), Team: cloneRecord(team), User: cloneRecord(targetUser),
			Organization: parseOrganizationMetadata(cloneRecord(organization)),
		}); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(contract.StatusOK, runtime.publicRecord("teamMember", teamMember))
}

func (runtime *runtime) resolveMaximumMembersPerTeam(
	ctx context.Context,
	teamID string,
	organizationID string,
	session *singleauth.PluginSessionState,
) (int, bool, error) {
	if runtime.options.Teams.MaximumMembersPerTeamFunc != nil {
		maximum, err := runtime.options.Teams.MaximumMembersPerTeamFunc(ctx, MaximumMembersPerTeamData{
			TeamID: teamID, OrganizationID: organizationID,
			Session: TeamSessionData{Session: cloneRecord(session.Session), User: cloneRecord(session.User)},
		})
		return maximum, true, err
	}
	if runtime.options.Teams.MaximumMembersPerTeam == nil {
		return 0, false, nil
	}
	return *runtime.options.Teams.MaximumMembersPerTeam, true, nil
}

func (runtime *runtime) removeTeamMemberEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeTeamObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	teamID, ok := body["teamId"].(string)
	if !ok {
		return contract.Response{}, invalidOrganizationBody(errors.New("teamId must be a string"))
	}
	userID, ok := coerceTeamUserID(body["userId"])
	if !ok {
		return contract.Response{}, invalidOrganizationBody(errors.New("userId is required"))
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	organizationID := optionalTeamString(body, "organizationId")
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}

	var teamMember storage.Record
	var team storage.Record
	var organization storage.Record
	var targetUser storage.Record
	lock := runtime.organizationLock(organizationID)
	err = func() error {
		lock.Lock()
		defer lock.Unlock()
		actorID, _ := recordString(session.User, "id")
		actor, findErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), actorID, organizationID)
		if findErr != nil {
			return findErr
		}
		if actor == nil {
			return organizationError(contract.StatusBadRequest, ErrorUserNotOrganizationMember)
		}
		role, _ := recordString(actor, "role")
		allowed, permissionErr := runtime.hasOrganizationPermission(
			ctx.GoContext(), organizationID, role,
			authorization.Statements{"member": {"delete"}}, false,
		)
		if permissionErr != nil {
			return permissionErr
		}
		if !allowed {
			return organizationError(contract.StatusForbidden, ErrorTeamMemberRemoveForbidden)
		}
		targetMember, findErr := runtime.findOrganizationMemberRecord(ctx.GoContext(), userID, organizationID)
		if findErr != nil {
			return findErr
		}
		if targetMember == nil {
			return organizationError(contract.StatusBadRequest, ErrorUserNotOrganizationMember)
		}
		team, findErr = runtime.findTeamRecord(ctx.GoContext(), teamID, organizationID)
		if findErr != nil {
			return findErr
		}
		if team == nil {
			return organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
		}
		organization, findErr = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
		})
		if findErr != nil {
			return fmt.Errorf("organization: remove team member: find organization: %w", findErr)
		}
		if organization == nil {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
		}
		targetUser, findErr = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if findErr != nil {
			return fmt.Errorf("organization: remove team member: find user: %w", findErr)
		}
		if targetUser == nil {
			return contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "User not found")
		}
		teamMember, findErr = runtime.findTeamMemberRecord(ctx.GoContext(), teamID, userID)
		if findErr != nil {
			return findErr
		}
		if teamMember == nil {
			return organizationError(contract.StatusBadRequest, ErrorUserNotTeamMember)
		}
		if runtime.options.Hooks.BeforeRemoveTeamMember != nil {
			if hookErr := runtime.options.Hooks.BeforeRemoveTeamMember(ctx.GoContext(), TeamMemberLifecycleHookData{
				TeamMember: cloneRecord(teamMember), Team: cloneRecord(team), User: cloneRecord(targetUser),
				Organization: parseOrganizationMetadata(cloneRecord(organization)),
			}); hookErr != nil {
				return hookErr
			}
		}
		_, deleteErr := runtime.adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
			Model: "teamMember", Where: []storage.Where{
				{Field: "teamId", Value: teamID}, {Field: "userId", Value: userID},
			},
		})
		if deleteErr != nil {
			return fmt.Errorf("organization: remove team member: delete: %w", deleteErr)
		}
		return nil
	}()
	if err != nil {
		return contract.Response{}, err
	}
	if runtime.options.Hooks.AfterRemoveTeamMember != nil {
		if err := runtime.options.Hooks.AfterRemoveTeamMember(ctx.GoContext(), TeamMemberLifecycleHookData{
			TeamMember: cloneRecord(teamMember), Team: cloneRecord(team), User: cloneRecord(targetUser),
			Organization: parseOrganizationMetadata(cloneRecord(organization)),
		}); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(contract.StatusOK, map[string]string{"message": "Team member removed successfully."})
}

func (runtime *runtime) findOrganizationMemberRecord(
	ctx context.Context,
	userID string,
	organizationID string,
) (storage.Record, error) {
	record, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID}, {Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: find organization member: %w", err)
	}
	return record, nil
}

func (runtime *runtime) findTeamRecord(
	ctx context.Context,
	teamID string,
	organizationID string,
) (storage.Record, error) {
	where := []storage.Where{{Field: "id", Value: teamID}}
	if organizationID != "" {
		where = append(where, storage.Where{Field: "organizationId", Value: organizationID})
	}
	record, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{Model: "team", Where: where})
	if err != nil {
		return nil, fmt.Errorf("organization: find team: %w", err)
	}
	return record, nil
}

func (runtime *runtime) findTeamMemberRecord(
	ctx context.Context,
	teamID string,
	userID string,
) (storage.Record, error) {
	record, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "teamMember", Where: []storage.Where{
			{Field: "teamId", Value: teamID}, {Field: "userId", Value: userID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: find team member: %w", err)
	}
	return record, nil
}

func (runtime *runtime) listOrganizationTeamRecords(
	ctx context.Context,
	organizationID string,
) ([]storage.Record, error) {
	records, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: list teams: %w", err)
	}
	result := make([]storage.Record, len(records))
	for index, record := range records {
		result[index] = runtime.publicRecord("team", record)
	}
	return result, nil
}

func decodeTeamObject(raw []byte) (storage.Record, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var result storage.Record
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("request body must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("request body contains multiple JSON values")
		}
		return nil, err
	}
	return result, nil
}

func trustedDirectTeamCall(ctx *engine.Context) bool {
	if ctx == nil || !ctx.IsDirect() {
		return false
	}
	for _, header := range ctx.Request().Headers().Fields() {
		switch strings.ToLower(header.Name) {
		case "content-type", "content-length", "accept":
			continue
		default:
			return false
		}
	}
	return true
}

func optionalTeamString(record storage.Record, key string) string {
	value, _ := record[key].(string)
	return strings.TrimSpace(value)
}

func coerceTeamUserID(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 32), true
	case int:
		return strconv.Itoa(typed), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case bool:
		return strconv.FormatBool(typed), true
	default:
		return "", false
	}
}

func cloneRecordWithout(record storage.Record, keys ...string) storage.Record {
	result := cloneRecord(record)
	for _, key := range keys {
		delete(result, key)
	}
	return result
}

func removeCSVTeamID(value, teamID string) (string, bool) {
	parts := strings.Split(value, ",")
	remaining := make([]string, 0, len(parts))
	removed := false
	for _, part := range parts {
		if part == teamID {
			removed = true
			continue
		}
		remaining = append(remaining, part)
	}
	return strings.Join(remaining, ","), removed
}

func csvContainsTeamID(value, teamID string) bool {
	for _, candidate := range strings.Split(value, ",") {
		if candidate == teamID {
			return true
		}
	}
	return false
}

func (runtime *runtime) teamAdditionalInput(input storage.Record, partial bool) (storage.Record, error) {
	model, ok := runtime.schema.Models["team"]
	if !ok {
		return storage.Record{}, nil
	}
	result := storage.Record{}
	for name, attribute := range model.Fields {
		if _, base := teamBaseInputFields[name]; base {
			continue
		}
		value, present := input[name]
		if !attribute.IsInput() {
			continue
		}
		if !present {
			if !partial && attribute.IsRequired() && attribute.DefaultValue == nil {
				return nil, invalidOrganizationBody(fmt.Errorf("required team field %q is missing", name))
			}
			continue
		}
		normalized, err := normalizeTeamInputValue(attribute, value)
		if err != nil {
			return nil, invalidOrganizationBody(fmt.Errorf("team field %q: %w", name, err))
		}
		parsed, err := storage.ToRecordSchema(map[string]storage.FieldAttribute{name: attribute}, true).Parse(
			storage.Record{name: normalized},
		)
		if err != nil {
			return nil, invalidOrganizationBody(err)
		}
		if parsedValue, exists := parsed[name]; exists {
			result[name] = parsedValue
		}
	}
	return result, nil
}

func normalizeTeamInputValue(attribute storage.FieldAttribute, value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch attribute.Type {
	case storage.FieldDate:
		if typed, ok := value.(string); ok {
			parsed, err := time.Parse(time.RFC3339Nano, typed)
			if err != nil {
				return nil, errors.New("must be an RFC3339 timestamp")
			}
			return parsed, nil
		}
	case storage.FieldStringArray:
		if values, ok := value.([]any); ok {
			result := make([]string, len(values))
			for index, item := range values {
				text, valid := item.(string)
				if !valid {
					return nil, errors.New("must be an array of strings")
				}
				result[index] = text
			}
			return result, nil
		}
	}
	return value, nil
}
