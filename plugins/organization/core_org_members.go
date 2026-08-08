package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/url"
	"strconv"
	"strings"
	"sync"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type checkOrganizationSlugBody struct {
	Slug string `json:"slug"`
}

func (runtime *runtime) checkOrganizationSlugEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body checkOrganizationSlugBody
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil || raw["slug"] == nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	var slug *string
	if err := json.Unmarshal(raw["slug"], &slug); err != nil || slug == nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	body.Slug = *slug

	session, err := runtime.resolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil && (!ctx.IsDirect() || ctx.Request().Headers().Len() != 0) {
		return contract.Response{}, unauthorizedOrganization()
	}

	record, err := runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "slug", Value: body.Slug}},
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: check slug: %w", err)
	}
	if record != nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorOrganizationSlugTaken)
	}
	return contract.JSONResponse(contract.StatusOK, CheckOrganizationSlugResult{Status: true})
}

type deleteOrganizationBody struct {
	OrganizationID string `json:"organizationId"`
}

func (runtime *runtime) deleteOrganizationEndpoint(ctx *engine.Context) (contract.Response, error) {
	if runtime.options.DisableOrganizationDeletion {
		return contract.Response{}, organizationError(
			contract.StatusNotFound, ErrorOrganizationDeletionDisabled,
		)
	}
	var body deleteOrganizationBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	session, err := runtime.resolveSession(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	body.OrganizationID = strings.TrimSpace(body.OrganizationID)
	if body.OrganizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	result, err := runtime.deleteOrganization(ctx.GoContext(), session, body.OrganizationID)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) deleteOrganization(
	ctx context.Context,
	session *resolvedSession,
	organizationID string,
) (storage.Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if session == nil || session.Session == nil || session.User == nil {
		return nil, unauthorizedOrganization()
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: delete: find member: %w", err)
	}
	if member == nil {
		return nil, organizationError(contract.StatusBadRequest, ErrorUserNotOrganizationMember)
	}
	role, _ := recordString(member, "role")
	allowed, err := runtime.hasOrganizationPermission(
		ctx, organizationID, role,
		authorization.Statements{"organization": {"delete"}}, false,
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, organizationError(contract.StatusForbidden, ErrorOrganizationDeleteForbidden)
	}

	activeOrganizationID, _ := recordString(session.Session, "activeOrganizationId")
	if activeOrganizationID == organizationID {
		token, _ := recordString(session.Session, "token")
		if err := runtime.setSessionActiveOrganization(ctx, token, nil); err != nil {
			return nil, err
		}
	}

	organization, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: delete: find organization: %w", err)
	}
	if organization == nil {
		return nil, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Bad Request")
	}
	publicOrganization := runtime.publicRecord("organization", organization)
	publicOrganization = parseOrganizationMetadata(publicOrganization)
	hookData := DeleteOrganizationHookData{
		Organization: cloneRecord(publicOrganization), User: cloneRecord(session.User),
	}
	if runtime.options.Hooks.BeforeDeleteOrganization != nil {
		if err := runtime.options.Hooks.BeforeDeleteOrganization(ctx, hookData); err != nil {
			return nil, err
		}
	}

	lock := runtime.organizationLock(organizationID)
	lock.Lock()
	currentMember, currentMemberErr := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if currentMemberErr != nil {
		lock.Unlock()
		return nil, fmt.Errorf("organization: delete: recheck member: %w", currentMemberErr)
	}
	if currentMember == nil {
		lock.Unlock()
		return nil, organizationError(contract.StatusBadRequest, ErrorUserNotOrganizationMember)
	}
	currentRole, _ := recordString(currentMember, "role")
	allowed, permissionErr := runtime.hasOrganizationPermission(
		ctx, organizationID, currentRole,
		authorization.Statements{"organization": {"delete"}}, false,
	)
	if permissionErr != nil {
		lock.Unlock()
		return nil, permissionErr
	}
	if !allowed {
		lock.Unlock()
		return nil, organizationError(contract.StatusForbidden, ErrorOrganizationDeleteForbidden)
	}
	currentOrganization, currentErr := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if currentErr != nil {
		lock.Unlock()
		return nil, fmt.Errorf("organization: delete: recheck organization: %w", currentErr)
	}
	if currentOrganization == nil {
		lock.Unlock()
		return nil, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Bad Request")
	}
	err = runtime.deleteOrganizationCascade(ctx, organizationID)
	lock.Unlock()
	if err != nil {
		return nil, err
	}
	if runtime.options.Hooks.AfterDeleteOrganization != nil {
		if err := runtime.options.Hooks.AfterDeleteOrganization(ctx, hookData); err != nil {
			return nil, err
		}
	}
	return publicOrganization, nil
}

func (runtime *runtime) deleteOrganizationCascade(ctx context.Context, organizationID string) error {
	mutation := func(adapter storage.TransactionAdapter) error {
		if runtime.options.Teams.Enabled {
			teams, err := findAllOrganizationRecords(
				ctx, adapter, "team",
				[]storage.Where{{Field: "organizationId", Value: organizationID}},
			)
			if err != nil {
				return fmt.Errorf("organization: delete: list teams: %w", err)
			}
			teamIDs := recordIDs(teams)
			if len(teamIDs) != 0 {
				if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
					Model: "teamMember",
					Where: []storage.Where{{Field: "teamId", Value: teamIDs, Operator: storage.OpIn}},
				}); err != nil {
					return fmt.Errorf("organization: delete: delete team memberships: %w", err)
				}
			}
			if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
				Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
			}); err != nil {
				return fmt.Errorf("organization: delete: delete teams: %w", err)
			}
		}
		if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
			Model: "member", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		}); err != nil {
			return fmt.Errorf("organization: delete: delete members: %w", err)
		}
		if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
			Model: "invitation", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		}); err != nil {
			return fmt.Errorf("organization: delete: delete invitations: %w", err)
		}
		if runtime.options.DynamicAccessControl.Enabled {
			if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
				Model: "organizationRole", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
			}); err != nil {
				return fmt.Errorf("organization: delete: delete roles: %w", err)
			}
		}
		if err := adapter.Delete(ctx, storage.DeleteParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
		}); err != nil {
			return fmt.Errorf("organization: delete: delete organization: %w", err)
		}
		return nil
	}
	if err := runtime.adapter.Transaction(ctx, mutation); err != nil {
		if !errors.Is(err, storage.ErrTransactionsUnsupported) {
			return err
		}
		return runtime.deleteOrganizationCascadeWithoutTransaction(ctx, organizationID, mutation)
	}
	return nil
}

func (runtime *runtime) deleteOrganizationCascadeWithoutTransaction(
	ctx context.Context,
	organizationID string,
	mutation func(storage.TransactionAdapter) error,
) error {
	models := []string{"organization", "member", "invitation"}
	if runtime.options.DynamicAccessControl.Enabled {
		models = append(models, "organizationRole")
	}
	if runtime.options.Teams.Enabled {
		models = append(models, "team", "teamMember")
	}
	snapshots := make(map[string][]storage.Record, len(models))
	organization, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if err != nil {
		return err
	}
	if organization != nil {
		snapshots["organization"] = []storage.Record{cloneRecord(organization)}
	}
	for _, model := range []string{"member", "invitation", "organizationRole", "team"} {
		if model == "team" && !runtime.options.Teams.Enabled {
			continue
		}
		if model == "organizationRole" && !runtime.options.DynamicAccessControl.Enabled {
			continue
		}
		rows, listErr := findAllOrganizationRecords(
			ctx, runtime.adapter, model,
			[]storage.Where{{Field: "organizationId", Value: organizationID}},
		)
		if listErr != nil {
			return listErr
		}
		for _, row := range rows {
			snapshots[model] = append(snapshots[model], cloneRecord(row))
		}
	}
	if runtime.options.Teams.Enabled {
		teamIDs := recordIDs(snapshots["team"])
		if len(teamIDs) != 0 {
			rows, listErr := findAllOrganizationRecords(
				ctx, runtime.adapter, "teamMember",
				[]storage.Where{{Field: "teamId", Value: teamIDs, Operator: storage.OpIn}},
			)
			if listErr != nil {
				return listErr
			}
			for _, row := range rows {
				snapshots["teamMember"] = append(snapshots["teamMember"], cloneRecord(row))
			}
		}
	}

	if err := mutation(runtime.adapter); err != nil {
		if restoreErr := runtime.restoreOrganizationSnapshots(ctx, snapshots); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return err
	}
	return nil
}

func (runtime *runtime) restoreOrganizationSnapshots(
	ctx context.Context,
	snapshots map[string][]storage.Record,
) error {
	order := []string{"organization", "organizationRole", "team", "member", "invitation", "teamMember"}
	var restoreErrors []error
	for _, model := range order {
		for _, row := range snapshots[model] {
			id, _ := recordString(row, "id")
			if id != "" {
				existing, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
					Model: model, Where: []storage.Where{{Field: "id", Value: id}},
				})
				if err != nil {
					restoreErrors = append(restoreErrors, err)
					continue
				}
				if existing != nil {
					continue
				}
			}
			if _, err := runtime.adapter.Create(ctx, storage.CreateParams{
				Model: model, Data: cloneRecord(row), ForceAllowID: id != "",
			}); err != nil && !errors.Is(err, storage.ErrUniqueConstraint) {
				restoreErrors = append(restoreErrors, err)
			}
		}
	}
	return errors.Join(restoreErrors...)
}

func (runtime *runtime) listOrganizationsEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	userID, _ := recordString(session.User, "id")
	organizations, err := runtime.listOrganizations(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, organizations)
}

func (runtime *runtime) listOrganizations(ctx context.Context, userID string) ([]storage.Record, error) {
	memberships, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: list organizations: list memberships: %w", err)
	}
	if len(memberships) == 0 {
		return []storage.Record{}, nil
	}
	organizationIDs := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		if organizationID, ok := recordString(membership, "organizationId"); ok {
			organizationIDs = append(organizationIDs, organizationID)
		}
	}
	organizations, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "organization",
		Where: []storage.Where{{Field: "id", Value: organizationIDs, Operator: storage.OpIn}},
		Limit: storage.Int(len(organizationIDs)),
	})
	if err != nil {
		return nil, fmt.Errorf("organization: list organizations: find organizations: %w", err)
	}
	byID := make(map[string]storage.Record, len(organizations))
	for _, organization := range organizations {
		id, _ := recordString(organization, "id")
		byID[id] = parseOrganizationMetadata(runtime.publicRecord("organization", organization))
	}
	result := make([]storage.Record, 0, len(organizationIDs))
	for _, organizationID := range organizationIDs {
		if organization := byID[organizationID]; organization != nil {
			result = append(result, cloneRecord(organization))
		}
	}
	return result, nil
}

func (runtime *runtime) publicRecord(model string, record storage.Record) storage.Record {
	result := cloneRecord(record)
	if result == nil {
		return nil
	}
	modelSchema, ok := runtime.schema.Models[model]
	if !ok {
		return result
	}
	for field, attribute := range modelSchema.Fields {
		if !attribute.IsReturned() {
			delete(result, field)
		}
	}
	return result
}

func parseOrganizationMetadata(record storage.Record) storage.Record {
	if record == nil {
		return nil
	}
	result := cloneRecord(record)
	metadata, ok := result["metadata"].(string)
	if !ok || strings.TrimSpace(metadata) == "" {
		return result
	}
	var decoded any
	if json.Unmarshal([]byte(metadata), &decoded) == nil {
		result["metadata"] = decoded
	}
	return result
}

func recordIDs(records []storage.Record) []string {
	result := make([]string, 0, len(records))
	for _, record := range records {
		if id, ok := recordString(record, "id"); ok && id != "" {
			result = append(result, id)
		}
	}
	return result
}

func findAllOrganizationRecords(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	model string,
	where []storage.Where,
) ([]storage.Record, error) {
	count, err := adapter.Count(ctx, storage.CountParams{Model: model, Where: where})
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return []storage.Record{}, nil
	}
	maxInt := int64(^uint(0) >> 1)
	if count > maxInt {
		return nil, fmt.Errorf("organization: %s row count %d exceeds platform limit", model, count)
	}
	limit := int(count)
	return adapter.FindMany(ctx, storage.FindManyParams{
		Model: model, Where: where, Limit: &limit,
	})
}

func (runtime *runtime) organizationLock(organizationID string) *sync.Mutex {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(organizationID))
	return &runtime.organizationLocks[hash.Sum32()%uint32(len(runtime.organizationLocks))]
}

type updateMemberRoleBody struct {
	Role           json.RawMessage `json:"role"`
	MemberID       string          `json:"memberId"`
	OrganizationID string          `json:"organizationId"`
}

type updateMemberRoleState struct {
	Actor        storage.Record
	Target       storage.Record
	Organization storage.Record
	User         storage.Record
}

func (runtime *runtime) updateMemberRoleEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body updateMemberRoleBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	roles, err := normalizeMemberRoles(body.Role)
	if err != nil || strings.TrimSpace(body.MemberID) == "" {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	organizationID := strings.TrimSpace(body.OrganizationID)
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	if err := runtime.validateOrganizationRoles(ctx.GoContext(), organizationID, roles); err != nil {
		return contract.Response{}, err
	}
	actorUserID, _ := recordString(session.User, "id")
	requestedRole := strings.Join(roles, ",")

	initial, err := runtime.loadUpdateMemberRoleState(
		ctx.GoContext(), actorUserID, strings.TrimSpace(body.MemberID), organizationID, roles,
	)
	if err != nil {
		return contract.Response{}, err
	}
	effectiveRole := requestedRole
	if runtime.options.Hooks.BeforeUpdateMemberRole != nil {
		override, hookErr := runtime.options.Hooks.BeforeUpdateMemberRole(
			ctx.GoContext(), UpdateMemberRoleBeforeData{
				Member: cloneRecord(initial.Target), NewRole: requestedRole,
				User: cloneRecord(initial.User), Organization: cloneRecord(initial.Organization),
			},
		)
		if hookErr != nil {
			return contract.Response{}, hookErr
		}
		if overrideRole, ok := recordString(override, "role"); ok && overrideRole != "" {
			effectiveRole = overrideRole
		}
	}
	effectiveRoles := normalizeRoleStrings([]string{effectiveRole})
	if len(effectiveRoles) == 0 {
		return contract.Response{}, invalidOrganizationBody(nil)
	}
	if err := runtime.validateOrganizationRoles(ctx.GoContext(), organizationID, effectiveRoles); err != nil {
		return contract.Response{}, err
	}
	effectiveRole = strings.Join(effectiveRoles, ",")

	lock := runtime.organizationLock(organizationID)
	lock.Lock()
	// A dynamic role can be renamed or deleted after the pre-hook validation.
	// Revalidate while holding the same organization mutation lock used by role
	// updates/deletes so a member is never committed with a role that ceased to
	// exist during this request.
	if err := runtime.validateOrganizationRoles(ctx.GoContext(), organizationID, effectiveRoles); err != nil {
		lock.Unlock()
		return contract.Response{}, err
	}
	state, err := runtime.loadUpdateMemberRoleState(
		ctx.GoContext(), actorUserID, strings.TrimSpace(body.MemberID), organizationID, effectiveRoles,
	)
	if err != nil {
		lock.Unlock()
		return contract.Response{}, err
	}
	previousRole, _ := recordString(state.Target, "role")
	updated, err := runtime.adapter.IncrementOne(ctx.GoContext(), storage.IncrementOneParams{
		Model: "member",
		Where: []storage.Where{
			{Field: "id", Value: strings.TrimSpace(body.MemberID)},
			{Field: "organizationId", Value: organizationID},
		},
		Set: storage.Record{"role": effectiveRole},
	})
	lock.Unlock()
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: update member role: %w", err)
	}
	if updated == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	if runtime.options.Hooks.AfterUpdateMemberRole != nil {
		if err := runtime.options.Hooks.AfterUpdateMemberRole(
			ctx.GoContext(), UpdateMemberRoleAfterData{
				Member: cloneRecord(updated), PreviousRole: previousRole,
				User: cloneRecord(state.User), Organization: cloneRecord(state.Organization),
			},
		); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(contract.StatusOK, runtime.publicRecord("member", updated))
}

func (runtime *runtime) loadUpdateMemberRoleState(
	ctx context.Context,
	actorUserID string,
	memberID string,
	organizationID string,
	rolesToSet []string,
) (updateMemberRoleState, error) {
	actor, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: actorUserID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return updateMemberRoleState{}, fmt.Errorf("organization: update member role: find actor: %w", err)
	}
	if actor == nil {
		return updateMemberRoleState{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	target := actor
	actorMemberID, _ := recordString(actor, "id")
	if actorMemberID != memberID {
		target, err = runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "member", Where: []storage.Where{{Field: "id", Value: memberID}},
		})
		if err != nil {
			return updateMemberRoleState{}, fmt.Errorf("organization: update member role: find target: %w", err)
		}
	}
	if target == nil {
		return updateMemberRoleState{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	targetOrganizationID, _ := recordString(target, "organizationId")
	if targetOrganizationID != organizationID {
		return updateMemberRoleState{}, organizationError(contract.StatusForbidden, ErrorMemberUpdateForbidden)
	}

	actorRole, _ := recordString(actor, "role")
	targetRole, _ := recordString(target, "role")
	actorIsCreator := roleIncludes(actorRole, runtime.creatorRole)
	targetIsCreator := roleIncludes(targetRole, runtime.creatorRole)
	settingCreator := stringSliceContains(rolesToSet, runtime.creatorRole)
	if (targetIsCreator && !actorIsCreator) || (settingCreator && !actorIsCreator) {
		return updateMemberRoleState{}, organizationError(contract.StatusForbidden, ErrorMemberUpdateForbidden)
	}
	if actorIsCreator && actorMemberID == memberID && !settingCreator {
		members, listErr := findAllOrganizationRecords(
			ctx, runtime.adapter, "member",
			[]storage.Where{{Field: "organizationId", Value: organizationID}},
		)
		if listErr != nil {
			return updateMemberRoleState{}, fmt.Errorf("organization: update member role: list owners: %w", listErr)
		}
		owners := 0
		for _, member := range members {
			role, _ := recordString(member, "role")
			if roleIncludes(role, runtime.creatorRole) {
				owners++
			}
		}
		if owners <= 1 {
			return updateMemberRoleState{}, organizationError(
				contract.StatusBadRequest, ErrorOrganizationWithoutOwner,
			)
		}
	}
	allowed, permissionErr := runtime.hasOrganizationPermission(
		ctx, organizationID, actorRole,
		authorization.Statements{"member": {"update"}}, true,
	)
	if permissionErr != nil {
		return updateMemberRoleState{}, permissionErr
	}
	if !allowed {
		return updateMemberRoleState{}, organizationError(contract.StatusForbidden, ErrorMemberUpdateForbidden)
	}

	organization, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if err != nil {
		return updateMemberRoleState{}, fmt.Errorf("organization: update member role: find organization: %w", err)
	}
	if organization == nil {
		return updateMemberRoleState{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	targetUserID, _ := recordString(target, "userId")
	user, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: targetUserID}},
	})
	if err != nil {
		return updateMemberRoleState{}, fmt.Errorf("organization: update member role: find user: %w", err)
	}
	if user == nil {
		return updateMemberRoleState{}, contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "User not found",
		)
	}
	target = cloneRecord(target)
	target["user"] = publicMemberUserRecord(user)
	return updateMemberRoleState{
		Actor: cloneRecord(actor), Target: target,
		Organization: parseOrganizationMetadata(runtime.publicRecord("organization", organization)),
		User:         cloneRecord(user),
	}, nil
}

func normalizeMemberRoles(raw json.RawMessage) ([]string, error) {
	roles, err := decodeMemberRoles(raw)
	if err != nil {
		return nil, err
	}
	roles = normalizeRoleStrings(roles)
	if len(roles) == 0 {
		return nil, errors.New("role is required")
	}
	return roles, nil
}

func normalizeRoleStrings(roles []string) []string {
	result := make([]string, 0, len(roles))
	for _, roleGroup := range roles {
		for _, role := range strings.Split(roleGroup, ",") {
			role = strings.TrimSpace(role)
			if role != "" {
				result = append(result, role)
			}
		}
	}
	return result
}

func validateStaticRoles(roles []string) error {
	unknown := make([]string, 0)
	for _, role := range roles {
		switch role {
		case "owner", "admin", "member":
		default:
			unknown = append(unknown, role)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return contract.NewAPIError(
		contract.StatusBadRequest,
		ErrorRoleNotFound,
		ErrorRoleNotFound+": "+strings.Join(unknown, ", "),
	)
}

type leaveOrganizationBody struct {
	OrganizationID string `json:"organizationId"`
}

func (runtime *runtime) leaveOrganizationEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body leaveOrganizationBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil || strings.TrimSpace(body.OrganizationID) == "" {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	userID, _ := recordString(session.User, "id")
	token, _ := recordString(session.Session, "token")
	activeOrganizationID, _ := recordString(session.Session, "activeOrganizationId")
	member, err := runtime.leaveOrganization(
		ctx.GoContext(), userID, token, activeOrganizationID, strings.TrimSpace(body.OrganizationID),
	)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, member)
}

func (runtime *runtime) leaveOrganization(
	ctx context.Context,
	userID string,
	sessionToken string,
	activeOrganizationID string,
	organizationID string,
) (storage.Record, error) {
	lock := runtime.organizationLock(organizationID)
	lock.Lock()
	member, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		lock.Unlock()
		return nil, fmt.Errorf("organization: leave: find member: %w", err)
	}
	if member == nil {
		lock.Unlock()
		return nil, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	role, _ := recordString(member, "role")
	if roleIncludes(role, runtime.creatorRole) {
		members, listErr := findAllOrganizationRecords(
			ctx, runtime.adapter, "member",
			[]storage.Where{{Field: "organizationId", Value: organizationID}},
		)
		if listErr != nil {
			lock.Unlock()
			return nil, fmt.Errorf("organization: leave: list owners: %w", listErr)
		}
		owners := 0
		for _, candidate := range members {
			candidateRole, _ := recordString(candidate, "role")
			if roleIncludes(candidateRole, runtime.creatorRole) {
				owners++
			}
		}
		if owners <= 1 {
			lock.Unlock()
			return nil, organizationError(contract.StatusBadRequest, ErrorOnlyOwner)
		}
	}
	memberID, _ := recordString(member, "id")
	err = runtime.deleteMemberRows(ctx, memberID, organizationID, userID)
	lock.Unlock()
	if err != nil {
		return nil, err
	}
	if activeOrganizationID == organizationID {
		if err := runtime.setSessionActiveOrganization(ctx, sessionToken, nil); err != nil {
			return nil, err
		}
	}
	return runtime.publicRecord("member", member), nil
}

func (runtime *runtime) deleteMemberRows(
	ctx context.Context,
	memberID string,
	organizationID string,
	userID string,
) error {
	mutation := func(adapter storage.TransactionAdapter) error {
		if err := adapter.Delete(ctx, storage.DeleteParams{
			Model: "member", Where: []storage.Where{
				{Field: "id", Value: memberID},
				{Field: "organizationId", Value: organizationID},
				{Field: "userId", Value: userID},
			},
		}); err != nil {
			return fmt.Errorf("organization: leave: delete member: %w", err)
		}
		if !runtime.options.Teams.Enabled {
			return nil
		}
		teams, err := adapter.FindMany(ctx, storage.FindManyParams{
			Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if err != nil {
			return fmt.Errorf("organization: leave: list teams: %w", err)
		}
		teamIDs := recordIDs(teams)
		if len(teamIDs) == 0 {
			return nil
		}
		if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
			Model: "teamMember", Where: []storage.Where{
				{Field: "userId", Value: userID},
				{Field: "teamId", Value: teamIDs, Operator: storage.OpIn},
			},
		}); err != nil {
			return fmt.Errorf("organization: leave: delete team memberships: %w", err)
		}
		return nil
	}
	if err := runtime.adapter.Transaction(ctx, mutation); err != nil {
		if !errors.Is(err, storage.ErrTransactionsUnsupported) {
			return err
		}
		snapshots := map[string][]storage.Record{}
		member, findErr := runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "member", Where: []storage.Where{{Field: "id", Value: memberID}},
		})
		if findErr != nil {
			return findErr
		}
		if member != nil {
			snapshots["member"] = []storage.Record{cloneRecord(member)}
		}
		if runtime.options.Teams.Enabled {
			teams, listErr := findAllOrganizationRecords(
				ctx, runtime.adapter, "team",
				[]storage.Where{{Field: "organizationId", Value: organizationID}},
			)
			if listErr != nil {
				return listErr
			}
			teamIDs := recordIDs(teams)
			if len(teamIDs) != 0 {
				rows, listErr := findAllOrganizationRecords(
					ctx, runtime.adapter, "teamMember", []storage.Where{
						{Field: "userId", Value: userID},
						{Field: "teamId", Value: teamIDs, Operator: storage.OpIn},
					},
				)
				if listErr != nil {
					return listErr
				}
				for _, row := range rows {
					snapshots["teamMember"] = append(snapshots["teamMember"], cloneRecord(row))
				}
			}
		}
		if mutationErr := mutation(runtime.adapter); mutationErr != nil {
			if restoreErr := runtime.restoreOrganizationSnapshots(ctx, snapshots); restoreErr != nil {
				return errors.Join(mutationErr, restoreErr)
			}
			return mutationErr
		}
	}
	return nil
}

func (runtime *runtime) listMembersEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidOrganizationQuery(err)
	}
	activeOrganizationID, _ := recordString(session.Session, "activeOrganizationId")
	organizationID, err := runtime.resolveOrganizationID(
		ctx.GoContext(), query, activeOrganizationID,
	)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(session.User, "id")
	result, err := runtime.listMembers(ctx.GoContext(), userID, organizationID, query)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) listMembers(
	ctx context.Context,
	userID string,
	organizationID string,
	query url.Values,
) (ListMembersResult, error) {
	if direction := query.Get("sortDirection"); direction != "" && direction != "asc" && direction != "desc" {
		return ListMembersResult{}, invalidOrganizationQuery(fmt.Errorf("invalid sortDirection"))
	}
	if rawOperator := strings.TrimSpace(query.Get("filterOperator")); rawOperator != "" {
		if !validOrganizationFilterOperator(storage.Operator(rawOperator)) {
			return ListMembersResult{}, invalidOrganizationQuery(fmt.Errorf("invalid filterOperator"))
		}
	}
	member, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return ListMembersResult{}, fmt.Errorf("organization: list members: find membership: %w", err)
	}
	if member == nil {
		return ListMembersResult{}, organizationError(
			contract.StatusForbidden, ErrorNotMemberOfOrganization,
		)
	}

	limit := runtime.options.MembershipLimit
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 0 {
			return ListMembersResult{}, invalidOrganizationQuery(parseErr)
		}
		if parsed > 0 {
			limit = parsed
		}
	}
	offset := 0
	if raw := strings.TrimSpace(query.Get("offset")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 0 {
			return ListMembersResult{}, invalidOrganizationQuery(parseErr)
		}
		offset = parsed
	}
	var sortBy *storage.Sort
	if field := strings.TrimSpace(query.Get("sortBy")); field != "" {
		direction := storage.Ascending
		switch query.Get("sortDirection") {
		case "", "asc":
		case "desc":
			direction = storage.Descending
		default:
			return ListMembersResult{}, invalidOrganizationQuery(
				fmt.Errorf("invalid sortDirection"),
			)
		}
		sortBy = &storage.Sort{Field: field, Direction: direction}
	}
	filter, err := runtime.memberFilterFromQuery(query)
	if err != nil {
		return ListMembersResult{}, err
	}
	where := []storage.Where{{Field: "organizationId", Value: organizationID}}
	if filter != nil {
		where = append(where, *filter)
	}
	members, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "member", Where: where, Limit: storage.Int(limit), Offset: storage.Int(offset), SortBy: sortBy,
	})
	if err != nil {
		return ListMembersResult{}, fmt.Errorf("organization: list members: find members: %w", err)
	}
	total, err := runtime.adapter.Count(ctx, storage.CountParams{Model: "member", Where: where})
	if err != nil {
		return ListMembersResult{}, fmt.Errorf("organization: list members: count members: %w", err)
	}

	usersByID := make(map[string]storage.Record, len(members))
	if len(members) != 0 {
		userIDs := make([]string, 0, len(members))
		for _, candidate := range members {
			if candidateUserID, ok := recordString(candidate, "userId"); ok {
				userIDs = append(userIDs, candidateUserID)
			}
		}
		users, usersErr := runtime.adapter.FindMany(ctx, storage.FindManyParams{
			Model: "user",
			Where: []storage.Where{{Field: "id", Value: userIDs, Operator: storage.OpIn}},
			Limit: storage.Int(len(members)),
		})
		if usersErr != nil {
			return ListMembersResult{}, fmt.Errorf("organization: list members: find users: %w", usersErr)
		}
		for _, user := range users {
			if candidateUserID, ok := recordString(user, "id"); ok {
				usersByID[candidateUserID] = user
			}
		}
	}

	result := ListMembersResult{Members: make([]storage.Record, 0, len(members)), Total: total}
	for _, candidate := range members {
		candidateUserID, _ := recordString(candidate, "userId")
		user := usersByID[candidateUserID]
		if user == nil {
			return ListMembersResult{}, fmt.Errorf(
				"organization: list members: unexpected user not found for member %q",
				candidate["id"],
			)
		}
		publicMember := runtime.publicRecord("member", candidate)
		publicMember["user"] = publicMemberUserRecord(user)
		result.Members = append(result.Members, publicMember)
	}
	return result, nil
}

func (runtime *runtime) memberFilterFromQuery(query url.Values) (*storage.Where, error) {
	field := strings.TrimSpace(query.Get("filterField"))
	operator := storage.OpEq
	if raw := strings.TrimSpace(query.Get("filterOperator")); raw != "" {
		operator = storage.Operator(raw)
		if !validOrganizationFilterOperator(operator) {
			return nil, invalidOrganizationQuery(fmt.Errorf("invalid filterOperator"))
		}
	}
	if field == "" {
		return nil, nil
	}
	value := runtime.memberFilterValue(field, query)
	if operator == storage.OpIn || operator == storage.OpNotIn {
		if !isSliceValue(value) {
			value = []string{fmt.Sprint(value)}
		}
	}
	clause := storage.Where{Field: field, Value: value, Operator: operator}
	if _, err := clause.Normalize(); err != nil {
		return nil, invalidOrganizationQuery(err)
	}
	return &clause, nil
}

func validOrganizationFilterOperator(operator storage.Operator) bool {
	switch operator {
	case storage.OpEq, storage.OpNe, storage.OpLt, storage.OpLTE, storage.OpGt,
		storage.OpGTE, storage.OpIn, storage.OpNotIn, storage.OpContains,
		storage.OpStartsWith, storage.OpEndsWith:
		return true
	default:
		return false
	}
}

func (runtime *runtime) memberFilterValue(field string, query url.Values) any {
	values, present := query["filterValue"]
	if !present || len(values) == 0 {
		return nil
	}
	attribute, hasAttribute := runtime.schema.Models["member"].Fields[field]
	if len(values) > 1 {
		return coerceMemberFilterSlice(values, attribute, hasAttribute)
	}
	raw := values[0]
	if strings.HasPrefix(strings.TrimSpace(raw), "[") {
		var decoded any
		if json.Unmarshal([]byte(raw), &decoded) == nil {
			return decoded
		}
	}
	if hasAttribute {
		switch attribute.Type {
		case storage.FieldNumber:
			if number, err := strconv.ParseFloat(raw, 64); err == nil {
				return number
			}
		case storage.FieldBoolean:
			if boolean, err := strconv.ParseBool(raw); err == nil {
				return boolean
			}
		case storage.FieldStringArray, storage.FieldNumberArray:
			parts := strings.Split(raw, ",")
			return coerceMemberFilterSlice(parts, attribute, true)
		}
	}
	return raw
}

func coerceMemberFilterSlice(
	values []string,
	attribute storage.FieldAttribute,
	hasAttribute bool,
) any {
	if hasAttribute && (attribute.Type == storage.FieldNumber || attribute.Type == storage.FieldNumberArray) {
		numbers := make([]float64, 0, len(values))
		for _, value := range values {
			number, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return append([]string(nil), values...)
			}
			numbers = append(numbers, number)
		}
		return numbers
	}
	return append([]string(nil), values...)
}

func isSliceValue(value any) bool {
	switch value.(type) {
	case []string, []int, []int64, []float64, []any:
		return true
	default:
		return false
	}
}

func publicMemberUserRecord(user storage.Record) storage.Record {
	result := storage.Record{
		"id": user["id"], "name": user["name"], "email": user["email"], "image": nil,
	}
	if image, ok := user["image"]; ok {
		result["image"] = image
	}
	return result
}

func (runtime *runtime) getActiveMemberRoleEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidOrganizationQuery(err)
	}
	activeOrganizationID, _ := recordString(session.Session, "activeOrganizationId")
	organizationID, err := runtime.resolveOrganizationID(ctx.GoContext(), query, activeOrganizationID)
	if err != nil {
		return contract.Response{}, err
	}
	currentUserID, _ := recordString(session.User, "id")
	actor, err := runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: currentUserID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: get active member role: find actor: %w", err)
	}
	if actor == nil {
		return contract.Response{}, organizationError(contract.StatusForbidden, ErrorNotMemberOfOrganization)
	}
	targetUserID := strings.TrimSpace(query.Get("userId"))
	member := actor
	if targetUserID != "" {
		member, err = runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "member", Where: []storage.Where{
				{Field: "userId", Value: targetUserID},
				{Field: "organizationId", Value: organizationID},
			},
		})
		if err != nil {
			return contract.Response{}, fmt.Errorf("organization: get active member role: find target: %w", err)
		}
		if member == nil {
			return contract.Response{}, organizationError(contract.StatusForbidden, ErrorNotMemberOfOrganization)
		}
	}
	role, _ := recordString(member, "role")
	return contract.JSONResponse(contract.StatusOK, ActiveMemberRoleResult{Role: role})
}

func (runtime *runtime) resolveOrganizationID(
	ctx context.Context,
	query url.Values,
	activeOrganizationID string,
) (string, error) {
	organizationID := strings.TrimSpace(query.Get("organizationId"))
	if organizationID == "" {
		organizationID = strings.TrimSpace(activeOrganizationID)
	}
	if slug := strings.TrimSpace(query.Get("organizationSlug")); slug != "" {
		organization, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "slug", Value: slug}},
		})
		if err != nil {
			return "", fmt.Errorf("organization: resolve organization slug: %w", err)
		}
		if organization == nil {
			return "", organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
		}
		organizationID, _ = recordString(organization, "id")
	}
	if organizationID == "" {
		return "", organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	return organizationID, nil
}

type hasPermissionBody struct {
	OrganizationID string              `json:"organizationId"`
	Permission     map[string][]string `json:"permission"`
	Permissions    map[string][]string `json:"permissions"`
}

func (runtime *runtime) hasPermissionEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body hasPermissionBody
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	_, hasLegacy := raw["permission"]
	_, hasCurrent := raw["permissions"]
	if hasLegacy == hasCurrent {
		return contract.Response{}, invalidOrganizationBody(nil)
	}
	permissions := body.Permissions
	if hasLegacy {
		permissions = body.Permission
	}
	if permissions == nil {
		return contract.Response{}, invalidOrganizationBody(nil)
	}
	for _, actions := range permissions {
		if actions == nil {
			return contract.Response{}, invalidOrganizationBody(nil)
		}
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	organizationID := strings.TrimSpace(body.OrganizationID)
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: has permission: find member: %w", err)
	}
	if member == nil {
		return contract.Response{}, organizationError(
			contract.StatusUnauthorized, ErrorUserNotOrganizationMember,
		)
	}
	role, _ := recordString(member, "role")
	success, err := runtime.hasOrganizationPermission(
		ctx.GoContext(), organizationID, role, authorization.Statements(permissions), false,
	)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, HasPermissionResult{
		Error: nil, Success: success,
	})
}

func roleIncludes(role, candidate string) bool {
	return stringSliceContains(strings.Split(role, ","), candidate)
}

func stringSliceContains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func invalidOrganizationQuery(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters",
	).WithCause(err)
}
