package organization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/storage"
)

type addMemberBody struct {
	OrganizationID string          `json:"organizationId"`
	UserID         string          `json:"userId"`
	Role           json.RawMessage `json:"role"`
}

type removeMemberBody struct {
	MemberIDOrEmail string `json:"memberIdOrEmail"`
	OrganizationID  string `json:"organizationId"`
}

type removeMemberInput struct {
	MemberIDOrEmail string
	OrganizationID  string
	SessionToken    string
	ActiveOrgID     string
}

type removeMemberResult struct {
	Member Member `json:"member"`
}

func (runtime *runtime) addMemberEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body addMemberBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		).WithCause(err)
	}
	roles, err := decodeMemberRoles(body.Role)
	if err != nil || body.OrganizationID == "" || body.UserID == "" {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		).WithCause(err)
	}
	member, err := runtime.addMember(ctx.GoContext(), AddMemberInput{
		OrganizationID: body.OrganizationID,
		UserID:         body.UserID,
		Roles:          roles,
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, member)
}

func (runtime *runtime) addMember(ctx context.Context, input AddMemberInput) (Member, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if input.OrganizationID == "" || input.UserID == "" || input.Roles == nil {
		return Member{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		)
	}
	organization, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization",
		Where: []storage.Where{{Field: "id", Value: input.OrganizationID}},
	})
	if err != nil {
		return Member{}, fmt.Errorf("organization: add member: find organization: %w", err)
	}
	if organization == nil {
		return Member{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	user, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: input.UserID}},
	})
	if err != nil {
		return Member{}, fmt.Errorf("organization: add member: find user: %w", err)
	}
	if user == nil {
		return Member{}, contract.NewAPIError(
			contract.StatusBadRequest, "USER_NOT_FOUND", "User not found",
		)
	}
	existing, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member",
		Where: []storage.Where{
			{Field: "userId", Value: input.UserID},
			{Field: "organizationId", Value: input.OrganizationID},
		},
	})
	if err != nil {
		return Member{}, fmt.Errorf("organization: add member: find existing member: %w", err)
	}
	if existing != nil {
		return Member{}, organizationError(contract.StatusBadRequest, ErrorUserAlreadyMember)
	}
	created, err := runtime.adapter.Create(ctx, storage.CreateParams{
		Model: "member",
		Data: storage.Record{
			"organizationId": input.OrganizationID,
			"userId":         input.UserID,
			"role":           strings.Join(input.Roles, ","),
			"createdAt":      runtime.clock(),
		},
	})
	if err != nil {
		return Member{}, fmt.Errorf("organization: add member: create member: %w", err)
	}
	return runtime.memberFromRecord(created), nil
}

func (runtime *runtime) removeMemberEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body removeMemberBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil || strings.TrimSpace(body.MemberIDOrEmail) == "" {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		).WithCause(err)
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized",
		)
	}
	organizationID := strings.TrimSpace(body.OrganizationID)
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	actorID, _ := recordString(session.User, "id")
	sessionToken, _ := recordString(session.Session, "token")
	activeOrgID, _ := recordString(session.Session, "activeOrganizationId")
	result, err := runtime.removeMember(ctx.GoContext(), actorID, removeMemberInput{
		MemberIDOrEmail: strings.TrimSpace(body.MemberIDOrEmail),
		OrganizationID:  organizationID,
		SessionToken:    sessionToken,
		ActiveOrgID:     activeOrgID,
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) removeMember(
	ctx context.Context,
	actorUserID string,
	input removeMemberInput,
) (removeMemberResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if actorUserID == "" {
		return removeMemberResult{}, contract.NewAPIError(
			contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized",
		)
	}
	if input.OrganizationID == "" || input.MemberIDOrEmail == "" {
		return removeMemberResult{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		)
	}

	actor, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: actorUserID},
			{Field: "organizationId", Value: input.OrganizationID},
		},
	})
	if err != nil {
		return removeMemberResult{}, fmt.Errorf("organization: remove member: find actor: %w", err)
	}
	if actor == nil {
		return removeMemberResult{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}

	target, err := runtime.findMemberForRemoval(ctx, input)
	if err != nil {
		return removeMemberResult{}, err
	}
	if target == nil {
		return removeMemberResult{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	actorRole, _ := recordString(actor, "role")
	targetRole, _ := recordString(target, "role")
	actorIsOwner := hasAllowedRole(actorRole, []string{runtime.creatorRole})
	if hasAllowedRole(targetRole, []string{runtime.creatorRole}) {
		if !actorIsOwner {
			return removeMemberResult{}, organizationError(contract.StatusBadRequest, ErrorOnlyOwner)
		}
		members, listErr := runtime.adapter.FindMany(ctx, storage.FindManyParams{
			Model: "member", Where: []storage.Where{{Field: "organizationId", Value: input.OrganizationID}},
		})
		if listErr != nil {
			return removeMemberResult{}, fmt.Errorf("organization: remove member: list owners: %w", listErr)
		}
		owners := 0
		for _, member := range members {
			role, _ := recordString(member, "role")
			if hasAllowedRole(role, []string{runtime.creatorRole}) {
				owners++
			}
		}
		if owners <= 1 {
			return removeMemberResult{}, organizationError(contract.StatusBadRequest, ErrorOnlyOwner)
		}
	}
	allowed, permissionErr := runtime.hasOrganizationPermission(
		ctx, input.OrganizationID, actorRole,
		authorization.Statements{"member": {"delete"}}, false,
	)
	if permissionErr != nil {
		return removeMemberResult{}, permissionErr
	}
	if !allowed {
		return removeMemberResult{}, organizationError(contract.StatusUnauthorized, ErrorMemberDeleteForbidden)
	}

	targetID, _ := recordString(target, "id")
	targetUserID, _ := recordString(target, "userId")
	if targetID == "" {
		return removeMemberResult{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	var afterTransaction func(context.Context) error
	if actorUserID == targetUserID && input.ActiveOrgID == input.OrganizationID {
		afterTransaction = func(afterContext context.Context) error {
			return runtime.setSessionActiveOrganization(afterContext, input.SessionToken, nil)
		}
	}
	joinedUser, _ := target["user"].(storage.Record)
	removed, err := runtime.removeMemberLifecycleWithUser(ctx, RemoveMemberInput{
		MemberID:         targetID,
		OrganizationID:   input.OrganizationID,
		UserID:           targetUserID,
		AfterTransaction: afterTransaction,
	}, joinedUser)
	if err != nil {
		return removeMemberResult{}, err
	}
	return removeMemberResult{Member: removed}, nil
}

func (runtime *runtime) removeMemberLifecycle(
	ctx context.Context,
	input RemoveMemberInput,
) (Member, error) {
	return runtime.removeMemberLifecycleWithUser(ctx, input, nil)
}

func (runtime *runtime) removeMemberLifecycleWithUser(
	ctx context.Context,
	input RemoveMemberInput,
	joinedUser storage.Record,
) (Member, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if runtime == nil || runtime.adapter == nil {
		return Member{}, fmt.Errorf("organization: remove member lifecycle requires a bound adapter")
	}
	if strings.TrimSpace(input.OrganizationID) == "" || strings.TrimSpace(input.UserID) == "" {
		return Member{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		)
	}

	memberWhere := []storage.Where{
		{Field: "organizationId", Value: input.OrganizationID},
		{Field: "userId", Value: input.UserID},
	}
	if input.MemberID != "" {
		memberWhere = append(memberWhere, storage.Where{Field: "id", Value: input.MemberID})
	}
	memberRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: memberWhere,
	})
	if err != nil {
		return Member{}, fmt.Errorf("organization: remove member lifecycle: find member: %w", err)
	}
	if memberRecord == nil {
		return Member{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	if joinedUser != nil {
		memberRecord = cloneRecord(memberRecord)
		memberRecord["user"] = cloneRecord(joinedUser)
	}
	organizationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: input.OrganizationID}},
	})
	if err != nil {
		return Member{}, fmt.Errorf("organization: remove member lifecycle: find organization: %w", err)
	}
	if organizationRecord == nil {
		return Member{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	userRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: input.UserID}},
	})
	if err != nil {
		return Member{}, fmt.Errorf("organization: remove member lifecycle: find user: %w", err)
	}
	if userRecord == nil {
		return Member{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "User not found")
	}

	hookData := RemoveMemberHookData{
		Member: cloneRecord(memberRecord), User: cloneRecord(userRecord), Organization: cloneRecord(organizationRecord),
	}
	if runtime.options.Hooks.BeforeRemoveMember != nil {
		if err = runtime.options.Hooks.BeforeRemoveMember(ctx, hookData); err != nil {
			return Member{}, err
		}
	}
	memberID, _ := recordString(hookData.Member, "id")
	err = runtime.adapter.Transaction(ctx, func(adapter storage.TransactionAdapter) error {
		if deleteErr := adapter.Delete(ctx, storage.DeleteParams{
			Model: "member", Where: []storage.Where{
				{Field: "id", Value: memberID},
				{Field: "organizationId", Value: input.OrganizationID},
				{Field: "userId", Value: input.UserID},
			},
		}); deleteErr != nil {
			return fmt.Errorf("organization: remove member lifecycle: delete member: %w", deleteErr)
		}
		if runtime.options.Teams.Enabled {
			teams, listErr := adapter.FindMany(ctx, storage.FindManyParams{
				Model: "team", Where: []storage.Where{{Field: "organizationId", Value: input.OrganizationID}},
			})
			if listErr != nil {
				return fmt.Errorf("organization: remove member lifecycle: list teams: %w", listErr)
			}
			teamIDs := make([]string, 0, len(teams))
			for _, team := range teams {
				if teamID, ok := recordString(team, "id"); ok && teamID != "" {
					teamIDs = append(teamIDs, teamID)
				}
			}
			if len(teamIDs) != 0 {
				if _, deleteErr := adapter.DeleteMany(ctx, storage.DeleteManyParams{
					Model: "teamMember", Where: []storage.Where{
						{Field: "userId", Value: input.UserID},
						{Field: "teamId", Value: teamIDs, Operator: storage.OpIn},
					},
				}); deleteErr != nil {
					return fmt.Errorf("organization: remove member lifecycle: delete team memberships: %w", deleteErr)
				}
			}
		}
		if input.TransactionMutation != nil {
			if mutationErr := input.TransactionMutation(ctx, adapter); mutationErr != nil {
				return mutationErr
			}
		}
		return nil
	})
	if err != nil {
		return Member{}, err
	}
	if input.AfterTransaction != nil {
		if err = input.AfterTransaction(ctx); err != nil {
			return Member{}, err
		}
	}
	if runtime.options.Hooks.AfterRemoveMember != nil {
		if err = runtime.options.Hooks.AfterRemoveMember(ctx, hookData); err != nil {
			return Member{}, err
		}
	}
	return runtime.memberFromRecord(hookData.Member), nil
}

func (runtime *runtime) findMemberForRemoval(
	ctx context.Context,
	input removeMemberInput,
) (storage.Record, error) {
	where := []storage.Where{{Field: "organizationId", Value: input.OrganizationID}}
	var joinedUser storage.Record
	if strings.Contains(input.MemberIDOrEmail, "@") {
		user, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "email", Value: strings.ToLower(input.MemberIDOrEmail)}},
		})
		if err != nil {
			return nil, fmt.Errorf("organization: remove member: find user by email: %w", err)
		}
		if user == nil {
			return nil, nil
		}
		joinedUser = user
		userID, _ := recordString(user, "id")
		where = append(where, storage.Where{Field: "userId", Value: userID})
	} else {
		where = append(where, storage.Where{Field: "id", Value: input.MemberIDOrEmail})
	}
	member, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{Model: "member", Where: where})
	if err != nil {
		return nil, fmt.Errorf("organization: remove member: find target: %w", err)
	}
	if member != nil && joinedUser != nil {
		member = cloneRecord(member)
		member["user"] = storage.Record{
			"id": joinedUser["id"], "name": joinedUser["name"],
			"email": joinedUser["email"], "image": joinedUser["image"],
		}
	}
	return member, nil
}

func decodeMemberRoles(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("role is required")
	}
	var roles []string
	if err := json.Unmarshal(raw, &roles); err == nil {
		return roles, nil
	}
	var role string
	if err := json.Unmarshal(raw, &role); err != nil {
		return nil, err
	}
	return []string{role}, nil
}
