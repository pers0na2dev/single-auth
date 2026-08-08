package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	invitationStatusPending  = "pending"
	invitationStatusAccepted = "accepted"
	invitationStatusRejected = "rejected"
	invitationStatusCanceled = "canceled"
)

type invitationActionBody struct {
	InvitationID string `json:"invitationId"`
}

func (runtime *runtime) acceptInvitationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	body, err := decodeInvitationActionBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(session.User, "id")
	userEmail, _ := recordString(session.User, "email")
	sessionToken, _ := recordString(session.Session, "token")
	result, err := runtime.acceptInvitation(ctx.GoContext(), AcceptInvitationInput{
		InvitationID:  body.InvitationID,
		UserID:        userID,
		UserEmail:     userEmail,
		EmailVerified: invitationUserEmailVerified(session.User),
		SessionToken:  sessionToken,
	}, cloneRecord(session.User))
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) acceptInvitation(
	ctx context.Context,
	input AcceptInvitationInput,
	user storage.Record,
) (AcceptInvitationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	input.InvitationID = strings.TrimSpace(input.InvitationID)
	if input.InvitationID == "" {
		return AcceptInvitationResult{}, invalidOrganizationBody(errors.New("invitationId is required"))
	}
	if input.UserID == "" || input.UserEmail == "" || input.SessionToken == "" {
		return AcceptInvitationResult{}, unauthorizedOrganization()
	}

	now := runtime.clock().UTC()
	invitationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: input.InvitationID}},
	})
	if err != nil {
		return AcceptInvitationResult{}, fmt.Errorf("organization: accept invitation: find invitation: %w", err)
	}
	if !usablePendingInvitation(invitationRecord, now) {
		return AcceptInvitationResult{}, invitationNotFound()
	}
	if err := runtime.requireInvitationRecipient(invitationRecord, input.UserEmail, input.EmailVerified, false); err != nil {
		return AcceptInvitationResult{}, err
	}
	organizationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: invitationRecord["organizationId"]}},
	})
	if err != nil {
		return AcceptInvitationResult{}, fmt.Errorf("organization: accept invitation: find organization: %w", err)
	}
	if organizationRecord == nil {
		return AcceptInvitationResult{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	organization := runtime.organizationFromRecord(organizationRecord)
	invitation := runtime.invitationFromRecord(invitationRecord)
	if runtime.options.Hooks.BeforeAcceptInvitation != nil {
		if err := runtime.options.Hooks.BeforeAcceptInvitation(ctx, InvitationActionData{
			Invitation: invitation, User: cloneRecord(user), Organization: organization,
		}); err != nil {
			return AcceptInvitationResult{}, err
		}
	}

	lock := runtime.invitationLock(input.InvitationID)
	lock.Lock()

	var result AcceptInvitationResult
	claimedByUs := false
	var createdMemberID any
	createdTeamMemberIDs := make([]any, 0)
	accept := func(adapter storage.TransactionAdapter) error {
		claimed, claimErr := adapter.IncrementOne(ctx, storage.IncrementOneParams{
			Model: "invitation",
			Where: []storage.Where{
				{Field: "id", Value: input.InvitationID},
				{Field: "status", Value: invitationStatusPending},
				{Field: "expiresAt", Value: now, Operator: storage.OpGTE},
			},
			Set: storage.Record{"status": invitationStatusAccepted},
		})
		if claimErr != nil {
			return fmt.Errorf("organization: accept invitation: claim invitation: %w", claimErr)
		}
		if claimed == nil {
			return invitationNotFound()
		}
		claimedByUs = true
		if recipientErr := runtime.requireInvitationRecipient(
			claimed, input.UserEmail, input.EmailVerified, false,
		); recipientErr != nil {
			return recipientErr
		}

		organizationID, _ := recordString(claimed, "organizationId")
		storedOrganization, findErr := adapter.FindOne(ctx, storage.FindOneParams{
			Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
		})
		if findErr != nil {
			return fmt.Errorf("organization: accept invitation: find organization in transaction: %w", findErr)
		}
		if storedOrganization == nil {
			return organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
		}

		existing, findErr := adapter.FindOne(ctx, storage.FindOneParams{
			Model: "member", Where: []storage.Where{
				{Field: "organizationId", Value: organizationID},
				{Field: "userId", Value: input.UserID},
			},
		})
		if findErr != nil {
			return fmt.Errorf("organization: accept invitation: find existing membership: %w", findErr)
		}
		if existing != nil {
			return organizationError(contract.StatusBadRequest, ErrorUserAlreadyMember)
		}
		count, countErr := adapter.Count(ctx, storage.CountParams{
			Model: "member", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if countErr != nil {
			return fmt.Errorf("organization: accept invitation: count members: %w", countErr)
		}
		if count >= int64(runtime.options.MembershipLimit) {
			return organizationError(contract.StatusForbidden, ErrorMembershipLimitReached)
		}

		teamIDs := invitationStoredTeamIDs(claimed)
		if runtime.options.Teams.Enabled {
			for _, teamID := range teamIDs {
				team, teamErr := adapter.FindOne(ctx, storage.FindOneParams{
					Model: "team", Where: []storage.Where{
						{Field: "id", Value: teamID},
						{Field: "organizationId", Value: organizationID},
					},
				})
				if teamErr != nil {
					return fmt.Errorf("organization: accept invitation: find team: %w", teamErr)
				}
				if team == nil {
					return organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
				}
				existingTeamMember, teamErr := adapter.FindOne(ctx, storage.FindOneParams{
					Model: "teamMember", Where: []storage.Where{
						{Field: "teamId", Value: teamID},
						{Field: "userId", Value: input.UserID},
					},
				})
				if teamErr != nil {
					return fmt.Errorf("organization: accept invitation: find team membership: %w", teamErr)
				}
				if existingTeamMember == nil {
					createdTeamMember, createTeamMemberErr := adapter.Create(ctx, storage.CreateParams{
						Model: "teamMember", Data: storage.Record{
							"teamId": teamID, "userId": input.UserID, "createdAt": now,
						},
					})
					if createTeamMemberErr != nil {
						return fmt.Errorf("organization: accept invitation: create team membership: %w", createTeamMemberErr)
					}
					if id, exists := createdTeamMember["id"]; exists {
						createdTeamMemberIDs = append(createdTeamMemberIDs, id)
					}
				}
			}
		}

		role, _ := recordString(claimed, "role")
		createdMember, createErr := adapter.Create(ctx, storage.CreateParams{
			Model: "member", Data: storage.Record{
				"organizationId": organizationID,
				"userId":         input.UserID,
				"role":           role,
				"createdAt":      now,
			},
		})
		if createErr != nil {
			if errors.Is(createErr, storage.ErrUniqueConstraint) {
				return organizationError(contract.StatusBadRequest, ErrorUserAlreadyMember)
			}
			return fmt.Errorf("organization: accept invitation: create member: %w", createErr)
		}
		createdMemberID = createdMember["id"]

		sessionUpdate := storage.Record{"activeOrganizationId": organizationID}
		if runtime.options.Teams.Enabled && len(teamIDs) == 1 {
			sessionUpdate["activeTeamId"] = teamIDs[0]
		}
		updatedSession, updateErr := adapter.Update(ctx, storage.UpdateParams{
			Model: "session", Where: []storage.Where{{Field: "token", Value: input.SessionToken}},
			Update: sessionUpdate,
		})
		if updateErr != nil {
			return fmt.Errorf("organization: accept invitation: update session: %w", updateErr)
		}
		if updatedSession == nil {
			return unauthorizedOrganization()
		}

		result = AcceptInvitationResult{
			Invitation: runtime.invitationFromRecord(claimed),
			Member:     runtime.memberFromRecord(createdMember),
		}
		return nil
	}
	err = runtime.adapter.Transaction(ctx, accept)
	if errors.Is(err, storage.ErrTransactionsUnsupported) {
		// single-auth adapters without native transaction support still execute
		// the lifecycle and release a successfully claimed invitation on any
		// subsequent failure. Keep the guarded status transition atomic and make
		// the compensating update conditional so it cannot overwrite a concurrent
		// cancel performed by another runtime.
		claimedByUs = false
		createdMemberID = nil
		createdTeamMemberIDs = createdTeamMemberIDs[:0]
		err = accept(runtime.adapter)
		if err != nil && claimedByUs {
			cleanupErrors := []error{err}
			if createdMemberID != nil {
				if cleanupErr := runtime.adapter.Delete(ctx, storage.DeleteParams{
					Model: "member", Where: []storage.Where{{Field: "id", Value: createdMemberID}},
				}); cleanupErr != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf(
						"organization: accept invitation: release transactionless member: %w",
						cleanupErr,
					))
				}
			}
			for index := len(createdTeamMemberIDs) - 1; index >= 0; index-- {
				if cleanupErr := runtime.adapter.Delete(ctx, storage.DeleteParams{
					Model: "teamMember",
					Where: []storage.Where{{Field: "id", Value: createdTeamMemberIDs[index]}},
				}); cleanupErr != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf(
						"organization: accept invitation: release transactionless team membership: %w",
						cleanupErr,
					))
				}
			}
			_, resetErr := runtime.adapter.IncrementOne(ctx, storage.IncrementOneParams{
				Model: "invitation",
				Where: []storage.Where{
					{Field: "id", Value: input.InvitationID},
					{Field: "status", Value: invitationStatusAccepted},
				},
				Set: storage.Record{"status": invitationStatusPending},
			})
			if resetErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf(
					"organization: accept invitation: release transactionless claim: %w",
					resetErr,
				))
			}
			err = errors.Join(cleanupErrors...)
		}
	}
	lock.Unlock()
	if err != nil {
		return AcceptInvitationResult{}, err
	}
	if runtime.options.Hooks.AfterAcceptInvitation != nil {
		if err := runtime.options.Hooks.AfterAcceptInvitation(ctx, AfterAcceptInvitationData{
			Invitation: result.Invitation, Member: result.Member,
			User: cloneRecord(user), Organization: organization,
		}); err != nil {
			return AcceptInvitationResult{}, err
		}
	}
	return result, nil
}

func (runtime *runtime) rejectInvitationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	body, err := decodeInvitationActionBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(session.User, "id")
	userEmail, _ := recordString(session.User, "email")
	result, err := runtime.rejectInvitation(ctx.GoContext(), RejectInvitationInput{
		InvitationID: body.InvitationID, UserID: userID, UserEmail: userEmail,
		EmailVerified: invitationUserEmailVerified(session.User),
	}, cloneRecord(session.User))
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) rejectInvitation(
	ctx context.Context,
	input RejectInvitationInput,
	user storage.Record,
) (RejectInvitationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	input.InvitationID = strings.TrimSpace(input.InvitationID)
	if input.InvitationID == "" {
		return RejectInvitationResult{}, invalidOrganizationBody(errors.New("invitationId is required"))
	}
	invitationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: input.InvitationID}},
	})
	if err != nil {
		return RejectInvitationResult{}, fmt.Errorf("organization: reject invitation: find invitation: %w", err)
	}
	status, _ := recordString(invitationRecord, "status")
	if invitationRecord == nil || status != invitationStatusPending {
		return RejectInvitationResult{}, invitationNotFound()
	}
	if err := runtime.requireInvitationRecipient(invitationRecord, input.UserEmail, input.EmailVerified, false); err != nil {
		return RejectInvitationResult{}, err
	}
	organizationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: invitationRecord["organizationId"]}},
	})
	if err != nil {
		return RejectInvitationResult{}, fmt.Errorf("organization: reject invitation: find organization: %w", err)
	}
	if organizationRecord == nil {
		return RejectInvitationResult{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	organization := runtime.organizationFromRecord(organizationRecord)
	invitation := runtime.invitationFromRecord(invitationRecord)
	if runtime.options.Hooks.BeforeRejectInvitation != nil {
		if err := runtime.options.Hooks.BeforeRejectInvitation(ctx, InvitationActionData{
			Invitation: invitation, User: cloneRecord(user), Organization: organization,
		}); err != nil {
			return RejectInvitationResult{}, err
		}
	}

	lock := runtime.invitationLock(input.InvitationID)
	lock.Lock()
	rejected, err := runtime.adapter.IncrementOne(ctx, storage.IncrementOneParams{
		Model: "invitation", Where: []storage.Where{
			{Field: "id", Value: input.InvitationID},
			{Field: "status", Value: invitationStatusPending},
		},
		Set: storage.Record{"status": invitationStatusRejected},
	})
	lock.Unlock()
	if err != nil {
		return RejectInvitationResult{}, fmt.Errorf("organization: reject invitation: update invitation: %w", err)
	}
	if rejected == nil {
		return RejectInvitationResult{}, invitationNotFound()
	}
	result := RejectInvitationResult{Invitation: runtime.invitationFromRecord(rejected), Member: nil}
	if runtime.options.Hooks.AfterRejectInvitation != nil {
		if err := runtime.options.Hooks.AfterRejectInvitation(ctx, InvitationActionData{
			Invitation: result.Invitation, User: cloneRecord(user), Organization: organization,
		}); err != nil {
			return RejectInvitationResult{}, err
		}
	}
	return result, nil
}

func (runtime *runtime) cancelInvitationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	body, err := decodeInvitationActionBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(session.User, "id")
	invitation, err := runtime.cancelInvitation(ctx.GoContext(), CancelInvitationInput{
		InvitationID: body.InvitationID, UserID: userID,
	}, cloneRecord(session.User))
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, invitation)
}

func (runtime *runtime) cancelInvitation(
	ctx context.Context,
	input CancelInvitationInput,
	user storage.Record,
) (Invitation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	input.InvitationID = strings.TrimSpace(input.InvitationID)
	if input.InvitationID == "" {
		return Invitation{}, invalidOrganizationBody(errors.New("invitationId is required"))
	}
	invitationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: input.InvitationID}},
	})
	if err != nil {
		return Invitation{}, fmt.Errorf("organization: cancel invitation: find invitation: %w", err)
	}
	if invitationRecord == nil {
		return Invitation{}, invitationNotFound()
	}
	organizationID, _ := recordString(invitationRecord, "organizationId")
	member, err := runtime.getActiveMember(ctx, input.UserID, organizationID)
	if err != nil {
		return Invitation{}, err
	}
	if member == nil {
		return Invitation{}, organizationError(contract.StatusBadRequest, ErrorMemberNotFound)
	}
	allowed, err := runtime.hasOrganizationPermission(
		ctx, organizationID, member.Role,
		authorization.Statements{"invitation": {"cancel"}}, false,
	)
	if err != nil {
		return Invitation{}, err
	}
	if !allowed {
		return Invitation{}, organizationError(contract.StatusForbidden, ErrorInvitationCancelForbidden)
	}
	organizationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if err != nil {
		return Invitation{}, fmt.Errorf("organization: cancel invitation: find organization: %w", err)
	}
	if organizationRecord == nil {
		return Invitation{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	organization := runtime.organizationFromRecord(organizationRecord)
	invitation := runtime.invitationFromRecord(invitationRecord)
	if runtime.options.Hooks.BeforeCancelInvitation != nil {
		if err := runtime.options.Hooks.BeforeCancelInvitation(ctx, CancelInvitationData{
			Invitation: invitation, CancelledBy: cloneRecord(user), Organization: organization,
		}); err != nil {
			return Invitation{}, err
		}
	}

	lock := runtime.invitationLock(input.InvitationID)
	lock.Lock()
	canceled, err := runtime.adapter.IncrementOne(ctx, storage.IncrementOneParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: input.InvitationID}},
		Set: storage.Record{"status": invitationStatusCanceled},
	})
	lock.Unlock()
	if err != nil {
		return Invitation{}, fmt.Errorf("organization: cancel invitation: update invitation: %w", err)
	}
	if canceled == nil {
		return Invitation{}, invitationNotFound()
	}
	result := runtime.invitationFromRecord(canceled)
	if runtime.options.Hooks.AfterCancelInvitation != nil {
		if err := runtime.options.Hooks.AfterCancelInvitation(ctx, CancelInvitationData{
			Invitation: result, CancelledBy: cloneRecord(user), Organization: organization,
		}); err != nil {
			return Invitation{}, err
		}
	}
	return result, nil
}

func (runtime *runtime) getInvitationEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidInvitationQuery(err)
	}
	userEmail, _ := recordString(session.User, "email")
	result, err := runtime.getInvitation(ctx.GoContext(), GetInvitationInput{
		InvitationID: strings.TrimSpace(query.Get("id")), UserEmail: userEmail,
		EmailVerified: invitationUserEmailVerified(session.User),
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (runtime *runtime) getInvitation(
	ctx context.Context,
	input GetInvitationInput,
) (InvitationDetails, error) {
	if input.InvitationID == "" {
		return InvitationDetails{}, invalidInvitationQuery(errors.New("id is required"))
	}
	invitationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: input.InvitationID}},
	})
	if err != nil {
		return InvitationDetails{}, fmt.Errorf("organization: get invitation: find invitation: %w", err)
	}
	if !usablePendingInvitation(invitationRecord, runtime.clock().UTC()) {
		return InvitationDetails{}, invitationNotFound()
	}
	if err := runtime.requireInvitationRecipient(invitationRecord, input.UserEmail, input.EmailVerified, true); err != nil {
		return InvitationDetails{}, err
	}
	organizationID, _ := recordString(invitationRecord, "organizationId")
	organizationRecord, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if err != nil {
		return InvitationDetails{}, fmt.Errorf("organization: get invitation: find organization: %w", err)
	}
	if organizationRecord == nil {
		return InvitationDetails{}, organizationError(contract.StatusBadRequest, ErrorOrganizationNotFound)
	}
	inviterID, _ := recordString(invitationRecord, "inviterId")
	inviterMember, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: inviterID}, {Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return InvitationDetails{}, fmt.Errorf("organization: get invitation: find inviter membership: %w", err)
	}
	if inviterMember == nil {
		return InvitationDetails{}, organizationError(contract.StatusBadRequest, ErrorInviterNoLongerMember)
	}
	inviter, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: inviterID}},
	})
	if err != nil {
		return InvitationDetails{}, fmt.Errorf("organization: get invitation: find inviter: %w", err)
	}
	if inviter == nil {
		return InvitationDetails{}, organizationError(contract.StatusBadRequest, ErrorInviterNoLongerMember)
	}
	organization := runtime.organizationFromRecord(organizationRecord)
	inviterEmail, _ := recordString(inviter, "email")
	return InvitationDetails{
		Invitation: runtime.invitationFromRecord(invitationRecord), OrganizationName: organization.Name,
		OrganizationSlug: organization.Slug, InviterEmail: inviterEmail,
	}, nil
}

func (runtime *runtime) listInvitationsEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return contract.Response{}, unauthorizedOrganization()
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidInvitationQuery(err)
	}
	organizationID := strings.TrimSpace(query.Get("organizationId"))
	if organizationID == "" {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	if organizationID == "" {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "Organization ID is required",
		)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.getActiveMember(ctx.GoContext(), userID, organizationID)
	if err != nil {
		return contract.Response{}, err
	}
	if member == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusForbidden, "FORBIDDEN", "You are not a member of this organization",
		)
	}
	invitations, err := runtime.listInvitations(ctx.GoContext(), organizationID)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, invitations)
}

func (runtime *runtime) listInvitations(ctx context.Context, organizationID string) ([]Invitation, error) {
	records, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "invitation", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Ascending},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: list invitations: %w", err)
	}
	result := make([]Invitation, len(records))
	for index, record := range records {
		result[index] = runtime.invitationFromRecord(record)
	}
	return result, nil
}

func (runtime *runtime) listUserInvitationsEndpoint(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidInvitationQuery(err)
	}
	queryEmail := strings.TrimSpace(query.Get("email"))
	if !ctx.IsDirect() && queryEmail != "" {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "User email cannot be passed for client side API calls.",
		)
	}
	session, err := runtime.resolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	email := queryEmail
	if session != nil && session.User != nil {
		if !invitationUserEmailVerified(session.User) {
			return contract.Response{}, organizationError(contract.StatusForbidden, ErrorInvitationListUnverified)
		}
		email, _ = recordString(session.User, "email")
	}
	if strings.TrimSpace(email) == "" {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "Missing session headers, or email query parameter.",
		)
	}
	invitations, err := runtime.listUserInvitations(ctx.GoContext(), email)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, invitations)
}

func (runtime *runtime) listUserInvitations(ctx context.Context, email string) ([]UserInvitation, error) {
	records, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "invitation", Where: []storage.Where{
			{Field: "email", Value: strings.ToLower(strings.TrimSpace(email))},
			{Field: "status", Value: invitationStatusPending},
		},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Ascending},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: list user invitations: %w", err)
	}
	organizations := make(map[string]string)
	result := make([]UserInvitation, 0, len(records))
	for _, record := range records {
		organizationID, _ := recordString(record, "organizationId")
		name, exists := organizations[organizationID]
		if !exists {
			organization, findErr := runtime.adapter.FindOne(ctx, storage.FindOneParams{
				Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
			})
			if findErr != nil {
				return nil, fmt.Errorf("organization: list user invitations: find organization: %w", findErr)
			}
			if organization != nil {
				name, _ = recordString(organization, "name")
			}
			organizations[organizationID] = name
		}
		result = append(result, UserInvitation{
			Invitation: runtime.invitationFromRecord(record), OrganizationName: name,
		})
	}
	return result, nil
}

func decodeInvitationActionBody(ctx *engine.Context) (invitationActionBody, error) {
	var body invitationActionBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return invitationActionBody{}, invalidOrganizationBody(err)
	}
	body.InvitationID = strings.TrimSpace(body.InvitationID)
	if body.InvitationID == "" {
		return invitationActionBody{}, invalidOrganizationBody(errors.New("invitationId is required"))
	}
	return body, nil
}

func usablePendingInvitation(record storage.Record, now time.Time) bool {
	if record == nil {
		return false
	}
	status, _ := recordString(record, "status")
	expiresAt, ok := invitationRecordTime(record, "expiresAt")
	return status == invitationStatusPending && ok && !expiresAt.Before(now)
}

func invitationRecordTime(record storage.Record, key string) (time.Time, bool) {
	value, ok := record[key].(time.Time)
	if ok {
		return value, true
	}
	if text, ok := record[key].(string); ok {
		parsed, err := time.Parse(time.RFC3339Nano, text)
		return parsed, err == nil
	}
	return time.Time{}, false
}

func (runtime *runtime) requireInvitationRecipient(
	invitation storage.Record,
	userEmail string,
	emailVerified bool,
	viewAction bool,
) error {
	recipient, _ := recordString(invitation, "email")
	if recipient == "" || !strings.EqualFold(strings.TrimSpace(recipient), strings.TrimSpace(userEmail)) {
		return organizationError(contract.StatusForbidden, ErrorInvitationRecipientMismatch)
	}
	if runtime.requireEmailVerificationOnInvitation && !emailVerified {
		code := ErrorInvitationEmailUnverified
		if viewAction {
			code = ErrorInvitationListUnverified
		}
		return organizationError(contract.StatusForbidden, code)
	}
	return nil
}

func invitationUserEmailVerified(user storage.Record) bool {
	verified, _ := user["emailVerified"].(bool)
	return verified
}

func invitationStoredTeamIDs(invitation storage.Record) []string {
	raw, _ := recordString(invitation, "teamId")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		teamID := strings.TrimSpace(part)
		if teamID == "" {
			continue
		}
		if _, exists := seen[teamID]; exists {
			continue
		}
		seen[teamID] = struct{}{}
		result = append(result, teamID)
	}
	return result
}

func (runtime *runtime) validateInvitationTeamIDs(
	ctx context.Context,
	organizationID string,
	teamIDs []string,
) ([]string, error) {
	if !runtime.options.Teams.Enabled || len(teamIDs) == 0 {
		return append([]string(nil), teamIDs...), nil
	}
	normalized := make([]string, 0, len(teamIDs))
	seen := make(map[string]struct{}, len(teamIDs))
	for _, rawTeamID := range teamIDs {
		teamID := strings.TrimSpace(rawTeamID)
		if teamID == "" {
			continue
		}
		if strings.Contains(teamID, ",") {
			return nil, organizationError(contract.StatusBadRequest, ErrorInvalidTeamID)
		}
		if _, exists := seen[teamID]; exists {
			continue
		}
		team, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "team",
			Where: []storage.Where{
				{Field: "id", Value: teamID},
				{Field: "organizationId", Value: organizationID},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("organization: create invitation: find team: %w", err)
		}
		if team == nil {
			return nil, organizationError(contract.StatusBadRequest, ErrorTeamNotFound)
		}
		seen[teamID] = struct{}{}
		normalized = append(normalized, teamID)
	}
	return normalized, nil
}

func (runtime *runtime) invitationLock(invitationID string) *sync.Mutex {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(invitationID))
	return &runtime.invitationLocks[hash.Sum32()%uint32(len(runtime.invitationLocks))]
}

func invitationNotFound() *contract.APIError {
	return organizationError(contract.StatusBadRequest, ErrorInvitationNotFound)
}

func invalidInvitationQuery(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters",
	).WithCause(err)
}
