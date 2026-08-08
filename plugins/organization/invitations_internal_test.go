package organization

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestAcceptInvitationIsAtomicUnderConcurrentReplay(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntime(t)

	const attempts = 12
	start := make(chan struct{})
	errorsByAttempt := make(chan error, attempts)
	results := make(chan AcceptInvitationResult, attempts)
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
				InvitationID: invitationID,
				UserID:       recipient["id"].(string),
				UserEmail:    recipient["email"].(string),
				SessionToken: sessionToken,
			}, recipient)
			if err == nil {
				results <- result
			}
			errorsByAttempt <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByAttempt)
	close(results)

	successes := 0
	notFound := 0
	for err := range errorsByAttempt {
		if err == nil {
			successes++
			continue
		}
		apiError, ok := contract.AsAPIError(err)
		if !ok || apiError.Code != ErrorInvitationNotFound || apiError.Status != contract.StatusBadRequest {
			t.Fatalf("concurrent accept error=%v want %s", err, ErrorInvitationNotFound)
		}
		notFound++
	}
	if successes != 1 || notFound != attempts-1 || len(results) != 1 {
		t.Fatalf("concurrent accept successes=%d notFound=%d results=%d", successes, notFound, len(results))
	}

	invitation := mustFindInvitationRecord(t, adapter, invitationID)
	if invitation["status"] != invitationStatusAccepted {
		t.Fatalf("invitation status=%#v want accepted", invitation["status"])
	}
	members, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "member", Where: []storage.Where{
			{Field: "organizationId", Value: "org-1"},
			{Field: "userId", Value: recipient["id"]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("recipient memberships=%d want 1: %#v", len(members), members)
	}
	session, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: sessionToken}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session["activeOrganizationId"] != "org-1" {
		t.Fatalf("activeOrganizationId=%#v want org-1", session["activeOrganizationId"])
	}
}

func TestAcceptInvitationRollsBackClaimAndSessionWhenMemberCreationFails(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	runtime.adapter = &failInvitationMemberCreateAdapter{
		Adapter: adapter,
		err:     errors.New("injected member create failure"),
	}

	_, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	if err == nil || !strings.Contains(err.Error(), "injected member create failure") {
		t.Fatalf("accept error=%v want injected failure", err)
	}

	invitation := mustFindInvitationRecord(t, adapter, invitationID)
	if invitation["status"] != invitationStatusPending {
		t.Fatalf("rolled-back invitation status=%#v want pending", invitation["status"])
	}
	members, findErr := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "userId", Value: recipient["id"]}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if len(members) != 0 {
		t.Fatalf("rolled-back recipient membership=%#v", members)
	}
	session, findErr := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: sessionToken}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if value, exists := session["activeOrganizationId"]; exists && value != nil && value != "" {
		t.Fatalf("rolled-back activeOrganizationId=%#v", value)
	}
}

func TestAcceptInvitationFallsBackWhenTransactionsAreUnsupported(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	runtime.adapter = &transactionlessInvitationAdapter{Adapter: adapter}

	result, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	if err != nil {
		t.Fatalf("transactionless accept: %v", err)
	}
	if result.Invitation.Status != invitationStatusAccepted || result.Member.UserID != recipient["id"] {
		t.Fatalf("transactionless accept result=%#v", result)
	}
	if status := mustFindInvitationRecord(t, adapter, invitationID)["status"]; status != invitationStatusAccepted {
		t.Fatalf("transactionless invitation status=%#v want accepted", status)
	}
}

func TestAcceptInvitationCompensatesTransactionlessPartialFailure(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntimeWithOptions(
		t,
		Options{Teams: TeamsOptions{Enabled: true}},
	)
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "team", Data: storage.Record{
			"id": "team-1", "name": "Team", "organizationId": "org-1",
			"createdAt": runtime.clock(),
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
		Update: storage.Record{"teamId": "team-1"},
	}); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected transactionless member failure")
	runtime.adapter = &transactionlessInvitationAdapter{
		Adapter: adapter, failCreateModel: "member", err: injected,
	}

	_, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("transactionless accept error=%v want injected failure", err)
	}
	if status := mustFindInvitationRecord(t, adapter, invitationID)["status"]; status != invitationStatusPending {
		t.Fatalf("released transactionless invitation status=%#v want pending", status)
	}
	members, findErr := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "userId", Value: recipient["id"]}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if len(members) != 0 {
		t.Fatalf("transactionless failure left members=%#v", members)
	}
	teamMembers, findErr := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "teamMember", Where: []storage.Where{{Field: "userId", Value: recipient["id"]}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if len(teamMembers) != 0 {
		t.Fatalf("transactionless failure left team members=%#v", teamMembers)
	}
}

func TestAcceptInvitationCompensatesTransactionlessSessionFailure(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	injected := errors.New("injected transactionless session failure")
	runtime.adapter = &transactionlessInvitationAdapter{
		Adapter: adapter, failUpdateModel: "session", err: injected,
	}

	_, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("transactionless accept error=%v want injected session failure", err)
	}
	if status := mustFindInvitationRecord(t, adapter, invitationID)["status"]; status != invitationStatusPending {
		t.Fatalf("released transactionless invitation status=%#v want pending", status)
	}
	members, findErr := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "userId", Value: recipient["id"]}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if len(members) != 0 {
		t.Fatalf("transactionless session failure left members=%#v", members)
	}
	session, findErr := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: sessionToken}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if value, exists := session["activeOrganizationId"]; exists && value != nil && value != "" {
		t.Fatalf("transactionless session failure left active organization=%#v", value)
	}
}

func TestAcceptInvitationReleasesLockBeforeAfterHook(t *testing.T) {
	runtime, _, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	runtime.options.Hooks.AfterAcceptInvitation = func(
		_ context.Context,
		data AfterAcceptInvitationData,
	) error {
		lock := runtime.invitationLock(data.Invitation.ID)
		if !lock.TryLock() {
			return errors.New("invitation lock is still held during afterAcceptInvitation")
		}
		lock.Unlock()
		return nil
	}

	_, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	if err != nil {
		t.Fatalf("accept with reentrant after hook: %v", err)
	}
}

func TestAcceptInvitationRejectsDuplicateMembershipWithoutConsumingInvite(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "member", Data: storage.Record{
			"id": "member-recipient", "organizationId": "org-1",
			"userId": recipient["id"], "role": "member", "createdAt": runtime.clock(),
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Code != ErrorUserAlreadyMember || apiError.Status != contract.StatusBadRequest {
		t.Fatalf("duplicate accept error=%v want %s", err, ErrorUserAlreadyMember)
	}
	if status := mustFindInvitationRecord(t, adapter, invitationID)["status"]; status != invitationStatusPending {
		t.Fatalf("duplicate accept consumed invitation: status=%#v", status)
	}
}

func TestAcceptInvitationDoesNotConsumeInviteAtMembershipLimit(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntimeWithOptions(
		t,
		Options{MembershipLimit: 1},
	)

	_, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	requireInvitationAPIError(t, err, contract.StatusForbidden, ErrorMembershipLimitReached)
	if status := mustFindInvitationRecord(t, adapter, invitationID)["status"]; status != invitationStatusPending {
		t.Fatalf("membership-limit invitation status=%#v want pending", status)
	}
}

func TestAcceptInvitationDoesNotConsumeInviteWhenTeamWasRemoved(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntimeWithOptions(
		t,
		Options{Teams: TeamsOptions{Enabled: true}},
	)
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "team", Data: storage.Record{
			"id": "removed-team", "name": "Removed", "organizationId": "org-1",
			"createdAt": runtime.clock(),
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
		Update: storage.Record{"teamId": "removed-team"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Delete(t.Context(), storage.DeleteParams{
		Model: "team", Where: []storage.Where{{Field: "id", Value: "removed-team"}},
	}); err != nil {
		t.Fatal(err)
	}

	_, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	requireInvitationAPIError(t, err, contract.StatusBadRequest, ErrorTeamNotFound)
	if status := mustFindInvitationRecord(t, adapter, invitationID)["status"]; status != invitationStatusPending {
		t.Fatalf("removed-team invitation status=%#v want pending", status)
	}
	teamMembers, findErr := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "teamMember", Where: []storage.Where{{Field: "userId", Value: recipient["id"]}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if len(teamMembers) != 0 {
		t.Fatalf("removed-team accept left team members=%#v", teamMembers)
	}
}

func TestAcceptInvitationUsesTeamIDsFromAtomicallyClaimedRow(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntimeWithOptions(
		t,
		Options{Teams: TeamsOptions{Enabled: true}},
	)
	for _, team := range []storage.Record{
		{"id": "stale-team", "name": "Stale", "organizationId": "org-1", "createdAt": runtime.clock()},
		{"id": "current-team", "name": "Current", "organizationId": "org-1", "createdAt": runtime.clock()},
	} {
		if _, err := adapter.Create(t.Context(), storage.CreateParams{
			Model: "team", Data: team, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
		Update: storage.Record{"teamId": "stale-team"},
	}); err != nil {
		t.Fatal(err)
	}
	runtime.options.Hooks.BeforeAcceptInvitation = func(context.Context, InvitationActionData) error {
		updated, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
			Update: storage.Record{"teamId": "current-team"},
		})
		if err != nil {
			return err
		}
		if updated == nil {
			return errors.New("invitation disappeared in before-accept hook")
		}
		return nil
	}

	result, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID,
		UserID:       recipient["id"].(string),
		UserEmail:    recipient["email"].(string),
		SessionToken: sessionToken,
	}, recipient)
	if err != nil {
		t.Fatalf("accept invitation with replaced team: %v", err)
	}
	if result.Invitation.TeamID == nil || *result.Invitation.TeamID != "current-team" {
		t.Fatalf("accepted invitation team=%#v want current-team", result.Invitation.TeamID)
	}
	teamMembers, findErr := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "teamMember", Where: []storage.Where{{Field: "userId", Value: recipient["id"]}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if len(teamMembers) != 1 || teamMembers[0]["teamId"] != "current-team" {
		t.Fatalf("accepted team memberships=%#v want current-team only", teamMembers)
	}
}

func TestInvitationExpiringAtCurrentTimeCanBeViewedAndAccepted(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	now := runtime.clock().UTC()
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model:  "invitation",
		Where:  []storage.Where{{Field: "id", Value: invitationID}},
		Update: storage.Record{"expiresAt": now},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil {
		t.Fatal("invitation expiry update returned nil")
	}

	details, err := runtime.getInvitation(t.Context(), GetInvitationInput{
		InvitationID:  invitationID,
		UserEmail:     recipient["email"].(string),
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("get invitation expiring at now: %v", err)
	}
	if details.ID != invitationID {
		t.Fatalf("get invitation id=%q want %q", details.ID, invitationID)
	}

	result, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID:  invitationID,
		UserID:        recipient["id"].(string),
		UserEmail:     recipient["email"].(string),
		EmailVerified: true,
		SessionToken:  sessionToken,
	}, recipient)
	if err != nil {
		t.Fatalf("accept invitation expiring at now: %v", err)
	}
	if result.Invitation.Status != invitationStatusAccepted {
		t.Fatalf("accepted invitation status=%q want accepted", result.Invitation.Status)
	}
}

func TestExpiredInvitationCannotBeViewedOrAccepted(t *testing.T) {
	runtime, adapter, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model:  "invitation",
		Where:  []storage.Where{{Field: "id", Value: invitationID}},
		Update: storage.Record{"expiresAt": runtime.clock().UTC().Add(-time.Nanosecond)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil {
		t.Fatal("invitation expiry update returned nil")
	}

	_, err = runtime.getInvitation(t.Context(), GetInvitationInput{
		InvitationID:  invitationID,
		UserEmail:     recipient["email"].(string),
		EmailVerified: true,
	})
	requireInvitationAPIError(t, err, contract.StatusBadRequest, ErrorInvitationNotFound)

	_, err = runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID:  invitationID,
		UserID:        recipient["id"].(string),
		UserEmail:     recipient["email"].(string),
		EmailVerified: true,
		SessionToken:  sessionToken,
	}, recipient)
	requireInvitationAPIError(t, err, contract.StatusBadRequest, ErrorInvitationNotFound)
	if status := mustFindInvitationRecord(t, adapter, invitationID)["status"]; status != invitationStatusPending {
		t.Fatalf("expired invitation status=%#v want pending", status)
	}
}

func TestInvitationRecipientOwnershipIsCaseInsensitiveAndRejectsOtherUsers(t *testing.T) {
	runtime, _, invitationID, recipient, sessionToken := newInvitationRuntime(t)
	wrongEmail := "other@example.test"

	_, err := runtime.getInvitation(t.Context(), GetInvitationInput{
		InvitationID: invitationID, UserEmail: wrongEmail, EmailVerified: true,
	})
	requireInvitationAPIError(t, err, contract.StatusForbidden, ErrorInvitationRecipientMismatch)

	_, err = runtime.rejectInvitation(t.Context(), RejectInvitationInput{
		InvitationID: invitationID, UserID: "other-user", UserEmail: wrongEmail,
		EmailVerified: true,
	}, storage.Record{"id": "other-user", "email": wrongEmail, "emailVerified": true})
	requireInvitationAPIError(t, err, contract.StatusForbidden, ErrorInvitationRecipientMismatch)

	_, err = runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID, UserID: "other-user", UserEmail: wrongEmail,
		EmailVerified: true, SessionToken: sessionToken,
	}, storage.Record{"id": "other-user", "email": wrongEmail, "emailVerified": true})
	requireInvitationAPIError(t, err, contract.StatusForbidden, ErrorInvitationRecipientMismatch)

	result, err := runtime.acceptInvitation(t.Context(), AcceptInvitationInput{
		InvitationID: invitationID, UserID: recipient["id"].(string),
		UserEmail: strings.ToUpper(recipient["email"].(string)), EmailVerified: true,
		SessionToken: sessionToken,
	}, recipient)
	if err != nil {
		t.Fatalf("accept invitation with differently cased recipient email: %v", err)
	}
	if result.Invitation.Status != invitationStatusAccepted {
		t.Fatalf("accepted invitation status=%q want accepted", result.Invitation.Status)
	}
}

func requireInvitationAPIError(t *testing.T, err error, wantStatus int, wantCode string) {
	t.Helper()
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != wantStatus || apiError.Code != wantCode {
		t.Fatalf("error=%v want status=%d code=%s", err, wantStatus, wantCode)
	}
}

func newInvitationRuntime(
	t *testing.T,
) (*runtime, storage.Adapter, string, storage.Record, string) {
	t.Helper()
	return newInvitationRuntimeWithOptions(t, Options{})
}

func newInvitationRuntimeWithOptions(
	t *testing.T,
	options Options,
) (*runtime, storage.Adapter, string, storage.Record, string) {
	t.Helper()
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	if options.MembershipLimit == 0 {
		options.MembershipLimit = 100
	}
	if options.InvitationExpiresIn == 0 {
		options.InvitationExpiresIn = 48 * time.Hour
	}
	extension, err := Schema(options)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(extension)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := memory.New(memory.WithSchema(schema), memory.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	create := func(model string, data storage.Record) storage.Record {
		t.Helper()
		created, createErr := adapter.Create(t.Context(), storage.CreateParams{
			Model: model, Data: data, ForceAllowID: true,
		})
		if createErr != nil {
			t.Fatalf("create %s: %v", model, createErr)
		}
		return created
	}
	owner := create("user", storage.Record{
		"id": "owner-1", "name": "Owner", "email": "owner@example.test", "emailVerified": true,
	})
	recipient := create("user", storage.Record{
		"id": "recipient-1", "name": "Recipient", "email": "recipient@example.test", "emailVerified": true,
	})
	create("organization", storage.Record{
		"id": "org-1", "name": "Organization", "slug": "organization", "createdAt": now,
	})
	create("member", storage.Record{
		"id": "member-owner", "organizationId": "org-1", "userId": owner["id"],
		"role": "owner", "createdAt": now,
	})
	const sessionToken = "recipient-session-token"
	create("session", storage.Record{
		"id": "session-recipient", "token": sessionToken, "userId": recipient["id"],
		"expiresAt": now.Add(24 * time.Hour),
	})
	const invitationID = "invitation-1"
	create("invitation", storage.Record{
		"id": invitationID, "organizationId": "org-1", "email": "Recipient@Example.Test",
		"role": "member", "status": invitationStatusPending, "inviterId": owner["id"],
		"expiresAt": now.Add(time.Hour), "createdAt": now,
	})
	return &runtime{
		adapter: adapter, clock: func() time.Time { return now }, creatorRole: "owner",
		options: options,
	}, adapter, invitationID, recipient, sessionToken
}

func mustFindInvitationRecord(t *testing.T, adapter storage.Adapter, invitationID string) storage.Record {
	t.Helper()
	record, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatalf("invitation %q not found", invitationID)
	}
	return record
}

type failInvitationMemberCreateAdapter struct {
	storage.Adapter
	err error
}

type transactionlessInvitationAdapter struct {
	storage.Adapter
	failCreateModel string
	failUpdateModel string
	err             error
}

func (adapter *transactionlessInvitationAdapter) Transaction(
	context.Context,
	func(storage.TransactionAdapter) error,
) error {
	return storage.ErrTransactionsUnsupported
}

func (adapter *transactionlessInvitationAdapter) Create(
	ctx context.Context,
	params storage.CreateParams,
) (storage.Record, error) {
	if params.Model == adapter.failCreateModel && adapter.err != nil {
		return nil, adapter.err
	}
	return adapter.Adapter.Create(ctx, params)
}

func (adapter *transactionlessInvitationAdapter) Update(
	ctx context.Context,
	params storage.UpdateParams,
) (storage.Record, error) {
	if params.Model == adapter.failUpdateModel && adapter.err != nil {
		return nil, adapter.err
	}
	return adapter.Adapter.Update(ctx, params)
}

func (adapter *failInvitationMemberCreateAdapter) Transaction(
	ctx context.Context,
	callback func(storage.TransactionAdapter) error,
) error {
	return adapter.Adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		return callback(failInvitationMemberCreateTransaction{
			TransactionAdapter: transaction, err: adapter.err,
		})
	})
}

type failInvitationMemberCreateTransaction struct {
	storage.TransactionAdapter
	err error
}

func (transaction failInvitationMemberCreateTransaction) Create(
	ctx context.Context,
	params storage.CreateParams,
) (storage.Record, error) {
	if params.Model == "member" {
		return nil, transaction.err
	}
	return transaction.TransactionAdapter.Create(ctx, params)
}
