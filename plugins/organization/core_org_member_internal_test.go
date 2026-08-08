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
)

func TestConcurrentOwnerLeavesPreserveExactlyOneOwner(t *testing.T) {
	runtime, adapter, _, secondOwner, _ := newInvitationRuntime(t)
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "member", Data: storage.Record{
			"id": "member-second-owner", "organizationId": "org-1",
			"userId": secondOwner["id"], "role": "owner", "createdAt": runtime.clock(),
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errorsByUser := make(chan error, 2)
	var wait sync.WaitGroup
	for _, userID := range []string{"owner-1", "recipient-1"} {
		userID := userID
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := runtime.leaveOrganization(t.Context(), userID, "", "", "org-1")
			errorsByUser <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByUser)

	successes := 0
	onlyOwnerFailures := 0
	for err := range errorsByUser {
		if err == nil {
			successes++
			continue
		}
		apiError, ok := contract.AsAPIError(err)
		if !ok || apiError.Code != ErrorOnlyOwner || apiError.Status != contract.StatusBadRequest {
			t.Fatalf("concurrent leave error=%v", err)
		}
		onlyOwnerFailures++
	}
	if successes != 1 || onlyOwnerFailures != 1 {
		t.Fatalf("concurrent leaves successes=%d onlyOwnerFailures=%d", successes, onlyOwnerFailures)
	}
	members, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "organizationId", Value: "org-1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	owners := 0
	for _, member := range members {
		role, _ := recordString(member, "role")
		if roleIncludes(role, "owner") {
			owners++
		}
	}
	if len(members) != 1 || owners != 1 {
		t.Fatalf("members=%#v owners=%d want exactly one owner", members, owners)
	}
}

func TestDeleteOrganizationRollbackPreservesRowsButClearsActiveSession(t *testing.T) {
	runtime, adapter, _, _, _ := newInvitationRuntimeWithOptions(
		t, Options{Teams: TeamsOptions{Enabled: true}},
	)
	seedOrganizationCoreTeamRows(t, adapter, runtime.clock())
	owner, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "owner-1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	createdSession, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "session", Data: storage.Record{
			"id": "owner-session", "token": "owner-token", "userId": "owner-1",
			"activeOrganizationId": "org-1", "expiresAt": now.Add(time.Hour),
		}, ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected invitation cascade failure")
	runtime.adapter = &coreDeleteFailureAdapter{Adapter: adapter, err: injected}

	_, err = runtime.deleteOrganization(t.Context(), &resolvedSession{
		Session: createdSession, User: owner,
	}, "org-1")
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("delete error=%v want injected failure", err)
	}
	assertOrganizationCoreRowsPresent(t, adapter)
	assertOrganizationCoreTeamRowsPresent(t, adapter)
	persistedSession, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: "owner-token"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if active, exists := persistedSession["activeOrganizationId"]; exists && active != nil && active != "" {
		t.Fatalf("active organization=%#v after failed delete; upstream clears before cascade", active)
	}
}

func TestDeleteOrganizationTransactionlessCompensationRestoresPartialCascade(t *testing.T) {
	runtime, adapter, _, _, _ := newInvitationRuntimeWithOptions(
		t, Options{Teams: TeamsOptions{Enabled: true}},
	)
	seedOrganizationCoreTeamRows(t, adapter, runtime.clock())
	injected := errors.New("injected transactionless invitation failure")
	runtime.adapter = &coreDeleteFailureAdapter{
		Adapter: adapter, err: injected, transactionsUnsupported: true,
	}

	err := runtime.deleteOrganizationCascade(t.Context(), "org-1")
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("transactionless delete error=%v want injected failure", err)
	}
	assertOrganizationCoreRowsPresent(t, adapter)
	assertOrganizationCoreTeamRowsPresent(t, adapter)
}

func seedOrganizationCoreTeamRows(t *testing.T, adapter storage.Adapter, createdAt time.Time) {
	t.Helper()
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "team", Data: storage.Record{
			"id": "core-team", "name": "Core Team", "organizationId": "org-1", "createdAt": createdAt,
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "teamMember", Data: storage.Record{
			"id": "core-team-member", "teamId": "core-team", "userId": "owner-1", "createdAt": createdAt,
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func assertOrganizationCoreTeamRowsPresent(t *testing.T, adapter storage.Adapter) {
	t.Helper()
	for _, item := range []struct {
		model string
		id    string
	}{
		{model: "team", id: "core-team"},
		{model: "teamMember", id: "core-team-member"},
	} {
		record, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: item.model, Where: []storage.Where{{Field: "id", Value: item.id}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if record == nil {
			t.Fatalf("%s %q was not rolled back", item.model, item.id)
		}
	}
}

func assertOrganizationCoreRowsPresent(t *testing.T, adapter storage.Adapter) {
	t.Helper()
	organization, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: "org-1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if organization == nil {
		t.Fatal("organization was not rolled back")
	}
	for _, model := range []string{"member", "invitation"} {
		count, err := adapter.Count(t.Context(), storage.CountParams{
			Model: model, Where: []storage.Where{{Field: "organizationId", Value: "org-1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatalf("%s rows were not rolled back", model)
		}
	}
}

type coreDeleteFailureAdapter struct {
	storage.Adapter
	err                     error
	transactionsUnsupported bool
}

func (adapter *coreDeleteFailureAdapter) Transaction(
	ctx context.Context,
	callback func(storage.TransactionAdapter) error,
) error {
	if adapter.transactionsUnsupported {
		return storage.ErrTransactionsUnsupported
	}
	return adapter.Adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		return callback(coreDeleteFailureTransaction{
			TransactionAdapter: transaction, err: adapter.err,
		})
	})
}

func (adapter *coreDeleteFailureAdapter) DeleteMany(
	ctx context.Context,
	params storage.DeleteManyParams,
) (int64, error) {
	if params.Model == "invitation" {
		return 0, adapter.err
	}
	return adapter.Adapter.DeleteMany(ctx, params)
}

type coreDeleteFailureTransaction struct {
	storage.TransactionAdapter
	err error
}

func (transaction coreDeleteFailureTransaction) DeleteMany(
	ctx context.Context,
	params storage.DeleteManyParams,
) (int64, error) {
	if params.Model == "invitation" {
		return 0, transaction.err
	}
	return transaction.TransactionAdapter.DeleteMany(ctx, params)
}
