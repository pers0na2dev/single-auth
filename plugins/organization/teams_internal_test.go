package organization

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestDeleteTeamCascadeRollsBackTransactionFailure(t *testing.T) {
	runtime, adapter, team, member, invitation := seedTeamCascadeRuntime(t)
	injected := errors.New("injected team invitation update failure")
	runtime.adapter = &teamCascadeFailureAdapter{Adapter: adapter, err: injected, remainingFailures: 1}

	err := runtime.deleteTeamCascade(t.Context(), "org-1", team)
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("delete team error=%v want injected failure", err)
	}
	assertTeamCascadeRows(t, adapter, team, member, invitation)
}

func TestDeleteTeamCascadeTransactionlessCompensationRestoresRows(t *testing.T) {
	runtime, adapter, team, member, invitation := seedTeamCascadeRuntime(t)
	injected := errors.New("injected transactionless team invitation update failure")
	runtime.adapter = &teamCascadeFailureAdapter{
		Adapter: adapter, err: injected, remainingFailures: 1, transactionsUnsupported: true,
	}

	err := runtime.deleteTeamCascade(t.Context(), "org-1", team)
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("transactionless delete team error=%v want injected failure", err)
	}
	assertTeamCascadeRows(t, adapter, team, member, invitation)
}

func TestDeleteOrganizationExplicitTeamCascadeWorksWithoutTransactionsOrFKCascade(t *testing.T) {
	runtime, adapter, _, _, _ := newInvitationRuntimeWithOptions(
		t, Options{
			Teams:                TeamsOptions{Enabled: true},
			DynamicAccessControl: DynamicAccessControlOptions{Enabled: true},
		},
	)
	seedOrganizationCoreTeamRows(t, adapter, runtime.clock())
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "organizationRole", ForceAllowID: true,
		Data: storage.Record{
			"id": "core-role", "organizationId": "org-1", "role": "core-role",
			"permission": "{}", "createdAt": runtime.clock(),
		},
	}); err != nil {
		t.Fatal(err)
	}
	checking := &teamCascadeOrderAdapter{Adapter: adapter}
	runtime.adapter = checking

	if err := runtime.deleteOrganizationCascade(t.Context(), "org-1"); err != nil {
		t.Fatalf("delete organization cascade: %v", err)
	}
	for _, query := range []struct {
		model string
		where []storage.Where
	}{
		{model: "organization", where: []storage.Where{{Field: "id", Value: "org-1"}}},
		{model: "member", where: []storage.Where{{Field: "organizationId", Value: "org-1"}}},
		{model: "invitation", where: []storage.Where{{Field: "organizationId", Value: "org-1"}}},
		{model: "team", where: []storage.Where{{Field: "organizationId", Value: "org-1"}}},
		{model: "teamMember", where: []storage.Where{{Field: "teamId", Value: "core-team"}}},
		{model: "organizationRole", where: []storage.Where{{Field: "organizationId", Value: "org-1"}}},
	} {
		count, err := adapter.Count(t.Context(), storage.CountParams{Model: query.model, Where: query.where})
		if err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v after explicit cascade", query.model, count, err)
		}
	}
	checking.mu.Lock()
	defer checking.mu.Unlock()
	wantOrder := []string{"teamMember", "team", "member", "invitation", "organizationRole", "organization"}
	if strings.Join(checking.order, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("cascade order=%#v want=%#v", checking.order, wantOrder)
	}
}

func seedTeamCascadeRuntime(
	t *testing.T,
) (*runtime, storage.Adapter, storage.Record, storage.Record, storage.Record) {
	t.Helper()
	runtime, adapter, invitationID, _, _ := newInvitationRuntimeWithOptions(
		t, Options{Teams: TeamsOptions{Enabled: true, AllowRemovingAllTeams: true}},
	)
	create := func(model string, data storage.Record) storage.Record {
		t.Helper()
		created, err := adapter.Create(t.Context(), storage.CreateParams{
			Model: model, Data: data, ForceAllowID: true,
		})
		if err != nil {
			t.Fatalf("create %s: %v", model, err)
		}
		return created
	}
	team := create("team", storage.Record{
		"id": "team-delete", "name": "Delete", "organizationId": "org-1", "createdAt": runtime.clock(),
	})
	create("team", storage.Record{
		"id": "team-keep", "name": "Keep", "organizationId": "org-1", "createdAt": runtime.clock(),
	})
	member := create("teamMember", storage.Record{
		"id": "team-member-delete", "teamId": "team-delete", "userId": "owner-1", "createdAt": runtime.clock(),
	})
	invitation, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
		Update: storage.Record{"teamId": "team-delete,team-keep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, adapter, team, member, invitation
}

func assertTeamCascadeRows(
	t *testing.T,
	adapter storage.Adapter,
	team storage.Record,
	member storage.Record,
	invitation storage.Record,
) {
	t.Helper()
	for _, item := range []struct {
		model  string
		record storage.Record
	}{
		{model: "team", record: team},
		{model: "teamMember", record: member},
		{model: "invitation", record: invitation},
	} {
		id, _ := recordString(item.record, "id")
		persisted, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: item.model, Where: []storage.Where{{Field: "id", Value: id}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if persisted == nil {
			t.Fatalf("%s %q was not rolled back", item.model, id)
		}
		if item.model == "invitation" && persisted["teamId"] != invitation["teamId"] {
			t.Fatalf("invitation teamId=%#v want=%#v", persisted["teamId"], invitation["teamId"])
		}
	}
}

type teamCascadeFailureAdapter struct {
	storage.Adapter
	err                     error
	transactionsUnsupported bool

	mu                sync.Mutex
	remainingFailures int
}

func (adapter *teamCascadeFailureAdapter) Transaction(
	ctx context.Context,
	callback func(storage.TransactionAdapter) error,
) error {
	if adapter.transactionsUnsupported {
		return storage.ErrTransactionsUnsupported
	}
	return adapter.Adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		return callback(&teamCascadeFailureTransaction{
			TransactionAdapter: transaction, parent: adapter,
		})
	})
}

func (adapter *teamCascadeFailureAdapter) Update(
	ctx context.Context,
	params storage.UpdateParams,
) (storage.Record, error) {
	if params.Model == "invitation" && adapter.takeFailure() {
		return nil, adapter.err
	}
	return adapter.Adapter.Update(ctx, params)
}

func (adapter *teamCascadeFailureAdapter) takeFailure() bool {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.remainingFailures == 0 {
		return false
	}
	adapter.remainingFailures--
	return true
}

type teamCascadeFailureTransaction struct {
	storage.TransactionAdapter
	parent *teamCascadeFailureAdapter
}

func (transaction *teamCascadeFailureTransaction) Update(
	ctx context.Context,
	params storage.UpdateParams,
) (storage.Record, error) {
	if params.Model == "invitation" && transaction.parent.takeFailure() {
		return nil, transaction.parent.err
	}
	return transaction.TransactionAdapter.Update(ctx, params)
}

type teamCascadeOrderAdapter struct {
	storage.Adapter
	mu    sync.Mutex
	order []string
}

func (*teamCascadeOrderAdapter) Transaction(
	context.Context,
	func(storage.TransactionAdapter) error,
) error {
	return storage.ErrTransactionsUnsupported
}

func (adapter *teamCascadeOrderAdapter) DeleteMany(
	ctx context.Context,
	params storage.DeleteManyParams,
) (int64, error) {
	deleted, err := adapter.Adapter.DeleteMany(ctx, params)
	if err == nil && deleted > 0 {
		adapter.mu.Lock()
		adapter.order = append(adapter.order, params.Model)
		adapter.mu.Unlock()
	}
	return deleted, err
}

func (adapter *teamCascadeOrderAdapter) Delete(
	ctx context.Context,
	params storage.DeleteParams,
) error {
	if params.Model == "team" {
		teamID := ""
		for _, condition := range params.Where {
			if condition.Field == "id" {
				teamID, _ = condition.Value.(string)
			}
		}
		count, err := adapter.Adapter.Count(ctx, storage.CountParams{
			Model: "teamMember", Where: []storage.Where{{Field: "teamId", Value: teamID}},
		})
		if err != nil {
			return err
		}
		if count != 0 {
			return errors.New("team deleted before team memberships")
		}
	}
	if params.Model == "organization" {
		for _, model := range []string{"team", "member", "invitation"} {
			count, err := adapter.Adapter.Count(ctx, storage.CountParams{
				Model: model, Where: []storage.Where{{Field: "organizationId", Value: "org-1"}},
			})
			if err != nil {
				return err
			}
			if count != 0 {
				return fmt.Errorf("organization deleted before %s", model)
			}
		}
	}
	if err := adapter.Adapter.Delete(ctx, params); err != nil {
		return err
	}
	adapter.mu.Lock()
	adapter.order = append(adapter.order, params.Model)
	adapter.mu.Unlock()
	return nil
}
