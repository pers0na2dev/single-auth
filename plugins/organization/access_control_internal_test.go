package organization

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestDeleteOrganizationDynamicRoleCascadeTransactionlessCompensation(t *testing.T) {
	runtime, adapter, _, _, _ := newInvitationRuntimeWithOptions(
		t, Options{DynamicAccessControl: DynamicAccessControlOptions{Enabled: true}},
	)
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "organizationRole", ForceAllowID: true,
		Data: storage.Record{
			"id": "role-rollback", "organizationId": "org-1", "role": "rollback",
			"permission": `{"organization":["update"]}`, "createdAt": runtime.clock(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected organization delete failure after role cascade")
	runtime.adapter = &organizationRoleCascadeFailureAdapter{Adapter: adapter, err: injected}

	err = runtime.deleteOrganizationCascade(t.Context(), "org-1")
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("delete cascade error=%v want injected failure", err)
	}
	role, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "organizationRole", Where: []storage.Where{{Field: "id", Value: created["id"]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if role == nil || role["permission"] != created["permission"] || role["role"] != "rollback" {
		t.Fatalf("dynamic role was not compensated: got=%#v want=%#v", role, created)
	}
	assertOrganizationCoreRowsPresent(t, adapter)
}

type organizationRoleCascadeFailureAdapter struct {
	storage.Adapter
	err error
}

func (*organizationRoleCascadeFailureAdapter) Transaction(
	context.Context,
	func(storage.TransactionAdapter) error,
) error {
	return storage.ErrTransactionsUnsupported
}

func (adapter *organizationRoleCascadeFailureAdapter) Delete(
	ctx context.Context,
	params storage.DeleteParams,
) error {
	if params.Model == "organization" {
		return adapter.err
	}
	return adapter.Adapter.Delete(ctx, params)
}
