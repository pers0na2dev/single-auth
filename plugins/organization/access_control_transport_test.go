package organization_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestOrganizationDynamicAccessControlAcrossTransports(t *testing.T) {
	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run(string(transport), func(t *testing.T) {
			runOrganizationDynamicAccessControlScenario(t)
		})
	}
}

func runOrganizationDynamicAccessControlScenario(t *testing.T) {
	t.Helper()
	options := organizationDynamicAccessOptions(nil)
	harness := newOrganizationCRUDHarness(t, options)
	createdOrganization := harness.createHTTP(t, harness.owner, "Dynamic Roles", "dynamic-roles", nil)
	organizationID := organizationCRUDString(t, createdOrganization, "id")

	unauthorized := harness.exchange(t, http.MethodPost, "/organization/create-role", "", map[string]any{
		"role": "writer", "permission": map[string]any{"project": []string{"create"}},
	})
	requireOrganizationCoreAPIError(t, unauthorized, http.StatusUnauthorized, "UNAUTHORIZED")

	malformed := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
		"role": "writer",
	})
	requireOrganizationCoreAPIError(t, malformed, http.StatusBadRequest, "VALIDATION_ERROR")

	created := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
		"role": "PROJECT-WRITER",
		"permission": map[string]any{
			"project": []string{"create", "read"},
		},
		"additionalFields": map[string]any{
			"color": "#000000", "serverOnlyValue": "attacker", "unknown": "ignored",
		},
	})
	requireOrganizationCRUDStatus(t, created, http.StatusOK)
	createBody := organizationCRUDObject(t, created.Value, "create role response")
	if createBody["success"] != true {
		t.Fatalf("create role success=%#v body=%s", createBody["success"], created.Body)
	}
	role := organizationCRUDObject(t, createBody["roleData"], "created role")
	roleID := organizationCRUDString(t, role, "id")
	if role["role"] != "project-writer" || role["color"] != "#000000" ||
		role["serverOnlyValue"] != "server-only-value" || role["unknown"] != nil || role["hidden"] != nil {
		t.Fatalf("created role=%#v body=%s", role, created.Body)
	}
	permissions := organizationCRUDObject(t, role["permission"], "created role permission")
	if len(organizationCRUDArray(t, permissions["project"], "created project permission")) != 2 {
		t.Fatalf("created permission=%#v", permissions)
	}
	duplicate := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "role": "PROJECT-WRITER",
		"permission":       map[string]any{"project": []string{"read"}},
		"additionalFields": map[string]any{"color": "#000000"},
	})
	requireOrganizationCoreAPIError(t, duplicate, http.StatusBadRequest, organization.ErrorRoleNameTaken)

	listed := harness.exchange(t, http.MethodGet, "/organization/list-roles", harness.owner.Cookie, nil)
	requireOrganizationCRUDStatus(t, listed, http.StatusOK)
	if len(organizationCRUDArray(t, listed.Value, "listed roles")) != 1 {
		t.Fatalf("listed roles=%#v body=%s", listed.Value, listed.Body)
	}
	gotByID := harness.exchange(t, http.MethodGet,
		"/organization/get-role?"+url.Values{"roleId": []string{roleID}}.Encode(),
		harness.owner.Cookie, nil,
	)
	requireOrganizationCRUDStatus(t, gotByID, http.StatusOK)
	if organizationCRUDObject(t, gotByID.Value, "role by id")["role"] != "project-writer" {
		t.Fatalf("role by id=%#v", gotByID.Value)
	}

	updated := harness.exchange(t, http.MethodPost, "/organization/update-role", harness.owner.Cookie, map[string]any{
		"roleId": roleID,
		"data": map[string]any{
			"roleName":   "PROJECT-EDITOR",
			"permission": map[string]any{"project": []string{"read", "update"}},
			"color":      "#111111", "unknown": "ignored",
		},
	})
	requireOrganizationCRUDStatus(t, updated, http.StatusOK)
	updatedRole := organizationCRUDObject(t,
		organizationCRUDObject(t, updated.Value, "update role response")["roleData"],
		"updated role",
	)
	if updatedRole["role"] != "project-editor" || updatedRole["color"] != "#111111" || updatedRole["unknown"] != nil {
		t.Fatalf("updated role=%#v body=%s", updatedRole, updated.Body)
	}
	gotByName := harness.exchange(t, http.MethodGet,
		"/organization/get-role?"+url.Values{"organizationId": []string{organizationID}, "roleName": []string{"project-editor"}}.Encode(),
		harness.owner.Cookie, nil,
	)
	requireOrganizationCRUDStatus(t, gotByName, http.StatusOK)
	if organizationCRUDObject(t, gotByName.Value, "role by name")["id"] != roleID {
		t.Fatalf("role by name=%#v", gotByName.Value)
	}

	memberActor := harness.signUp(t, "dynamic-member@example.test", "Dynamic Member")
	memberRecord := harness.addMemberDirect(t, organizationID, memberActor)
	memberID := organizationCRUDString(t, memberRecord, "id")
	setDynamicRole := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "memberId": memberID, "role": "project-editor",
	})
	requireOrganizationCRUDStatus(t, setDynamicRole, http.StatusOK)

	allowed := harness.exchange(t, http.MethodPost, "/organization/has-permission", memberActor.Cookie, map[string]any{
		"organizationId": organizationID,
		"permissions":    map[string]any{"project": []string{"read", "update"}},
	})
	requireOrganizationCRUDStatus(t, allowed, http.StatusOK)
	if organizationCRUDObject(t, allowed.Value, "allowed permission")["success"] != true {
		t.Fatalf("allowed permission=%s", allowed.Body)
	}
	denied := harness.exchange(t, http.MethodPost, "/organization/has-permission", memberActor.Cookie, map[string]any{
		"organizationId": organizationID,
		"permissions":    map[string]any{"project": []string{"delete"}},
	})
	requireOrganizationCRUDStatus(t, denied, http.StatusOK)
	if organizationCRUDObject(t, denied.Value, "denied permission")["success"] != false {
		t.Fatalf("denied permission=%s", denied.Body)
	}
	listDenied := harness.exchange(t, http.MethodGet,
		"/organization/list-roles?"+url.Values{"organizationId": []string{organizationID}}.Encode(),
		memberActor.Cookie, nil,
	)
	requireOrganizationCoreAPIError(t, listDenied, http.StatusForbidden, organization.ErrorRoleListForbidden)
	getDenied := harness.exchange(t, http.MethodGet,
		"/organization/get-role?"+url.Values{"organizationId": []string{organizationID}, "roleId": []string{roleID}}.Encode(),
		memberActor.Cookie, nil,
	)
	requireOrganizationCoreAPIError(t, getDenied, http.StatusForbidden, organization.ErrorRoleReadForbidden)
	createDenied := harness.exchange(t, http.MethodPost, "/organization/create-role", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "role": "unauthorized-create",
		"permission":       map[string]any{"project": []string{"read"}},
		"additionalFields": map[string]any{"color": "#000000"},
	})
	requireOrganizationCoreAPIError(t, createDenied, http.StatusForbidden, organization.ErrorRoleCreateForbidden)
	updateDenied := harness.exchange(t, http.MethodPost, "/organization/update-role", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "roleId": roleID,
		"data": map[string]any{"roleName": "unauthorized-update"},
	})
	requireOrganizationCoreAPIError(t, updateDenied, http.StatusForbidden, organization.ErrorRoleUpdateForbidden)
	deleteDenied := harness.exchange(t, http.MethodPost, "/organization/delete-role", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "roleId": roleID,
	})
	requireOrganizationCoreAPIError(t, deleteDenied, http.StatusForbidden, organization.ErrorRoleDeleteForbidden)

	assignedDelete := harness.exchange(t, http.MethodPost, "/organization/delete-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "roleName": "project-editor",
	})
	requireOrganizationCoreAPIError(t, assignedDelete, http.StatusBadRequest, organization.ErrorRoleAssignedToMembers)

	resetMember := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "memberId": memberID, "role": "member",
	})
	requireOrganizationCRUDStatus(t, resetMember, http.StatusOK)
	staticMemberList := harness.exchange(t, http.MethodGet,
		"/organization/list-roles?"+url.Values{"organizationId": []string{organizationID}}.Encode(),
		memberActor.Cookie, nil,
	)
	requireOrganizationCRUDStatus(t, staticMemberList, http.StatusOK)
	deleted := harness.exchange(t, http.MethodPost, "/organization/delete-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "roleId": roleID,
	})
	requireOrganizationCRUDStatus(t, deleted, http.StatusOK)
	missingDelete := harness.exchange(t, http.MethodPost, "/organization/delete-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "roleId": roleID,
	})
	requireOrganizationCoreAPIError(t, missingDelete, http.StatusBadRequest, organization.ErrorRoleNotFound)
	disposable := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "role": "delete-by-name",
		"permission":       map[string]any{"project": []string{"read"}},
		"additionalFields": map[string]any{"color": "#000000"},
	})
	requireOrganizationCRUDStatus(t, disposable, http.StatusOK)
	deletedByName := harness.exchange(t, http.MethodPost, "/organization/delete-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "roleName": "delete-by-name",
	})
	requireOrganizationCRUDStatus(t, deletedByName, http.StatusOK)

	predefined := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "role": "admin",
		"permission": map[string]any{"project": []string{"read"}},
	})
	requireOrganizationCoreAPIError(t, predefined, http.StatusBadRequest, organization.ErrorRoleNameTaken)
	invalidResource := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "role": "invalid-resource",
		"permission": map[string]any{"unknown": []string{"read"}},
	})
	requireOrganizationCoreAPIError(t, invalidResource, http.StatusBadRequest, organization.ErrorInvalidRoleResource)

	adminActor := harness.signUp(t, "dynamic-admin@example.test", "Dynamic Admin")
	adminMember := harness.invoke(t, "addMember", map[string]any{
		"organizationId": organizationID, "userId": adminActor.ID, "role": "admin",
	})
	requireOrganizationCRUDStatus(t, adminMember, http.StatusOK)
	privilegeEscalation := harness.exchange(t, http.MethodPost, "/organization/create-role", adminActor.Cookie, map[string]any{
		"organizationId": organizationID, "role": "sales-owner",
		"permission": map[string]any{"sales": []string{"create", "delete", "create", "update"}},
	})
	requireOrganizationCRUDStatus(t, privilegeEscalation, http.StatusForbidden)
	privilegeError := organizationCRUDObject(t, privilegeEscalation.Value, "privilege error")
	if privilegeError["code"] != organization.ErrorRoleCreateForbidden {
		t.Fatalf("privilege error=%#v body=%s", privilegeError, privilegeEscalation.Body)
	}
	missing := organizationCRUDArray(t, privilegeError["missingPermissions"], "missing permissions")
	if fmt.Sprint(missing) != "[sales:delete sales:update]" {
		t.Fatalf("missing permissions=%#v", missing)
	}

	managerActor := harness.signUp(t, "manager@example.test", "Manager")
	managerMember := harness.invoke(t, "addMember", map[string]any{
		"organizationId": organizationID, "userId": managerActor.ID, "role": "manager",
	})
	requireOrganizationCRUDStatus(t, managerMember, http.StatusOK)
	newName := "Managed Organization"
	managed := harness.exchange(t, http.MethodPost, "/organization/update", managerActor.Cookie, map[string]any{
		"organizationId": organizationID, "data": map[string]any{"name": newName},
	})
	requireOrganizationCRUDStatus(t, managed, http.StatusOK)
	if organizationCRUDObject(t, managed.Value, "manager update")["name"] != newName {
		t.Fatalf("manager update=%s", managed.Body)
	}

	operatorCreated := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "role": "operator",
		"permission": map[string]any{
			"organization": []string{"update"},
			"invitation":   []string{"create", "cancel"},
			"member":       []string{"update", "delete"},
			"team":         []string{"create", "update", "delete"},
			"ac":           []string{"read"},
		},
		"additionalFields": map[string]any{"color": "#222222"},
	})
	requireOrganizationCRUDStatus(t, operatorCreated, http.StatusOK)
	operatorRole := organizationCRUDObject(t,
		organizationCRUDObject(t, operatorCreated.Value, "operator response")["roleData"],
		"operator role",
	)
	if operatorRole["role"] != "operator" {
		t.Fatalf("operator role=%#v", operatorRole)
	}
	setOperator := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "memberId": memberID, "role": "operator",
	})
	requireOrganizationCRUDStatus(t, setOperator, http.StatusOK)

	operatorUpdate := harness.exchange(t, http.MethodPost, "/organization/update", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "data": map[string]any{"name": "Operator Managed"},
	})
	requireOrganizationCRUDStatus(t, operatorUpdate, http.StatusOK)
	creatorInviteDenied := harness.exchange(t, http.MethodPost, "/organization/invite-member", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "email": "operator-owner-invite@example.test", "role": "owner",
	})
	requireOrganizationCoreAPIError(
		t, creatorInviteDenied, http.StatusForbidden, organization.ErrorInvitationCreatorRoleForbidden,
	)
	unknownRoleInvite := harness.exchange(t, http.MethodPost, "/organization/invite-member", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "email": "unknown-role-invite@example.test", "role": "does-not-exist",
	})
	requireOrganizationCoreAPIError(t, unknownRoleInvite, http.StatusBadRequest, organization.ErrorRoleNotFound)
	invited := harness.exchange(t, http.MethodPost, "/organization/invite-member", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "email": "operator-invite@example.test", "role": "operator",
	})
	requireOrganizationCRUDStatus(t, invited, http.StatusOK)
	invitationID := organizationCRUDString(t, organizationCRUDObject(t, invited.Value, "operator invitation"), "id")
	canceled := harness.exchange(t, http.MethodPost, "/organization/cancel-invitation", memberActor.Cookie, map[string]any{
		"invitationId": invitationID,
	})
	requireOrganizationCRUDStatus(t, canceled, http.StatusOK)

	teamCreated := harness.exchange(t, http.MethodPost, "/organization/create-team", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "name": "Operator Team",
	})
	requireOrganizationCRUDStatus(t, teamCreated, http.StatusOK)
	teamID := organizationCRUDString(t, organizationCRUDObject(t, teamCreated.Value, "operator team"), "id")
	teamUpdated := harness.exchange(t, http.MethodPost, "/organization/update-team", memberActor.Cookie, map[string]any{
		"teamId": teamID, "data": map[string]any{"organizationId": organizationID, "name": "Updated Operator Team"},
	})
	requireOrganizationCRUDStatus(t, teamUpdated, http.StatusOK)
	targetActor := harness.signUp(t, "operator-target@example.test", "Operator Target")
	targetMember := harness.addMemberDirect(t, organizationID, targetActor)
	targetMemberID := organizationCRUDString(t, targetMember, "id")
	teamMemberAdded := harness.exchange(t, http.MethodPost, "/organization/add-team-member", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "teamId": teamID, "userId": targetActor.ID,
	})
	requireOrganizationCRUDStatus(t, teamMemberAdded, http.StatusOK)
	teamMemberRemoved := harness.exchange(t, http.MethodPost, "/organization/remove-team-member", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "teamId": teamID, "userId": targetActor.ID,
	})
	requireOrganizationCRUDStatus(t, teamMemberRemoved, http.StatusOK)
	targetRoleUpdated := harness.exchange(t, http.MethodPost, "/organization/update-member-role", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "memberId": targetMemberID, "role": "manager",
	})
	requireOrganizationCRUDStatus(t, targetRoleUpdated, http.StatusOK)
	targetRemoved := harness.exchange(t, http.MethodPost, "/organization/remove-member", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "memberIdOrEmail": targetMemberID,
	})
	requireOrganizationCRUDStatus(t, targetRemoved, http.StatusOK)
	teamRemoved := harness.exchange(t, http.MethodPost, "/organization/remove-team", memberActor.Cookie, map[string]any{
		"organizationId": organizationID, "teamId": teamID,
	})
	requireOrganizationCRUDStatus(t, teamRemoved, http.StatusOK)
	resetOperator := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "memberId": memberID, "role": "member",
	})
	requireOrganizationCRUDStatus(t, resetOperator, http.StatusOK)

	encodedAugment, err := json.Marshal(authorization.Statements{"project": {"delete"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "organizationRole",
		Data: storage.Record{
			"organizationId": organizationID, "role": "member",
			"permission": string(encodedAugment), "createdAt": time.Now(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	merged := harness.exchange(t, http.MethodPost, "/organization/has-permission", memberActor.Cookie, map[string]any{
		"organizationId": organizationID,
		"permissions": map[string]any{
			"project": []string{"delete"}, "ac": []string{"read"},
		},
	})
	requireOrganizationCRUDStatus(t, merged, http.StatusOK)
	if organizationCRUDObject(t, merged.Value, "merged permission")["success"] != true {
		t.Fatalf("merged permission=%s", merged.Body)
	}

	secondOrganization := harness.createHTTP(t, harness.owner, "Other Organization", "other-organization", nil)
	secondID := organizationCRUDString(t, secondOrganization, "id")
	crossOrganization := harness.exchange(t, http.MethodGet,
		"/organization/list-roles?"+url.Values{"organizationId": []string{secondID}}.Encode(),
		memberActor.Cookie, nil,
	)
	requireOrganizationCoreAPIError(t, crossOrganization, http.StatusForbidden, organization.ErrorNotMemberOfOrganization)

	deletedOrganization := harness.exchange(t, http.MethodPost, "/organization/delete", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID,
	})
	requireOrganizationCRUDStatus(t, deletedOrganization, http.StatusOK)
	roleCount, err := harness.auth.Adapter().Count(t.Context(), storage.CountParams{
		Model: "organizationRole", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
	})
	if err != nil || roleCount != 0 {
		t.Fatalf("organization role count after cascade=%d err=%v", roleCount, err)
	}
}

func TestOrganizationDynamicRoleLimitIsAtomic(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		maximum := 1
		var callbackMu sync.Mutex
		callbackCalls := 0
		options := organizationDynamicAccessOptions(&maximum)
		options.DynamicAccessControl.MaximumRolesPerOrganization = nil
		options.DynamicAccessControl.MaximumRolesPerOrganizationFunc = func(_ context.Context, organizationID string) (int, error) {
			callbackMu.Lock()
			callbackCalls++
			callbackMu.Unlock()
			if organizationID == "" {
				return 0, fmt.Errorf("empty organization id")
			}
			return 1, nil
		}
		harness := newOrganizationCRUDHarness(t, options)
		created := harness.createHTTP(t, harness.owner, "Atomic Roles", "atomic-roles", nil)
		organizationID := organizationCRUDString(t, created, "id")
		headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: harness.owner.Cookie})
		statuses := concurrentOrganizationDirectStatuses(t, 2, func(index int) (int, error) {
			result, err := harness.auth.API().Call(t.Context(), "createOrgRole", singleauth.DirectCallInput{
				Method: http.MethodPost, Headers: headers,
				Body: map[string]any{
					"organizationId":   organizationID,
					"role":             fmt.Sprintf("atomic-%d", index),
					"permission":       map[string]any{"project": []string{"read"}},
					"additionalFields": map[string]any{"color": "#000000"},
				},
			})
			return result.Response.Status(), err
		})
		requireConcurrentOrganizationStatuses(t, statuses, http.StatusOK, http.StatusBadRequest)
		count, err := harness.auth.Adapter().Count(t.Context(), storage.CountParams{
			Model: "organizationRole", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if err != nil || count != 1 {
			t.Fatalf("dynamic role count=%d err=%v", count, err)
		}
		callbackMu.Lock()
		defer callbackMu.Unlock()
		if callbackCalls != 2 {
			t.Fatalf("maximum role callback calls=%d want=2", callbackCalls)
		}
	})
}

func TestOrganizationDynamicPermissionCompositionSemantics(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organizationDynamicAccessOptions(nil))
		created := harness.createHTTP(t, harness.owner, "Permission Composition", "permission-composition", nil)
		organizationID := organizationCRUDString(t, created, "id")
		actor := harness.signUp(t, "permission-composer@example.test", "Permission Composer")
		member := harness.addMemberDirect(t, organizationID, actor)
		memberID := organizationCRUDString(t, member, "id")

		for roleName, permission := range map[string]map[string]any{
			"project-granter": {
				"ac": []string{"create"}, "project": []string{"create"},
			},
			"sales-granter": {
				"sales": []string{"create"},
			},
		} {
			response := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
				"organizationId": organizationID, "role": roleName, "permission": permission,
				"additionalFields": map[string]any{"color": "#000000"},
			})
			requireOrganizationCRUDStatus(t, response, http.StatusOK)
		}
		assigned := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
			"organizationId": organizationID, "memberId": memberID,
			"role": []string{"project-granter", "sales-granter"},
		})
		requireOrganizationCRUDStatus(t, assigned, http.StatusOK)

		combinedCheck := harness.exchange(t, http.MethodPost, "/organization/has-permission", actor.Cookie, map[string]any{
			"organizationId": organizationID,
			"permissions": map[string]any{
				"project": []string{"create"}, "sales": []string{"create"},
			},
		})
		requireOrganizationCRUDStatus(t, combinedCheck, http.StatusOK)
		if organizationCRUDObject(t, combinedCheck.Value, "combined permission")["success"] != false {
			t.Fatalf("permissions from separate roles were incorrectly unioned: %s", combinedCheck.Body)
		}

		createdComposite := harness.exchange(t, http.MethodPost, "/organization/create-role", actor.Cookie, map[string]any{
			"organizationId": organizationID, "role": "composite",
			"permission": map[string]any{
				"project": []string{"create"}, "sales": []string{"create"},
			},
			"additionalFields": map[string]any{"color": "#000000"},
		})
		requireOrganizationCRUDStatus(t, createdComposite, http.StatusOK)
	})
}

func TestOrganizationDynamicRoleExplicitZeroLimit(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		zero := 0
		harness := newOrganizationCRUDHarness(t, organizationDynamicAccessOptions(&zero))
		created := harness.createHTTP(t, harness.owner, "Zero Roles", "zero-roles", nil)
		organizationID := organizationCRUDString(t, created, "id")
		response := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
			"organizationId": organizationID, "role": "blocked",
			"permission":       map[string]any{"project": []string{"read"}},
			"additionalFields": map[string]any{"color": "#000000"},
		})
		requireOrganizationCoreAPIError(t, response, http.StatusBadRequest, organization.ErrorTooManyRoles)
		// single-auth applies the organization role cap before inspecting the
		// requested role's resource vocabulary or privilege ceiling.
		invalid := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
			"organizationId": organizationID, "role": "still-blocked",
			"permission":       map[string]any{"unknown": []string{"read"}},
			"additionalFields": map[string]any{"color": "#000000"},
		})
		requireOrganizationCoreAPIError(t, invalid, http.StatusBadRequest, organization.ErrorTooManyRoles)
	})
}

func TestOrganizationDynamicPermissionRejectsCorruptStoredRole(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organizationDynamicAccessOptions(nil))
		created := harness.createHTTP(t, harness.owner, "Corrupt Role", "corrupt-role", nil)
		organizationID := organizationCRUDString(t, created, "id")
		_, err := harness.auth.Adapter().Create(t.Context(), storage.CreateParams{
			Model: "organizationRole",
			Data: storage.Record{
				"organizationId": organizationID, "role": "broken",
				"permission": "null", "createdAt": time.Now(),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		response := harness.exchange(t, http.MethodPost, "/organization/has-permission", harness.owner.Cookie, map[string]any{
			"organizationId": organizationID,
			"permissions":    map[string]any{"organization": []string{"update"}},
		})
		requireOrganizationCoreAPIError(t, response, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
		if body := organizationCRUDObject(t, response.Value, "corrupt role error"); body["message"] != "Invalid permissions for role broken" {
			t.Fatalf("corrupt role error=%#v", body)
		}
	})
}

func TestOrganizationDynamicAccessEndpointsAndSchemaAreConditional(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		disabled := newOrganizationCRUDHarness(t, organization.Options{})
		response := disabled.exchange(t, http.MethodGet, "/organization/list-roles", disabled.owner.Cookie, nil)
		requireOrganizationCoreAPIError(t, response, http.StatusNotFound, "NOT_FOUND")
		if _, exists := disabled.auth.Registry().Endpoint("createOrgRole"); exists {
			t.Fatal("dynamic access endpoint is registered while disabled")
		}
		if _, exists := disabled.auth.Options().Schema.Models["organizationRole"]; exists {
			t.Fatal("organizationRole schema is registered while disabled")
		}

		enabled := newOrganizationCRUDHarness(t, organizationDynamicAccessOptions(nil))
		want := map[string]struct {
			path   string
			method string
		}{
			"createOrgRole": {"/organization/create-role", http.MethodPost},
			"deleteOrgRole": {"/organization/delete-role", http.MethodPost},
			"listOrgRoles":  {"/organization/list-roles", http.MethodGet},
			"getOrgRole":    {"/organization/get-role", http.MethodGet},
			"updateOrgRole": {"/organization/update-role", http.MethodPost},
		}
		for name, expected := range want {
			endpoint, exists := enabled.auth.Registry().Endpoint(name)
			if !exists || endpoint.Path != expected.path || len(endpoint.Methods) != 1 || endpoint.Methods[0] != expected.method {
				t.Fatalf("endpoint %s=%#v exists=%v want path=%q method=%q", name, endpoint, exists, expected.path, expected.method)
			}
		}
		roleSchema, exists := enabled.auth.Options().Schema.Models["organizationRole"]
		if !exists || roleSchema.Fields["organizationId"].References == nil ||
			roleSchema.Fields["organizationId"].References.Model != "organization" {
			t.Fatalf("organizationRole schema=%#v exists=%v", roleSchema, exists)
		}
	})
}

func TestOrganizationDynamicAccessMissingControl(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organization.Options{
			DynamicAccessControl: organization.DynamicAccessControlOptions{Enabled: true},
		})
		created := harness.createHTTP(t, harness.owner, "Missing AC", "missing-ac", nil)
		organizationID := organizationCRUDString(t, created, "id")
		response := harness.exchange(t, http.MethodPost, "/organization/create-role", harness.owner.Cookie, map[string]any{
			"organizationId": organizationID, "role": "test",
			"permission": map[string]any{"project": []string{"read"}},
		})
		requireOrganizationCoreAPIError(t, response, http.StatusNotImplemented, organization.ErrorMissingAccessControl)
	})
}

func TestOrganizationCustomRolesReplaceDefaultPermissionMap(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Roles: map[string]*authorization.Role{
				"manager": authorization.NewRole(authorization.Statements{"organization": {"update"}}),
			},
		})
		created := harness.createHTTP(t, harness.owner, "Custom Roles", "custom-roles", nil)
		organizationID := organizationCRUDString(t, created, "id")
		ownerDenied := harness.exchange(t, http.MethodPost, "/organization/update", harness.owner.Cookie, map[string]any{
			"organizationId": organizationID, "data": map[string]any{"name": "Owner Must Not Update"},
		})
		requireOrganizationCoreAPIError(
			t, ownerDenied, http.StatusForbidden, organization.ErrorOrganizationUpdateForbidden,
		)

		manager := harness.signUp(t, "custom-manager@example.test", "Custom Manager")
		added := harness.invoke(t, "addMember", map[string]any{
			"organizationId": organizationID, "userId": manager.ID, "role": "manager",
		})
		requireOrganizationCRUDStatus(t, added, http.StatusOK)
		updated := harness.exchange(t, http.MethodPost, "/organization/update", manager.Cookie, map[string]any{
			"organizationId": organizationID, "data": map[string]any{"name": "Manager Updated"},
		})
		requireOrganizationCRUDStatus(t, updated, http.StatusOK)
	})
}

func organizationDynamicAccessOptions(maximum *int) organization.Options {
	statements := cloneAccessStatements(organization.DefaultStatements)
	statements["project"] = []string{"create", "read", "update", "delete"}
	statements["sales"] = []string{"create", "read", "update", "delete"}
	control := authorization.CreateAccessControl(statements)
	_, defaults := organization.DefaultAccessControl()
	owner := defaults["owner"].Statements()
	owner["project"] = []string{"create", "read", "update", "delete"}
	owner["sales"] = []string{"create", "read", "update", "delete"}
	admin := defaults["admin"].Statements()
	admin["project"] = []string{"create", "read", "update"}
	admin["sales"] = []string{"create", "read"}
	member := defaults["member"].Statements()
	member["project"] = []string{"read"}
	member["sales"] = []string{"read"}
	manager := authorization.Statements{
		"organization": {"update"}, "ac": {"read"},
	}
	defaultTeam := false
	return organization.Options{
		AccessControl: control,
		Roles: map[string]*authorization.Role{
			"owner": control.NewRole(owner), "admin": control.NewRole(admin),
			"member": control.NewRole(member), "manager": control.NewRole(manager),
		},
		DynamicAccessControl: organization.DynamicAccessControlOptions{
			Enabled: true, MaximumRolesPerOrganization: maximum,
		},
		Teams: organization.TeamsOptions{
			Enabled: true, DefaultTeamEnabled: &defaultTeam, AllowRemovingAllTeams: true,
		},
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"organizationRole": {
				Fields: map[string]storage.FieldAttribute{
					"color": {Type: storage.FieldString, DefaultValue: storage.StaticValue("#ffffff")},
					"serverOnlyValue": {
						Type: storage.FieldString, Input: storage.Bool(false),
						DefaultValue: storage.StaticValue("server-only-value"),
					},
					"hidden": {
						Type: storage.FieldString, Returned: storage.Bool(false),
						DefaultValue: storage.StaticValue("hidden-value"),
					},
				},
			},
		}},
	}
}

func cloneAccessStatements(source authorization.Statements) authorization.Statements {
	result := make(authorization.Statements, len(source))
	for resource, actions := range source {
		result[resource] = append([]string(nil), actions...)
	}
	return result
}
