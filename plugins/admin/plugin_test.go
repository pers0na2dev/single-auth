package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDescriptorSchemaDefaultsErrorsAndSnapshots(t *testing.T) {
	roles := map[string]*authorization.Role{"admin": authorization.NewRole(authorization.Statements{"user": {"list"}})}
	adminRoles := []string{"admin"}
	userIDs := []string{"root"}
	descriptor, err := New(Options{Roles: roles, AdminRoles: adminRoles, AdminUserIDs: userIDs})
	if err != nil {
		t.Fatal(err)
	}
	roles["admin"] = authorization.NewRole(nil)
	adminRoles[0] = "mutated"
	userIDs[0] = "mutated"
	if descriptor.ID != PluginID || descriptor.Version != Version || len(descriptor.Endpoints) != 15 {
		t.Fatalf("descriptor=%#v", descriptor)
	}
	wantPaths := map[string]string{
		"setRole": "/admin/set-role", "getUser": "/admin/get-user",
		"createUser": "/admin/create-user", "adminUpdateUser": "/admin/update-user",
		"listUsers": "/admin/list-users", "listUserSessions": "/admin/list-user-sessions",
		"unbanUser": "/admin/unban-user", "banUser": "/admin/ban-user",
		"impersonateUser": "/admin/impersonate-user", "stopImpersonating": "/admin/stop-impersonating",
		"revokeUserSession": "/admin/revoke-user-session", "revokeUserSessions": "/admin/revoke-user-sessions",
		"removeUser": "/admin/remove-user", "setUserPassword": "/admin/set-user-password",
		"userHasPermission": "/admin/has-permission",
	}
	for _, endpoint := range descriptor.Endpoints {
		if wantPaths[endpoint.Name] != endpoint.Path || len(endpoint.Methods) != 1 {
			t.Fatalf("endpoint=%#v", endpoint)
		}
	}
	userSchema := descriptor.Schema.Models["user"]
	if userSchema.Fields["role"].Type != storage.FieldString ||
		userSchema.Fields["banned"].Type != storage.FieldBoolean ||
		userSchema.Fields["banExpires"].Type != storage.FieldDate ||
		descriptor.Schema.Models["session"].Fields["impersonatedBy"].Type != storage.FieldString {
		t.Fatalf("schema=%#v", descriptor.Schema)
	}
	if len(descriptor.ErrorCodes) != len(errorMessages) {
		t.Fatalf("errors=%#v", descriptor.ErrorCodes)
	}
	if _, err := New(Options{AdminRoles: []string{"missing"}}); err == nil || !strings.Contains(err.Error(), "Invalid admin roles") {
		t.Fatalf("invalid admin roles error=%v", err)
	}
	customSchema := storage.Schema{Models: map[string]storage.ModelSchema{"user": {Fields: map[string]storage.FieldAttribute{
		"role": {Type: storage.FieldString, FieldName: "custom_role", Required: storage.Bool(false)},
	}}}}
	merged, err := Schema(customSchema)
	if err != nil || merged.Models["user"].Fields["role"].FieldName != "custom_role" {
		t.Fatalf("custom schema=%#v err=%v", merged, err)
	}
	if DefaultBannedUserMessage == "" || time.Hour <= 0 {
		t.Fatal("invalid frozen defaults")
	}
}
