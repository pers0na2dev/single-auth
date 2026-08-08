package organization

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

// DefaultStatements is single-auth 1.6.26's organization permission
// vocabulary. Applications can extend this map before constructing their own
// authorization.AccessControl.
var DefaultStatements = authorization.Statements{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
}

// DefaultAccessControl returns independent built-in role values on each call.
func DefaultAccessControl() (*authorization.AccessControl, map[string]*authorization.Role) {
	control := authorization.CreateAccessControl(DefaultStatements)
	roles := map[string]*authorization.Role{
		"admin": control.NewRole(authorization.Statements{
			"organization": {"update"},
			"invitation":   {"create", "cancel"},
			"member":       {"create", "update", "delete"},
			"team":         {"create", "update", "delete"},
			"ac":           {"create", "read", "update", "delete"},
		}),
		"owner": control.NewRole(authorization.Statements{
			"organization": {"update", "delete"},
			"member":       {"create", "update", "delete"},
			"invitation":   {"create", "cancel"},
			"team":         {"create", "update", "delete"},
			"ac":           {"create", "read", "update", "delete"},
		}),
		"member": control.NewRole(authorization.Statements{
			"organization": {},
			"member":       {},
			"invitation":   {},
			"team":         {},
			"ac":           {"read"},
		}),
	}
	return control, roles
}

func cloneOrganizationRoles(source map[string]*authorization.Role) map[string]*authorization.Role {
	if source == nil {
		return nil
	}
	result := make(map[string]*authorization.Role, len(source))
	for name, role := range source {
		if role == nil {
			result[name] = nil
			continue
		}
		result[name] = authorization.NewRole(role.Statements())
	}
	return result
}

func (runtime *runtime) baseOrganizationRoles() map[string]*authorization.Role {
	if runtime.options.Roles != nil {
		return cloneOrganizationRoles(runtime.options.Roles)
	}
	_, roles := DefaultAccessControl()
	return roles
}

func (runtime *runtime) hasOrganizationPermission(
	ctx context.Context,
	organizationID string,
	memberRole string,
	permissions authorization.Statements,
	allowCreatorAllPermissions bool,
) (bool, error) {
	roles := runtime.baseOrganizationRoles()
	if runtime.options.DynamicAccessControl.Enabled && runtime.options.AccessControl != nil {
		rows, err := findAllOrganizationRecords(
			ctx,
			runtime.adapter,
			"organizationRole",
			[]storage.Where{{Field: "organizationId", Value: organizationID}},
		)
		if err != nil {
			return false, fmt.Errorf("organization: has permission: list roles: %w", err)
		}
		for _, row := range rows {
			roleName, _ := recordString(row, "role")
			permission, err := decodeOrganizationRolePermission(row["permission"], roleName)
			if err != nil {
				return false, err
			}
			merged := authorization.Statements{}
			if existing := roles[roleName]; existing != nil {
				for resource, actions := range existing.Statements() {
					merged[resource] = append([]string(nil), actions...)
				}
			}
			for resource, actions := range permission {
				merged[resource] = appendUniqueActions(merged[resource], actions)
			}
			roles[roleName] = runtime.options.AccessControl.NewRole(merged)
		}
	}

	roleNames := strings.Split(memberRole, ",")
	if allowCreatorAllPermissions && stringSliceContains(roleNames, runtime.creatorRole) {
		return true, nil
	}
	if len(permissions) == 0 {
		return false, nil
	}
	request := organizationPermissionRequest(permissions)
	for _, roleName := range roleNames {
		candidate := roles[roleName]
		if candidate == nil {
			continue
		}
		result, err := candidate.Authorize(request)
		if err == nil && result.Success {
			return true, nil
		}
	}
	return false, nil
}

func organizationPermissionRequest(permission authorization.Statements) authorization.AuthorizeRequest {
	resources := make([]string, 0, len(permission))
	for resource := range permission {
		resources = append(resources, resource)
	}
	sort.Strings(resources)
	request := make(authorization.AuthorizeRequest, 0, len(resources))
	for _, resource := range resources {
		request = append(request, authorization.ResourceRequest{
			Resource: resource,
			Actions:  append([]string(nil), permission[resource]...),
		})
	}
	return request
}

func appendUniqueActions(existing, additional []string) []string {
	result := append([]string(nil), existing...)
	for _, action := range additional {
		if !stringSliceContains(result, action) {
			result = append(result, action)
		}
	}
	return result
}

func decodeOrganizationRolePermission(value any, roleName string) (authorization.Statements, error) {
	var raw []byte
	switch typed := value.(type) {
	case string:
		raw = []byte(typed)
	case []byte:
		raw = append([]byte(nil), typed...)
	default:
		return nil, invalidStoredOrganizationRole(roleName, nil)
	}
	var permission authorization.Statements
	if err := json.Unmarshal(raw, &permission); err != nil || permission == nil {
		return nil, invalidStoredOrganizationRole(roleName, err)
	}
	for _, actions := range permission {
		if actions == nil {
			return nil, invalidStoredOrganizationRole(roleName, nil)
		}
	}
	return permission, nil
}

func invalidStoredOrganizationRole(roleName string, cause error) error {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Invalid permissions for role "+roleName,
	).WithCause(cause)
}

func (runtime *runtime) validateOrganizationRoles(
	ctx context.Context,
	organizationID string,
	roles []string,
) error {
	valid := map[string]struct{}{"owner": {}, "admin": {}, "member": {}}
	for roleName := range runtime.options.Roles {
		valid[roleName] = struct{}{}
	}
	unknown := make([]string, 0)
	for _, roleName := range roles {
		if _, exists := valid[roleName]; !exists {
			unknown = append(unknown, roleName)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	if runtime.options.DynamicAccessControl.Enabled {
		rows, err := runtime.adapter.FindMany(ctx, storage.FindManyParams{
			Model: "organizationRole",
			Where: []storage.Where{
				{Field: "organizationId", Value: organizationID},
				{Field: "role", Value: unknown, Operator: storage.OpIn},
			},
			Limit: storage.Int(len(unknown)),
		})
		if err != nil {
			return fmt.Errorf("organization: validate roles: %w", err)
		}
		for _, row := range rows {
			if roleName, ok := recordString(row, "role"); ok {
				valid[roleName] = struct{}{}
			}
		}
		stillUnknown := unknown[:0]
		for _, roleName := range unknown {
			if _, exists := valid[roleName]; !exists {
				stillUnknown = append(stillUnknown, roleName)
			}
		}
		unknown = stillUnknown
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

func (runtime *runtime) predefinedOrganizationRoleNames() []string {
	if runtime.options.Roles == nil {
		return []string{"owner", "admin", "member"}
	}
	result := make([]string, 0, len(runtime.options.Roles))
	for roleName := range runtime.options.Roles {
		result = append(result, roleName)
	}
	sort.Strings(result)
	return result
}
