package admin

import "github.com/pers0na2dev/single-auth/security/authorization"

// DefaultStatements is the frozen single-auth 1.6.26 admin vocabulary.
var DefaultStatements = authorization.Statements{
	"user": {
		"create", "list", "set-role", "ban", "impersonate",
		"impersonate-admins", "delete", "set-password", "set-email",
		"get", "update",
	},
	"session": {"list", "revoke", "delete"},
}

// DefaultAccessControl creates independent role values on every call.
func DefaultAccessControl() (*authorization.AccessControl, map[string]*authorization.Role) {
	control := authorization.CreateAccessControl(DefaultStatements)
	roles := map[string]*authorization.Role{
		"admin": control.NewRole(authorization.Statements{
			"user": {
				"create", "list", "set-role", "ban", "impersonate",
				"delete", "set-password", "set-email", "get", "update",
			},
			"session": {"list", "revoke", "delete"},
		}),
		"user": control.NewRole(authorization.Statements{
			"user": {}, "session": {},
		}),
	}
	return control, roles
}

func cloneRoles(source map[string]*authorization.Role) map[string]*authorization.Role {
	if source == nil {
		return nil
	}
	result := make(map[string]*authorization.Role, len(source))
	for name, role := range source {
		if role == nil {
			result[name] = authorization.NewRole(nil)
			continue
		}
		result[name] = authorization.NewRole(role.Statements())
	}
	return result
}

func hasPermission(userID, role string, options Options, permissions authorization.AuthorizeRequest) bool {
	if userID != "" && containsString(options.AdminUserIDs, userID) {
		return true
	}
	if len(permissions) == 0 {
		return false
	}
	roles := options.Roles
	if roles == nil {
		_, roles = DefaultAccessControl()
	}
	if role == "" {
		role = options.DefaultRole
	}
	if role == "" {
		role = "user"
	}
	for _, roleName := range splitComma(role) {
		candidate := roles[roleName]
		if candidate == nil {
			continue
		}
		result, err := candidate.Authorize(permissions)
		if err == nil && result.Success {
			return true
		}
	}
	return false
}
