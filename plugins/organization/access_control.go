package organization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

var organizationRoleBaseFields = map[string]struct{}{
	"id": {}, "organizationId": {}, "role": {}, "permission": {},
	"createdAt": {}, "updatedAt": {},
}

type organizationRoleSelector struct {
	RoleName string
	RoleID   string
}

func (selector organizationRoleSelector) where() []storage.Where {
	if selector.RoleName != "" {
		return []storage.Where{{Field: "role", Value: selector.RoleName}}
	}
	return []storage.Where{{Field: "id", Value: selector.RoleID}}
}

func decodeOrganizationPermission(raw json.RawMessage) (authorization.Statements, error) {
	var permission authorization.Statements
	if len(raw) == 0 || string(raw) == "null" {
		return nil, invalidOrganizationBody(nil)
	}
	if err := json.Unmarshal(raw, &permission); err != nil || permission == nil {
		return nil, invalidOrganizationBody(err)
	}
	for _, actions := range permission {
		if actions == nil {
			return nil, invalidOrganizationBody(nil)
		}
	}
	return permission, nil
}

func organizationRoleSession(ctx *engine.Context) (*singleauth.PluginSessionState, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session == nil {
		return nil, unauthorizedOrganization()
	}
	return session, nil
}

func organizationRoleOrganizationID(explicit string, session *singleauth.PluginSessionState) string {
	organizationID := strings.TrimSpace(explicit)
	if organizationID == "" && session != nil {
		organizationID, _ = recordString(session.Session, "activeOrganizationId")
	}
	return organizationID
}

func organizationRoleSelectorFromRaw(raw map[string]json.RawMessage) (organizationRoleSelector, error) {
	var selector organizationRoleSelector
	if value, exists := raw["roleName"]; exists {
		if err := json.Unmarshal(value, &selector.RoleName); err != nil || selector.RoleName == "" {
			return organizationRoleSelector{}, invalidOrganizationBody(err)
		}
	}
	if value, exists := raw["roleId"]; exists {
		if err := json.Unmarshal(value, &selector.RoleID); err != nil || selector.RoleID == "" {
			return organizationRoleSelector{}, invalidOrganizationBody(err)
		}
	}
	if selector.RoleName == "" && selector.RoleID == "" {
		return organizationRoleSelector{}, invalidOrganizationBody(nil)
	}
	return selector, nil
}

func (runtime *runtime) findRoleActor(
	ctx context.Context,
	organizationID string,
	userID string,
) (storage.Record, error) {
	member, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member",
		Where: []storage.Where{
			{Field: "organizationId", Value: organizationID},
			{Field: "userId", Value: userID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("organization: role: find member: %w", err)
	}
	if member == nil {
		return nil, organizationError(contract.StatusForbidden, ErrorNotMemberOfOrganization)
	}
	return member, nil
}

func (runtime *runtime) requireRolePermission(
	ctx context.Context,
	organizationID string,
	member storage.Record,
	action string,
	errorCode string,
) error {
	memberRole, _ := recordString(member, "role")
	allowed, err := runtime.hasOrganizationPermission(
		ctx, organizationID, memberRole, authorization.Statements{"ac": {action}}, false,
	)
	if err != nil {
		return err
	}
	if !allowed {
		return organizationError(contract.StatusForbidden, errorCode)
	}
	return nil
}

func (runtime *runtime) ensureValidRoleResources(permission authorization.Statements) error {
	if runtime.options.AccessControl == nil {
		return organizationError(501, ErrorMissingAccessControl)
	}
	valid := runtime.options.AccessControl.Statements()
	for resource := range permission {
		if _, exists := valid[resource]; !exists {
			return organizationError(contract.StatusBadRequest, ErrorInvalidRoleResource)
		}
	}
	return nil
}

func (runtime *runtime) ensureMemberCanGrantRolePermissions(
	ctx context.Context,
	organizationID string,
	member storage.Record,
	permission authorization.Statements,
	action string,
) error {
	memberRole, _ := recordString(member, "role")
	missing := make([]string, 0)
	resources := make([]string, 0, len(permission))
	for resource := range permission {
		resources = append(resources, resource)
	}
	sort.Strings(resources)
	for _, resource := range resources {
		actions := permission[resource]
		for _, requestedAction := range actions {
			allowed, err := runtime.hasOrganizationPermission(
				ctx,
				organizationID,
				memberRole,
				authorization.Statements{resource: {requestedAction}},
				false,
			)
			if err != nil {
				return err
			}
			if !allowed {
				missing = append(missing, resource+":"+requestedAction)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	code := ErrorRoleGetForbidden
	switch action {
	case "create":
		code = ErrorRoleCreateForbidden
	case "update":
		code = ErrorRoleUpdateForbidden
	case "delete":
		code = ErrorRoleDeleteForbidden
	case "read":
		code = ErrorRoleReadForbidden
	case "list":
		code = ErrorRoleListForbidden
	}
	base := organizationError(contract.StatusForbidden, code)
	return base.WithWireBody(map[string]any{
		"code": code, "message": base.Message, "missingPermissions": missing,
	})
}

func (runtime *runtime) ensureRoleNameAvailable(
	ctx context.Context,
	organizationID string,
	roleName string,
	includeDatabase bool,
) error {
	for _, predefined := range runtime.predefinedOrganizationRoleNames() {
		if roleName == predefined {
			return organizationError(contract.StatusBadRequest, ErrorRoleNameTaken)
		}
	}
	if !includeDatabase {
		return nil
	}
	existing, err := runtime.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "organizationRole",
		Where: []storage.Where{
			{Field: "organizationId", Value: organizationID},
			{Field: "role", Value: roleName},
		},
	})
	if err != nil {
		return fmt.Errorf("organization: role: check name: %w", err)
	}
	if existing != nil {
		return organizationError(contract.StatusBadRequest, ErrorRoleNameTaken)
	}
	return nil
}

func (runtime *runtime) organizationRoleAdditionalInput(
	input storage.Record,
	partial bool,
) (storage.Record, error) {
	model, ok := runtime.schema.Models["organizationRole"]
	if !ok {
		return storage.Record{}, nil
	}
	result := storage.Record{}
	for name, attribute := range model.Fields {
		if _, base := organizationRoleBaseFields[name]; base || !attribute.IsInput() {
			continue
		}
		value, present := input[name]
		if !present {
			if !partial && attribute.IsRequired() && attribute.DefaultValue == nil {
				return nil, invalidOrganizationBody(fmt.Errorf("required organization role field %q is missing", name))
			}
			continue
		}
		normalized, err := normalizeTeamInputValue(attribute, value)
		if err != nil {
			return nil, invalidOrganizationBody(fmt.Errorf("organization role field %q: %w", name, err))
		}
		parsed, err := storage.ToRecordSchema(
			map[string]storage.FieldAttribute{name: attribute}, true,
		).Parse(storage.Record{name: normalized})
		if err != nil {
			return nil, invalidOrganizationBody(err)
		}
		if parsedValue, exists := parsed[name]; exists {
			result[name] = parsedValue
		}
	}
	return result, nil
}

func (runtime *runtime) publicOrganizationRole(record storage.Record) (storage.Record, error) {
	result := runtime.publicRecord("organizationRole", record)
	roleName, _ := recordString(record, "role")
	permission, err := decodeOrganizationRolePermission(record["permission"], roleName)
	if err != nil {
		return nil, err
	}
	result["permission"] = permission
	return result, nil
}

type createOrgRoleBody struct {
	OrganizationID   string          `json:"organizationId"`
	Role             string          `json:"role"`
	Permission       json.RawMessage `json:"permission"`
	AdditionalFields storage.Record  `json:"additionalFields"`
}

func (runtime *runtime) createOrgRoleEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body createOrgRoleBody
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	if _, exists := raw["role"]; !exists {
		return contract.Response{}, invalidOrganizationBody(nil)
	}
	if _, exists := raw["permission"]; !exists {
		return contract.Response{}, invalidOrganizationBody(nil)
	}
	if additionalRaw, exists := raw["additionalFields"]; exists && string(additionalRaw) == "null" {
		return contract.Response{}, invalidOrganizationBody(nil)
	}
	permission, err := decodeOrganizationPermission(body.Permission)
	if err != nil {
		return contract.Response{}, err
	}
	additional, err := runtime.organizationRoleAdditionalInput(body.AdditionalFields, false)
	if err != nil {
		return contract.Response{}, err
	}
	if runtime.options.AccessControl == nil {
		return contract.Response{}, organizationError(501, ErrorMissingAccessControl)
	}
	session, err := organizationRoleSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	organizationID := organizationRoleOrganizationID(body.OrganizationID, session)
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorRoleOrganizationRequired)
	}
	roleName := strings.ToLower(body.Role)
	if err := runtime.ensureRoleNameAvailable(ctx.GoContext(), organizationID, roleName, false); err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.findRoleActor(ctx.GoContext(), organizationID, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if err := runtime.requireRolePermission(
		ctx.GoContext(), organizationID, member, "create", ErrorRoleCreateForbidden,
	); err != nil {
		return contract.Response{}, err
	}
	maximum := 0
	hasMaximum := false
	if runtime.options.DynamicAccessControl.MaximumRolesPerOrganizationFunc != nil {
		hasMaximum = true
		maximum, err = runtime.options.DynamicAccessControl.MaximumRolesPerOrganizationFunc(
			ctx.GoContext(), organizationID,
		)
		if err != nil {
			return contract.Response{}, err
		}
	} else if configured := runtime.options.DynamicAccessControl.MaximumRolesPerOrganization; configured != nil {
		hasMaximum = true
		maximum = *configured
	}

	lock := runtime.organizationLock(organizationID)
	lock.Lock()
	defer lock.Unlock()
	if hasMaximum {
		count, countErr := runtime.adapter.Count(ctx.GoContext(), storage.CountParams{
			Model: "organizationRole",
			Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if countErr != nil {
			return contract.Response{}, fmt.Errorf("organization: create role: count: %w", countErr)
		}
		if count >= int64(maximum) {
			return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorTooManyRoles)
		}
	}
	if err := runtime.ensureValidRoleResources(permission); err != nil {
		return contract.Response{}, err
	}
	if err := runtime.ensureMemberCanGrantRolePermissions(
		ctx.GoContext(), organizationID, member, permission, "create",
	); err != nil {
		return contract.Response{}, err
	}
	if err := runtime.ensureRoleNameAvailable(ctx.GoContext(), organizationID, roleName, true); err != nil {
		return contract.Response{}, err
	}
	encodedPermission, err := json.Marshal(permission)
	if err != nil {
		return contract.Response{}, err
	}
	data := storage.Record{
		"organizationId": organizationID,
		"role":           roleName,
		"permission":     string(encodedPermission),
		"createdAt":      runtime.clock(),
	}
	mergeRecord(data, additional)
	created, err := runtime.adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "organizationRole", Data: data,
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: create role: %w", err)
	}
	public, err := runtime.publicOrganizationRole(created)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"success": true, "roleData": public, "statements": permission,
	})
}

type deleteOrgRoleBody struct {
	OrganizationID string `json:"organizationId"`
}

func (runtime *runtime) deleteOrgRoleEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body deleteOrgRoleBody
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	selector, err := organizationRoleSelectorFromRaw(raw)
	if err != nil {
		return contract.Response{}, err
	}
	session, err := organizationRoleSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	organizationID := organizationRoleOrganizationID(body.OrganizationID, session)
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.findRoleActor(ctx.GoContext(), organizationID, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if err := runtime.requireRolePermission(
		ctx.GoContext(), organizationID, member, "delete", ErrorRoleDeleteForbidden,
	); err != nil {
		return contract.Response{}, err
	}
	if selector.RoleName != "" {
		for _, predefined := range runtime.predefinedOrganizationRoleNames() {
			if selector.RoleName == predefined {
				return contract.Response{}, organizationError(
					contract.StatusBadRequest, ErrorCannotDeletePredefinedRole,
				)
			}
		}
	}

	lock := runtime.organizationLock(organizationID)
	lock.Lock()
	defer lock.Unlock()
	where := append([]storage.Where{{Field: "organizationId", Value: organizationID}}, selector.where()...)
	role, err := runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "organizationRole", Where: where,
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: delete role: find role: %w", err)
	}
	if role == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorRoleNotFound)
	}
	roleName, _ := recordString(role, "role")
	if _, err := decodeOrganizationRolePermission(role["permission"], roleName); err != nil {
		return contract.Response{}, err
	}
	members, err := findAllOrganizationRecords(
		ctx.GoContext(), runtime.adapter, "member",
		[]storage.Where{{Field: "organizationId", Value: organizationID}},
	)
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: delete role: list members: %w", err)
	}
	for _, candidate := range members {
		memberRoles, _ := recordString(candidate, "role")
		for _, assigned := range strings.Split(memberRoles, ",") {
			if strings.TrimSpace(assigned) == roleName {
				return contract.Response{}, organizationError(
					contract.StatusBadRequest, ErrorRoleAssignedToMembers,
				)
			}
		}
	}
	if err := runtime.adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "organizationRole", Where: where,
	}); err != nil {
		return contract.Response{}, fmt.Errorf("organization: delete role: %w", err)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"success": true})
}

func (runtime *runtime) listOrgRolesEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, err := organizationRoleSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	organizationID := organizationRoleOrganizationID(query.Get("organizationId"), session)
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.findRoleActor(ctx.GoContext(), organizationID, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if err := runtime.requireRolePermission(
		ctx.GoContext(), organizationID, member, "read", ErrorRoleListForbidden,
	); err != nil {
		return contract.Response{}, err
	}
	rows, err := findAllOrganizationRecords(
		ctx.GoContext(), runtime.adapter, "organizationRole",
		[]storage.Where{{Field: "organizationId", Value: organizationID}},
	)
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: list roles: %w", err)
	}
	roles := make([]storage.Record, 0, len(rows))
	for _, row := range rows {
		public, parseErr := runtime.publicOrganizationRole(row)
		if parseErr != nil {
			return contract.Response{}, parseErr
		}
		roles = append(roles, public)
	}
	return contract.JSONResponse(contract.StatusOK, roles)
}

func (runtime *runtime) getOrgRoleEndpoint(ctx *engine.Context) (contract.Response, error) {
	session, err := organizationRoleSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	raw := map[string]json.RawMessage{}
	if values, exists := query["roleName"]; exists && len(values) != 0 {
		encoded, _ := json.Marshal(values[0])
		raw["roleName"] = encoded
	}
	if values, exists := query["roleId"]; exists && len(values) != 0 {
		encoded, _ := json.Marshal(values[0])
		raw["roleId"] = encoded
	}
	selector, err := organizationRoleSelectorFromRaw(raw)
	if err != nil {
		return contract.Response{}, err
	}
	organizationID := organizationRoleOrganizationID(query.Get("organizationId"), session)
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.findRoleActor(ctx.GoContext(), organizationID, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if err := runtime.requireRolePermission(
		ctx.GoContext(), organizationID, member, "read", ErrorRoleReadForbidden,
	); err != nil {
		return contract.Response{}, err
	}
	where := append([]storage.Where{{Field: "organizationId", Value: organizationID}}, selector.where()...)
	role, err := runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "organizationRole", Where: where,
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: get role: %w", err)
	}
	if role == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorRoleNotFound)
	}
	public, err := runtime.publicOrganizationRole(role)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, public)
}

type updateOrgRoleBody struct {
	OrganizationID string          `json:"organizationId"`
	Data           json.RawMessage `json:"data"`
}

func (runtime *runtime) updateOrgRoleEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body updateOrgRoleBody
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	selector, err := organizationRoleSelectorFromRaw(raw)
	if err != nil {
		return contract.Response{}, err
	}
	var dataRaw map[string]json.RawMessage
	if len(body.Data) == 0 || string(body.Data) == "null" || json.Unmarshal(body.Data, &dataRaw) != nil || dataRaw == nil {
		return contract.Response{}, invalidOrganizationBody(nil)
	}
	var genericData storage.Record
	if err := json.Unmarshal(body.Data, &genericData); err != nil {
		return contract.Response{}, invalidOrganizationBody(err)
	}
	additional, err := runtime.organizationRoleAdditionalInput(genericData, true)
	if err != nil {
		return contract.Response{}, err
	}
	if runtime.options.AccessControl == nil {
		return contract.Response{}, organizationError(501, ErrorMissingAccessControl)
	}
	session, err := organizationRoleSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	organizationID := organizationRoleOrganizationID(body.OrganizationID, session)
	if organizationID == "" {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorNoActiveOrganization)
	}
	userID, _ := recordString(session.User, "id")
	member, err := runtime.findRoleActor(ctx.GoContext(), organizationID, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if err := runtime.requireRolePermission(
		ctx.GoContext(), organizationID, member, "update", ErrorRoleUpdateForbidden,
	); err != nil {
		return contract.Response{}, err
	}

	where := append([]storage.Where{{Field: "organizationId", Value: organizationID}}, selector.where()...)
	lock := runtime.organizationLock(organizationID)
	lock.Lock()
	defer lock.Unlock()
	role, err := runtime.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "organizationRole", Where: where,
	})
	if err != nil {
		return contract.Response{}, fmt.Errorf("organization: update role: find role: %w", err)
	}
	if role == nil {
		return contract.Response{}, organizationError(contract.StatusBadRequest, ErrorRoleNotFound)
	}
	roleName, _ := recordString(role, "role")
	if _, err := decodeOrganizationRolePermission(role["permission"], roleName); err != nil {
		return contract.Response{}, err
	}
	update := cloneRecord(additional)
	if update == nil {
		update = storage.Record{}
	}
	if permissionRaw, exists := dataRaw["permission"]; exists {
		permission, decodeErr := decodeOrganizationPermission(permissionRaw)
		if decodeErr != nil {
			return contract.Response{}, decodeErr
		}
		if err := runtime.ensureValidRoleResources(permission); err != nil {
			return contract.Response{}, err
		}
		if err := runtime.ensureMemberCanGrantRolePermissions(
			ctx.GoContext(), organizationID, member, permission, "update",
		); err != nil {
			return contract.Response{}, err
		}
		encoded, encodeErr := json.Marshal(permission)
		if encodeErr != nil {
			return contract.Response{}, encodeErr
		}
		update["permission"] = string(encoded)
	}
	if roleNameRaw, exists := dataRaw["roleName"]; exists {
		var newRoleName string
		if err := json.Unmarshal(roleNameRaw, &newRoleName); err != nil {
			return contract.Response{}, invalidOrganizationBody(err)
		}
		if newRoleName != "" {
			newRoleName = strings.ToLower(newRoleName)
			if err := runtime.ensureRoleNameAvailable(
				ctx.GoContext(), organizationID, newRoleName, true,
			); err != nil {
				return contract.Response{}, err
			}
			update["role"] = newRoleName
		}
	}
	if len(update) != 0 {
		if _, err := runtime.adapter.UpdateMany(ctx.GoContext(), storage.UpdateManyParams{
			Model: "organizationRole", Where: where, Update: update,
		}); err != nil {
			return contract.Response{}, fmt.Errorf("organization: update role: %w", err)
		}
	}
	result := cloneRecord(role)
	mergeRecord(result, update)
	public, err := runtime.publicOrganizationRole(result)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"success": true, "roleData": public,
	})
}

func dynamicAccessControlEndpoints(runtime *runtime) []engine.Endpoint {
	return []engine.Endpoint{
		{
			Name: "createOrgRole", Path: "/organization/create-role",
			Methods: []string{http.MethodPost}, OperationID: "createOrgRole",
			Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
			Handler: runtime.createOrgRoleEndpoint,
		},
		{
			Name: "deleteOrgRole", Path: "/organization/delete-role",
			Methods: []string{http.MethodPost}, OperationID: "deleteOrgRole",
			Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
			Handler: runtime.deleteOrgRoleEndpoint,
		},
		{
			Name: "listOrgRoles", Path: "/organization/list-roles",
			Methods: []string{http.MethodGet}, OperationID: "listOrgRoles",
			Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
			Handler: runtime.listOrgRolesEndpoint,
		},
		{
			Name: "getOrgRole", Path: "/organization/get-role",
			Methods: []string{http.MethodGet}, OperationID: "getOrgRole",
			Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
			Handler: runtime.getOrgRoleEndpoint,
		},
		{
			Name: "updateOrgRole", Path: "/organization/update-role",
			Methods: []string{http.MethodPost}, OperationID: "updateOrgRole",
			Use:     []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware},
			Handler: runtime.updateOrgRoleEndpoint,
		},
	}
}
