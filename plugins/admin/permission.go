package admin

import (
	"sort"

	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (p *plugin) userHasPermission(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	rawPermissions, exists := body["permissions"]
	if !exists || rawPermissions == nil {
		return contract.Response{}, baseError(contract.StatusBadRequest, "BAD_REQUEST", "invalid permission check. no permission(s) were passed.")
	}
	permissions, err := decodePermissions(rawPermissions)
	if err != nil {
		return contract.Response{}, err
	}

	var session *SessionState
	if !ctx.IsDirect() || requestHasCallerHeaders(ctx) {
		if p.options.Runtime.ResolveSession == nil {
			return contract.Response{}, internalError(nil)
		}
		session, err = p.options.Runtime.ResolveSession(ctx, true)
		if err != nil {
			return contract.Response{}, err
		}
		if session == nil {
			return contract.Response{}, baseError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		}
	}

	userID := ""
	if _, exists := body["userId"]; exists {
		userID, err = requiredCoercedString(body, "userId")
		if err != nil {
			return contract.Response{}, err
		}
	}
	role, _ := body["role"].(string)
	if session != nil {
		userID, _ = recordString(session.User, "id")
		role, _ = recordString(session.User, "role")
	} else if role == "" && userID == "" {
		return contract.Response{}, baseError(contract.StatusBadRequest, "BAD_REQUEST", "user id or role is required")
	} else if role == "" {
		user, findErr := p.findUser(ctx.GoContext(), userID)
		if findErr != nil {
			return contract.Response{}, preserveRuntimeError(findErr)
		}
		if user == nil {
			return contract.Response{}, baseError(contract.StatusBadRequest, "BAD_REQUEST", "user not found")
		}
		userID, _ = recordString(user, "id")
		role, _ = recordString(user, "role")
	}
	success := hasPermission(userID, role, p.options, permissions)
	return jsonSuccess(map[string]any{"error": nil, "success": success})
}

func decodePermissions(value any) (authorization.AuthorizeRequest, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, validationError("permissions must be an object")
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make(authorization.AuthorizeRequest, 0, len(keys))
	for _, resource := range keys {
		raw := object[resource]
		items, ok := raw.([]any)
		if !ok {
			if strings, typed := raw.([]string); typed {
				result = append(result, authorization.ResourceRequest{Resource: resource, Actions: append([]string(nil), strings...)})
				continue
			}
			return nil, validationError("permission actions must be an array")
		}
		actions := make([]string, len(items))
		for index, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil, validationError("permission actions must be strings")
			}
			actions[index] = text
		}
		result = append(result, authorization.ResourceRequest{Resource: resource, Actions: actions})
	}
	return result, nil
}
