package organization

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// RequireOrgRole builds endpoint-local middleware equivalent to single-auth's
// requireOrgRole. The Plugin must also be installed on the Auth runtime that
// owns the endpoint.
func (plugin *Plugin) RequireOrgRole(options RequireOrgRoleOptions) (engine.EndpointMiddlewareFunc, error) {
	if plugin == nil {
		return nil, errors.New("organization: plugin is nil")
	}
	if strings.TrimSpace(options.OrgIDParam) == "" {
		return nil, errors.New("organization: org ID parameter must not be empty")
	}
	if options.OrgIDSource != OrgIDSourceBody && options.OrgIDSource != OrgIDSourceQuery {
		return nil, errors.New("organization: org ID source must be body or query")
	}
	orgIDParam := options.OrgIDParam
	orgIDSource := options.OrgIDSource
	allowedRoles := append([]string(nil), options.AllowedRoles...)

	return func(ctx *engine.Context) (engine.EndpointMiddlewareResult, error) {
		session, ok := singleauth.SessionFromEndpointContext(ctx)
		if !ok {
			return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
				contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized",
			)
		}
		userID, _ := recordString(session.User, "id")
		if userID == "" {
			return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
				contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized",
			)
		}

		plugin.mu.RLock()
		implementation := plugin.runtime
		plugin.mu.RUnlock()
		if implementation == nil || implementation.hasPlugin == nil || !implementation.hasPlugin("organization") {
			return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
				contract.StatusBadRequest,
				"BAD_REQUEST",
				"Organization plugin is required for org role authorization",
			)
		}

		organizationID, err := organizationIDFromRequest(ctx, orgIDSource, orgIDParam)
		if err != nil {
			return engine.EndpointMiddlewareResult{}, err
		}
		if organizationID == "" {
			return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
				contract.StatusBadRequest,
				"BAD_REQUEST",
				"Missing required parameter: "+orgIDParam,
			)
		}

		member, err := implementation.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "member",
			Where: []storage.Where{
				{Field: "userId", Value: userID},
				{Field: "organizationId", Value: organizationID},
			},
		})
		if err != nil {
			return engine.EndpointMiddlewareResult{}, fmt.Errorf("organization: require org role: find member: %w", err)
		}
		if member == nil {
			return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
				contract.StatusForbidden,
				"FORBIDDEN",
				"Not a member of this organization",
			)
		}
		rawRole, _ := recordString(member, "role")
		if len(allowedRoles) > 0 && !hasAllowedRole(rawRole, allowedRoles) {
			return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
				contract.StatusForbidden,
				"FORBIDDEN",
				"Insufficient role for this operation",
			)
		}

		return engine.EndpointMiddlewareResult{Values: map[string]any{
			verifiedMemberContextKey: cloneRecord(member),
		}}, nil
	}, nil
}

func organizationIDFromRequest(ctx *engine.Context, source OrgIDSource, parameter string) (string, error) {
	if source == OrgIDSourceQuery {
		query, err := ctx.Request().Query()
		if err != nil {
			return "", contract.NewAPIError(
				contract.StatusBadRequest, "BAD_REQUEST", "Invalid query parameters",
			).WithCause(err)
		}
		return query.Get(parameter), nil
	}

	var body map[string]any
	if len(strings.TrimSpace(string(ctx.Request().Body()))) == 0 {
		return "", nil
	}
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return "", contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "Invalid request body",
		).WithCause(err)
	}
	value, _ := body[parameter].(string)
	return value, nil
}

func hasAllowedRole(rawRole string, allowedRoles []string) bool {
	for _, memberRole := range strings.Split(rawRole, ",") {
		memberRole = strings.TrimSpace(memberRole)
		if memberRole == "" {
			continue
		}
		for _, allowedRole := range allowedRoles {
			if memberRole == allowedRole {
				return true
			}
		}
	}
	return false
}
