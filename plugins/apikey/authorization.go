package apikey

import (
	"context"
	"strings"

	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func (service *Service) authorizeOrganization(
	ctx context.Context,
	userID string,
	organizationID string,
	action PermissionAction,
) error {
	if service.hasPlugin == nil || !service.hasPlugin("organization") {
		return apiError(contract.StatusInternalServerError, ErrorOrganizationPluginRequired)
	}
	member, err := service.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member",
		Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return err
	}
	if member == nil {
		return apiError(contract.StatusForbidden, ErrorUserNotMemberOfOrganization)
	}
	roleValue, _ := recordString(member, "role")
	creatorRole := service.organization.CreatorRole
	if creatorRole == "" {
		creatorRole = "owner"
	}
	for _, roleName := range strings.Split(roleValue, ",") {
		roleName = strings.TrimSpace(roleName)
		if roleName == creatorRole {
			return nil
		}
		statements, exists := service.organization.Roles[roleName]
		if !exists {
			continue
		}
		role := authorization.NewRole(statements)
		result, authorizeErr := role.Authorize(authorization.AuthorizeRequest{{
			Resource: "apiKey", Actions: []string{string(action)},
		}})
		if authorizeErr == nil && result.Success {
			return nil
		}
	}
	return apiError(contract.StatusForbidden, ErrorInsufficientAPIKeyPermissions)
}
