package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const listResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

var scimUserFilterPattern = regexp.MustCompile(`(?i)^\s*([^\s]+)\s+(eq|ne|co|sw|ew|pr)\s*(?:"([^"]*)"|([^\s]+))?\s*$`)

func (p *plugin) listUsers(ctx *engine.Context) (contract.Response, error) {
	provider, err := scimProviderFromContext(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("scim: runtime adapter is required")
	}
	query, err := ctx.Request().Query()
	if err != nil {
		err = scimError(http.StatusBadRequest, "Invalid SCIM filter", "invalidFilter")
		return contract.ResponseFromError(err), err
	}
	emailFilter, err := parseSCIMUserNameFilter(query.Get("filter"))
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	accounts, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "providerId", Value: provider.ProviderID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if len(accounts) == 0 {
		return scimEmptyUserList()
	}
	accountByUser := make(map[string]storage.Record, len(accounts))
	userIDs := make([]string, 0, len(accounts))
	for _, account := range accounts {
		userID := recordString(account, "userId")
		if userID == "" {
			continue
		}
		if _, exists := accountByUser[userID]; !exists {
			accountByUser[userID] = account
			userIDs = append(userIDs, userID)
		}
	}
	if provider.OrganizationID != "" {
		members, findErr := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
			Model: "member", Where: []storage.Where{
				{Field: "organizationId", Value: provider.OrganizationID},
				{Field: "userId", Value: userIDs, Operator: storage.OpIn},
			},
		})
		if findErr != nil {
			return contract.Response{}, findErr
		}
		userIDs = userIDs[:0]
		for _, member := range members {
			if userID := recordString(member, "userId"); userID != "" {
				userIDs = append(userIDs, userID)
			}
		}
	}
	if len(userIDs) == 0 {
		return scimEmptyUserList()
	}
	where := []storage.Where{{Field: "id", Value: userIDs, Operator: storage.OpIn}}
	if emailFilter != "" {
		where = append(where, storage.Where{Field: "email", Value: emailFilter})
	}
	users, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{Model: "user", Where: where})
	if err != nil {
		return contract.Response{}, err
	}
	resources := make([]map[string]any, 0, len(users))
	for _, user := range users {
		resources = append(resources, scimUserResource(ctx, user, accountByUser[recordString(user, "id")]))
	}
	return contract.JSONResponse(http.StatusOK, map[string]any{
		"schemas": []string{listResponseSchema}, "totalResults": len(resources),
		"startIndex": 1, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (p *plugin) getUser(ctx *engine.Context) (contract.Response, error) {
	provider, err := scimProviderFromContext(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	userID, _ := ctx.Param("userId")
	user, account, err := p.findScopedUser(ctx, provider, userID)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	return contract.JSONResponse(http.StatusOK, scimUserResource(ctx, user, account))
}

func (p *plugin) updateUser(ctx *engine.Context) (contract.Response, error) {
	provider, err := scimProviderFromContext(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	var body scimCreateUserBody
	if err = decodeSCIMUserBody(ctx, &body); err != nil {
		return contract.ResponseFromError(err), err
	}
	userID, _ := ctx.Param("userId")
	user, account, err := p.findScopedUser(ctx, provider, userID)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	adapter := p.adapter(ctx)
	email := strings.ToLower(primarySCIMEmail(body))
	name := scimFullName(email, body.Name)
	emailChanged := email != strings.ToLower(recordString(user, "email"))
	if emailChanged {
		if err = assertSCIMEmailAvailable(ctx.GoContext(), adapter, email, userID); err != nil {
			return contract.ResponseFromError(err), err
		}
	}
	userUpdate := storage.Record{"email": email, "name": name, "updatedAt": p.options.Runtime.Clock().UTC()}
	if emailChanged {
		userUpdate["emailVerified"] = false
	}
	if body.Active != nil {
		userUpdate["banned"] = !*body.Active
	}
	deactivating, err := resolveActivePatch(p.options.Runtime, userUpdate)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	if p.options.Runtime.UpdateUser != nil {
		user, err = p.options.Runtime.UpdateUser(ctx, userID, userUpdate)
	} else {
		user, err = adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}, Update: userUpdate,
		})
	}
	if err != nil {
		return contract.Response{}, err
	}
	accountID := body.ExternalID
	if accountID == "" {
		accountID = body.UserName
	}
	account, err = adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: recordString(account, "id")}},
		Update: storage.Record{"accountId": accountID, "updatedAt": p.options.Runtime.Clock().UTC()},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if deactivating {
		if p.options.Runtime.RevokeSessions == nil {
			return contract.Response{}, fmt.Errorf("scim: Runtime.RevokeSessions is required for deactivation")
		}
		if err = p.options.Runtime.RevokeSessions(ctx, userID); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(http.StatusOK, scimUserResource(ctx, user, account))
}

func (p *plugin) deleteUser(ctx *engine.Context) (contract.Response, error) {
	provider, err := scimProviderFromContext(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	userID, _ := ctx.Param("userId")
	_, account, err := p.findScopedUser(ctx, provider, userID)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	adapter := p.adapter(ctx)
	if provider.OrganizationID != "" {
		if !p.hasPlugin("organization") || p.options.Runtime.RemoveOrganizationMember == nil {
			err = scimError(http.StatusBadRequest, "Organization-scoped SCIM deprovisioning requires the organization plugin", "")
			return contract.ResponseFromError(err), err
		}
		accountID := recordString(account, "id")
		err = p.options.Runtime.RemoveOrganizationMember(
			ctx.GoContext(), provider.OrganizationID, userID,
			func(transactionContext context.Context, transaction storage.TransactionAdapter) error {
				return transaction.Delete(transactionContext, storage.DeleteParams{
					Model: "account", Where: []storage.Where{
						{Field: "id", Value: accountID},
						{Field: "userId", Value: userID},
						{Field: "providerId", Value: provider.ProviderID},
					},
				})
			},
		)
		if err != nil {
			return contract.Response{}, err
		}
		return contract.NewResponse(http.StatusNoContent, contract.Headers{}, nil), nil
	}
	accounts, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if len(accounts) > 1 {
		if err = adapter.Delete(ctx.GoContext(), storage.DeleteParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: recordString(account, "id")}},
		}); err != nil {
			return contract.Response{}, err
		}
		return contract.NewResponse(http.StatusNoContent, contract.Headers{}, nil), nil
	}
	if p.options.Runtime.DeleteUser != nil {
		if err = p.options.Runtime.DeleteUser(ctx, userID); err != nil {
			return contract.Response{}, err
		}
	} else {
		if p.options.Runtime.RevokeSessions != nil {
			if err = p.options.Runtime.RevokeSessions(ctx, userID); err != nil {
				return contract.Response{}, err
			}
		}
		if _, err = adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
			Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
		}); err != nil {
			return contract.Response{}, err
		}
		if err = adapter.Delete(ctx.GoContext(), storage.DeleteParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		}); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.NewResponse(http.StatusNoContent, contract.Headers{}, nil), nil
}

func (p *plugin) findScopedUser(ctx *engine.Context, provider Provider, userID string) (storage.Record, storage.Record, error) {
	adapter := p.adapter(ctx)
	if adapter == nil {
		return nil, nil, fmt.Errorf("scim: runtime adapter is required")
	}
	account, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{
			{Field: "userId", Value: userID}, {Field: "providerId", Value: provider.ProviderID},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	if account == nil {
		return nil, nil, scimError(http.StatusNotFound, "User not found", "")
	}
	if provider.OrganizationID != "" {
		member, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "member", Where: []storage.Where{
				{Field: "organizationId", Value: provider.OrganizationID}, {Field: "userId", Value: userID},
			},
		})
		if findErr != nil {
			return nil, nil, findErr
		}
		if member == nil {
			return nil, nil, scimError(http.StatusNotFound, "User not found", "")
		}
	}
	user, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, scimError(http.StatusNotFound, "User not found", "")
	}
	return user, account, nil
}

func (p *plugin) canLinkExistingUser(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	provider Provider,
	user storage.Record,
	email string,
) (bool, error) {
	policy := p.options.LinkExistingUsers
	if !policy.Enabled {
		return false, nil
	}
	if policy.RequireExistingOrgMembership {
		if provider.OrganizationID == "" {
			return false, nil
		}
		member, err := adapter.FindOne(ctx, storage.FindOneParams{
			Model: "member", Where: []storage.Where{
				{Field: "organizationId", Value: provider.OrganizationID},
				{Field: "userId", Value: recordString(user, "id")},
			},
		})
		if err != nil || member == nil {
			return false, err
		}
	}
	if len(policy.TrustedDomains) != 0 {
		parts := strings.Split(email, "@")
		if len(parts) < 2 {
			return false, nil
		}
		domain := strings.ToLower(parts[len(parts)-1])
		trusted := false
		for _, candidate := range policy.TrustedDomains {
			if strings.EqualFold(strings.TrimSpace(candidate), domain) {
				trusted = true
				break
			}
		}
		if !trusted {
			return false, nil
		}
	}
	if policy.ShouldLinkUser != nil {
		return policy.ShouldLinkUser(ctx, ExistingUserLinkInput{
			User: cloneSCIMRecord(user), Email: email, ProviderID: provider.ProviderID,
			OrganizationID: provider.OrganizationID,
		})
	}
	return true, nil
}

func scimProviderFromContext(ctx *engine.Context) (Provider, error) {
	if ctx != nil {
		if value, ok := ctx.Value(providerContextKey); ok {
			if provider, valid := value.(Provider); valid {
				return provider, nil
			}
		}
	}
	return Provider{}, scimError(http.StatusUnauthorized, "SCIM token is required", "")
}

func decodeSCIMUserBody(ctx *engine.Context, body *scimCreateUserBody) error {
	if ctx == nil || body == nil || len(ctx.Request().Body()) == 0 {
		return validationError("Invalid request body")
	}
	if err := json.Unmarshal(ctx.Request().Body(), body); err != nil || strings.TrimSpace(body.UserName) == "" {
		return validationError("Invalid request body")
	}
	return nil
}

func assertSCIMEmailAvailable(ctx context.Context, adapter storage.TransactionAdapter, email, userID string) error {
	existing, err := adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: strings.ToLower(email)}},
	})
	if err != nil {
		return err
	}
	if existing != nil && recordString(existing, "id") != userID {
		return scimError(http.StatusConflict, "Email already in use", "uniqueness")
	}
	return nil
}

func scimUserResource(ctx *engine.Context, user, account storage.Record) map[string]any {
	userID := recordString(user, "id")
	email := recordString(user, "email")
	name := recordString(user, "name")
	banned, _ := user["banned"].(bool)
	return map[string]any{
		"id": userID, "externalId": recordString(account, "accountId"),
		"meta": map[string]any{
			"resourceType": "User", "created": user["createdAt"], "lastModified": user["updatedAt"],
			"location": resourceLocation(ctx, userID),
		},
		"userName": email, "name": map[string]string{"formatted": name}, "displayName": name,
		"active": !banned, "emails": []map[string]any{{"primary": true, "value": email}},
		"schemas": []string{UserSchema},
	}
}

func scimEmptyUserList() (contract.Response, error) {
	return contract.JSONResponse(http.StatusOK, map[string]any{
		"schemas": []string{listResponseSchema}, "totalResults": 0,
		"startIndex": 1, "itemsPerPage": 0, "Resources": []any{},
	})
}

func parseSCIMUserNameFilter(filter string) (string, error) {
	if strings.TrimSpace(filter) == "" {
		return "", nil
	}
	match := scimUserFilterPattern.FindStringSubmatch(filter)
	if match == nil || (match[3] == "" && match[4] == "") {
		return "", scimError(http.StatusBadRequest, "Invalid filter expression", "invalidFilter")
	}
	operator := strings.ToLower(match[2])
	if operator != "eq" {
		return "", scimError(http.StatusBadRequest, fmt.Sprintf("The operator %q is not supported", operator), "invalidFilter")
	}
	if match[1] != "userName" {
		return "", scimError(http.StatusBadRequest, fmt.Sprintf("The attribute %q is not supported", match[1]), "invalidFilter")
	}
	value := match[3]
	if value == "" {
		value = match[4]
	}
	return strings.ToLower(value), nil
}
