package scim

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type patchMapping struct {
	resource string
	target   string
	mapValue func(storage.Record, Operation, PatchResources) (any, error)
}

var userPatchMappings = map[string]patchMapping{
	"/active": {
		resource: "user", target: "banned",
		mapValue: func(_ storage.Record, operation Operation, _ PatchResources) (any, error) {
			return operation.Value == false || operation.Value == "false", nil
		},
	},
	"/name/formatted": {resource: "user", target: "name", mapValue: identityPatchValue},
	"/name/givenName": {
		resource: "user", target: "name", mapValue: func(user storage.Record, operation Operation, resources PatchResources) (any, error) {
			currentName := patchCurrentName(user, resources)
			parts := strings.Split(currentName, " ")
			familyName := strings.TrimSpace(strings.Join(parts[1:], " "))
			givenName, ok := operation.Value.(string)
			if !ok {
				return nil, fmt.Errorf("scim: name.givenName must be a string")
			}
			return userFullName(recordString(user, "email"), givenName, familyName), nil
		},
	},
	"/name/familyName": {
		resource: "user", target: "name", mapValue: func(user storage.Record, operation Operation, resources PatchResources) (any, error) {
			currentName := patchCurrentName(user, resources)
			parts := strings.Split(currentName, " ")
			givenName := strings.TrimSpace(strings.Join(parts[:max(len(parts)-1, 0)], " "))
			if givenName == "" {
				givenName = strings.TrimSpace(currentName)
			}
			familyName, ok := operation.Value.(string)
			if !ok {
				return nil, fmt.Errorf("scim: name.familyName must be a string")
			}
			return userFullName(recordString(user, "email"), givenName, familyName), nil
		},
	},
	"/externalId": {resource: "account", target: "accountId", mapValue: identityPatchValue},
	"/userName": {
		resource: "user", target: "email", mapValue: func(_ storage.Record, operation Operation, _ PatchResources) (any, error) {
			value, ok := operation.Value.(string)
			if !ok {
				return nil, fmt.Errorf("scim: userName must be a string")
			}
			return strings.ToLower(value), nil
		},
	},
}

func identityPatchValue(_ storage.Record, operation Operation, _ PatchResources) (any, error) {
	return operation.Value, nil
}

// BuildUserPatch implements single-auth's SCIM user/account PatchOp mapping.
// Unknown paths and remove operations produce no update, matching 1.6.26.
func BuildUserPatch(user storage.Record, operations []Operation) (PatchResources, error) {
	resources := PatchResources{User: storage.Record{}, Account: storage.Record{}}
	for _, operation := range operations {
		op := strings.ToLower(operation.Op)
		if op != "add" && op != "replace" {
			continue
		}
		operation.Op = op
		if err := applyPatchValue(user, resources, operation.Value, operation, operation.Path); err != nil {
			return PatchResources{}, err
		}
	}
	return resources, nil
}

func applyPatchValue(
	user storage.Record,
	resources PatchResources,
	value any,
	operation Operation,
	path string,
) error {
	if object, ok := value.(map[string]any); ok {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			nestedPath := key
			if path != "" {
				nestedPath = path + "." + key
			}
			if err := applyPatchValue(user, resources, object[key], operation, nestedPath); err != nil {
				return err
			}
		}
		return nil
	}
	if path == "" {
		return nil
	}
	return applyMapping(user, resources, path, value, operation)
}

func applyMapping(
	user storage.Record,
	resources PatchResources,
	path string,
	value any,
	operation Operation,
) error {
	normalizedPath := normalizePatchPath(path)
	mapping, ok := userPatchMappings[normalizedPath]
	if !ok {
		return nil
	}
	operation.Path = normalizedPath
	operation.Value = value
	newValue, err := mapping.mapValue(user, operation, resources)
	if err != nil {
		return err
	}
	if operation.Op == "add" && mapping.resource == "user" {
		if current, exists := user[mapping.target]; exists && reflect.DeepEqual(current, newValue) {
			return nil
		}
	}
	if mapping.resource == "user" {
		resources.User[mapping.target] = newValue
	} else {
		resources.Account[mapping.target] = newValue
	}
	return nil
}

func normalizePatchPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	return "/" + strings.ReplaceAll(path, ".", "/")
}

func patchCurrentName(user storage.Record, resources PatchResources) string {
	if name, ok := resources.User["name"].(string); ok {
		return name
	}
	return recordString(user, "name")
}

func userFullName(email, givenName, familyName string) string {
	if givenName != "" && familyName != "" {
		return givenName + " " + familyName
	}
	if givenName != "" {
		return givenName
	}
	if familyName != "" {
		return familyName
	}
	return email
}

func recordString(record storage.Record, key string) string {
	value, _ := record[key].(string)
	return value
}

func patchUser(
	ctx *engine.Context,
	runtime Runtime,
	provider Provider,
	userID string,
	request PatchRequest,
) error {
	adapter := runtime.Adapter
	if runtime.AdapterForContext != nil {
		adapter = runtime.AdapterForContext(ctx.GoContext())
	}
	if adapter == nil {
		return fmt.Errorf("scim: runtime adapter is required")
	}
	account, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "account",
		Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: provider.ProviderID},
		},
	})
	if err != nil {
		return err
	}
	if account == nil {
		return scimError(contract.StatusNotFound, "User not found", "")
	}
	if provider.OrganizationID != "" {
		member, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "member",
			Where: []storage.Where{
				{Field: "organizationId", Value: provider.OrganizationID},
				{Field: "userId", Value: userID},
			},
		})
		if findErr != nil {
			return findErr
		}
		if member == nil {
			return scimError(contract.StatusNotFound, "User not found", "")
		}
	}
	user, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil {
		return err
	}
	if user == nil {
		return scimError(contract.StatusNotFound, "User not found", "")
	}
	resources, err := BuildUserPatch(user, request.Operations)
	if err != nil {
		return err
	}
	if len(resources.User) == 0 && len(resources.Account) == 0 {
		return scimError(contract.StatusBadRequest, "No valid fields to update", "")
	}
	if email, ok := resources.User["email"].(string); ok && email != recordString(user, "email") {
		existing, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "email", Value: strings.ToLower(email)}},
		})
		if findErr != nil {
			return findErr
		}
		if existing != nil && recordString(existing, "id") != userID {
			return scimError(contract.StatusConflict, "Email already in use", "uniqueness")
		}
		resources.User["emailVerified"] = false
	}
	deactivating, err := resolveActivePatch(runtime, resources.User)
	if err != nil {
		return err
	}
	now := runtime.Clock().UTC()
	if len(resources.User) > 0 {
		resources.User["updatedAt"] = now
		if runtime.UpdateUser != nil {
			if _, err = runtime.UpdateUser(ctx, userID, resources.User); err != nil {
				return err
			}
		} else if _, err = adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}, Update: resources.User,
		}); err != nil {
			return err
		}
	}
	if len(resources.Account) > 0 {
		resources.Account["updatedAt"] = now
		if _, err = adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: recordString(account, "id")}}, Update: resources.Account,
		}); err != nil {
			return err
		}
	}
	if deactivating {
		if runtime.RevokeSessions == nil {
			return fmt.Errorf("scim: Runtime.RevokeSessions is required for deactivation")
		}
		if err = runtime.RevokeSessions(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

func resolveActivePatch(runtime Runtime, userPatch storage.Record) (bool, error) {
	value, exists := userPatch["banned"]
	if !exists {
		return false, nil
	}
	deactivating, _ := value.(bool)
	hasAdmin := runtime.HasPlugin != nil && runtime.HasPlugin("admin")
	if !hasAdmin {
		if deactivating {
			return false, scimError(
				contract.StatusBadRequest,
				"Setting `active: false` requires the admin plugin, which provides the enforced disabled-user state",
				"",
			)
		}
		delete(userPatch, "banned")
		return false, nil
	}
	if deactivating {
		userPatch["banReason"] = "Deactivated via SCIM"
		return true, nil
	}
	userPatch["banReason"] = nil
	userPatch["banExpires"] = nil
	return false, nil
}
