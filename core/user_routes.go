package core

import (
	"encoding/json"
	"fmt"
	"reflect"
	"unicode/utf16"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) updateSession(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	fields, err := a.parseAdditionalInput("session", body)
	if err != nil {
		return contract.Response{}, err
	}
	if len(fields) == 0 {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "No fields to update",
		)
	}
	fields["updatedAt"] = a.options.Clock().UTC()
	token, _ := recordString(current.Session, "token")
	updated, err := a.updateStoredSession(ctx.GoContext(), token, fields)
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if updated == nil {
		a.expireSessionCookies(ctx)
		return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorFailedToGetSession)
	}
	a.setSessionCookies(ctx, updated, current.User, false)
	return jsonResponse(contract.StatusOK, map[string]any{
		"session": a.publicSession(updated),
	})
}

func (a *Auth) updateUser(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	if email, exists := body["email"]; exists && jsTruthy(email) {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorEmailCannotBeUpdated)
	}
	update := storage.Record{}
	if name, exists := body["name"]; exists {
		update["name"] = name
	}
	if image, exists := body["image"]; exists {
		update["image"] = image
	}
	additional, err := a.parseAdditionalInput("user", body)
	if err != nil {
		return contract.Response{}, err
	}
	for key, value := range additional {
		update[key] = value
	}
	if len(update) == 0 {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "No fields to update",
		)
	}
	userID, _ := recordString(current.User, "id")
	updated, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}, Update: update,
	})
	if err != nil {
		return contract.Response{}, baseError(
			contract.StatusInternalServerError, ErrorFailedToUpdateUser,
		).WithCause(err)
	}
	if updated == nil {
		updated = cloneStorageRecord(current.User)
		for key, value := range update {
			updated[key] = value
		}
	}
	if err := a.refreshSecondaryUser(ctx.GoContext(), updated); err != nil {
		return contract.Response{}, internalServerError(err)
	}
	a.setSessionCookies(ctx, current.Session, updated, false)
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) changePassword(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	newPassword, ok := requiredString(body, "newPassword")
	if !ok {
		return contract.Response{}, missingField("newPassword")
	}
	currentPassword, ok := requiredString(body, "currentPassword")
	if !ok {
		return contract.Response{}, missingField("currentPassword")
	}
	if err := a.validatePasswordLength(newPassword); err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(current.User, "id")
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	var credential storage.Record
	var existingHash string
	for _, account := range accounts {
		providerID, _ := recordString(account, "providerId")
		password, hasPassword := recordString(account, "password")
		if providerID == "credential" && hasPassword && password != "" {
			credential, existingHash = account, password
			break
		}
	}
	if credential == nil {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorCredentialAccountNotFound)
	}
	// upstream implementation computes the new hash before checking the old password.
	passwordHash, err := a.hashPassword(ctx, newPassword)
	if err != nil {
		return contract.Response{}, passwordHashError(err, nil)
	}
	if !a.options.EmailAndPassword.Password.Verify(existingHash, currentPassword) {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidPassword)
	}
	accountID, _ := recordString(credential, "id")
	if _, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model:  "account",
		Where:  []storage.Where{{Field: "id", Value: accountID}},
		Update: storage.Record{"password": passwordHash},
	}); err != nil {
		return contract.Response{}, internalServerError(err)
	}

	var token any
	revokeOthers, _ := optionalBool(body, "revokeOtherSessions")
	if revokeOthers != nil && *revokeOthers {
		if err := a.deleteStoredUserSessions(ctx.GoContext(), userID, false); err != nil {
			return contract.Response{}, internalServerError(err)
		}
		newSession, err := a.createSession(ctx, a.adapter, userID, false)
		if err != nil || newSession == nil {
			return contract.Response{}, baseError(
				contract.StatusInternalServerError, ErrorFailedToGetSession,
			).WithCause(err)
		}
		a.setSessionCookies(ctx, newSession, current.User, false)
		token, _ = recordString(newSession, "token")
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"token": token,
		"user":  a.publicUser(current.User),
	})
}

func (a *Auth) setPassword(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	newPassword, ok := requiredString(body, "newPassword")
	if !ok {
		return contract.Response{}, missingField("newPassword")
	}
	if err := a.validatePasswordLength(newPassword); err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(current.User, "id")
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	for _, account := range accounts {
		providerID, _ := recordString(account, "providerId")
		password, hasPassword := recordString(account, "password")
		if providerID == "credential" && hasPassword && password != "" {
			return contract.Response{}, baseError(contract.StatusBadRequest, ErrorPasswordAlreadySet)
		}
	}
	passwordHash, err := a.hashPassword(ctx, newPassword)
	if err != nil {
		return contract.Response{}, passwordHashError(err, nil)
	}
	id, generated, err := generateIdentifier(a.options, "account", 32)
	if err != nil {
		return contract.Response{}, err
	}
	now := a.options.Clock().UTC()
	account := storage.Record{
		"providerId": "credential",
		"accountId":  userID,
		"userId":     userID,
		"password":   passwordHash,
		"createdAt":  now,
		"updatedAt":  now,
	}
	if generated {
		account["id"] = id
	}
	if _, err := a.adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "account", Data: account, ForceAllowID: generated,
	}); err != nil {
		return contract.Response{}, internalServerError(err)
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) validatePasswordLength(password string) error {
	length := len(utf16.Encode([]rune(password)))
	if length < a.options.EmailAndPassword.MinPasswordLength {
		return baseError(contract.StatusBadRequest, ErrorPasswordTooShort)
	}
	if length > a.options.EmailAndPassword.MaxPasswordLength {
		return baseError(contract.StatusBadRequest, ErrorPasswordTooLong)
	}
	return nil
}

func (a *Auth) parseAdditionalInput(modelName string, body map[string]any) (storage.Record, error) {
	result := storage.Record{}
	table, ok := a.options.Schema.Models[modelName]
	if !ok {
		return result, nil
	}
	for key, attribute := range table.Fields {
		if isCoreInputField(modelName, key) {
			continue
		}
		value, exists := body[key]
		if !exists {
			continue
		}
		if !attribute.IsInput() {
			if jsTruthy(value) {
				return nil, contract.NewAPIError(
					contract.StatusBadRequest,
					string(ErrorFieldNotAllowed),
					fmt.Sprintf("%s is not allowed to be set", key),
				)
			}
			continue
		}
		result[key] = value
	}
	return result, nil
}

func isCoreInputField(modelName, field string) bool {
	switch modelName {
	case "user":
		return isCoreUserField(field)
	case "session":
		switch field {
		case "id", "userId", "token", "expiresAt", "ipAddress", "userAgent", "createdAt", "updatedAt":
			return true
		}
	}
	return false
}

func jsTruthy(value any) bool {
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed != ""
	case json.Number:
		value, err := typed.Float64()
		return err != nil || value != 0
	case float64:
		return typed != 0
	case float32:
		return typed != 0
	case int:
		return typed != 0
	case int8:
		return typed != 0
	case int16:
		return typed != 0
	case int32:
		return typed != 0
	case int64:
		return typed != 0
	case uint:
		return typed != 0
	case uint8:
		return typed != 0
	case uint16:
		return typed != 0
	case uint32:
		return typed != 0
	case uint64:
		return typed != 0
	default:
		return true
	}
}

func cloneStorageRecord(record storage.Record) storage.Record {
	clone := make(storage.Record, len(record))
	for key, value := range record {
		if value == nil {
			clone[key] = nil
			continue
		}
		kind := reflect.TypeOf(value).Kind()
		if kind == reflect.Map || kind == reflect.Slice || kind == reflect.Array {
			encoded, err := json.Marshal(value)
			if err == nil {
				var copied any
				if json.Unmarshal(encoded, &copied) == nil {
					clone[key] = copied
					continue
				}
			}
		}
		clone[key] = value
	}
	return clone
}
