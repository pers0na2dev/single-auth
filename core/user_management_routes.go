package core

import (
	"context"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) deleteUser(ctx *engine.Context) (contract.Response, error) {
	if !a.options.User.DeleteUser.Enabled {
		return contract.Response{}, contract.NewAPIError(contract.StatusNotFound, "NOT_FOUND", "Not Found")
	}
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	password, _ := optionalString(body, "password")
	if password != nil && *password != "" {
		if err := a.checkCurrentPassword(ctx, current.User, *password, true); err != nil {
			return contract.Response{}, err
		}
	}
	if token, exists := optionalString(body, "token"); exists && token != nil && *token != "" {
		if err := a.consumeDeleteUserToken(ctx, current, *token); err != nil {
			return contract.Response{}, err
		}
		return jsonResponse(contract.StatusOK, map[string]any{
			"success": true, "message": "User deleted",
		})
	}
	settings := a.options.User.DeleteUser
	if settings.SendDeleteAccountVerification != nil {
		token, err := randomStringFromAlphabet(a.options.Random, 32, "0123456789abcdefghijklmnopqrstuvwxyz")
		if err != nil {
			return contract.Response{}, err
		}
		userID, _ := recordString(current.User, "id")
		if _, err := a.createVerification(
			ctx,
			"delete-account-"+token,
			userID,
			a.options.Clock().Add(settings.DeleteTokenExpiresIn),
		); err != nil {
			return contract.Response{}, internalServerError(err)
		}
		callbackURL := "/"
		if callback, exists := optionalString(body, "callbackURL"); exists && callback != nil {
			callbackURL = *callback
		}
		deletionURL := a.baseURLForRequest(ctx.Request()) + "/delete-user/callback?token=" + token +
			"&callbackURL=" + percentEncodeURIComponent(callbackURL)
		message := DeleteAccountMessage{
			User: userFromRecord(current.User), URL: deletionURL, Token: token,
		}
		if err := a.runBackground(ctx.GoContext(), func(background context.Context) error {
			return settings.SendDeleteAccountVerification(background, message)
		}); err != nil {
			return contract.Response{}, err
		}
		return jsonResponse(contract.StatusOK, map[string]any{
			"success": true, "message": "Verification email sent",
		})
	}
	if password == nil || *password == "" {
		freshAge := defaultSessionFreshAge
		if a.options.Session.FreshAge != nil {
			freshAge = *a.options.Session.FreshAge
		}
		if freshAge != 0 {
			createdAt, ok := recordTime(current.Session, "createdAt")
			if !ok || a.options.Clock().Sub(createdAt) >= freshAge {
				return contract.Response{}, baseError(contract.StatusBadRequest, ErrorSessionExpired)
			}
		}
	}
	if err := a.deleteUserRecords(ctx, current); err != nil {
		return contract.Response{}, err
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"success": true, "message": "User deleted",
	})
}

func (a *Auth) deleteUserCallback(ctx *engine.Context) (contract.Response, error) {
	if !a.shouldSkipOrigin(ctx) {
		if err := a.validateRedirectFields(ctx.Request()); err != nil {
			return contract.Response{}, err
		}
	}
	if !a.options.User.DeleteUser.Enabled {
		return contract.Response{}, contract.NewAPIError(contract.StatusNotFound, "NOT_FOUND", "Not found")
	}
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		if apiError, ok := contract.AsAPIError(err); ok && apiError.Code == "UNAUTHORIZED" {
			return contract.Response{}, baseError(contract.StatusNotFound, ErrorFailedToGetUserInfo)
		}
		return contract.Response{}, err
	}
	query, _ := ctx.Request().Query()
	token := query.Get("token")
	if err := a.consumeDeleteUserToken(ctx, current, token); err != nil {
		return contract.Response{}, err
	}
	if callbackURL := query.Get("callbackURL"); callbackURL != "" {
		return redirectResponse(callbackURL), nil
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"success": true, "message": "User deleted",
	})
}

func (a *Auth) consumeDeleteUserToken(
	ctx *engine.Context,
	current *authenticatedSession,
	token string,
) error {
	verification, err := a.consumeVerification(ctx, "delete-account-"+token)
	if err != nil {
		return internalServerError(err)
	}
	userID, _ := recordString(current.User, "id")
	ownerID, _ := recordString(verification, "value")
	if verification == nil || ownerID != userID {
		return baseError(contract.StatusNotFound, ErrorInvalidToken)
	}
	return a.deleteUserRecords(ctx, current)
}

func (a *Auth) deleteUserRecords(ctx *engine.Context, current *authenticatedSession) error {
	settings := a.options.User.DeleteUser
	user := userFromRecord(current.User)
	if settings.BeforeDelete != nil {
		if err := settings.BeforeDelete(ctx.GoContext(), user); err != nil {
			return err
		}
	}
	userID, _ := recordString(current.User, "id")
	if err := a.deleteStoredUserSessions(ctx.GoContext(), userID, true); err != nil {
		return internalServerError(err)
	}
	if _, err := a.adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	}); err != nil {
		return internalServerError(err)
	}
	if err := a.adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	}); err != nil {
		return internalServerError(err)
	}
	a.expireSessionCookies(ctx)
	if settings.AfterDelete != nil {
		if err := settings.AfterDelete(ctx.GoContext(), user); err != nil {
			return err
		}
	}
	return nil
}

func (a *Auth) changeEmail(ctx *engine.Context) (contract.Response, error) {
	settings := a.options.User.ChangeEmail
	if !settings.Enabled {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorChangeEmailDisabled)
	}
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	newEmail, ok := requiredString(body, "newEmail")
	if !ok || !validEmail(newEmail) {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidEmail)
	}
	newEmail = strings.ToLower(newEmail)
	currentEmail := recordText(current.User, "email")
	if newEmail == currentEmail {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Email is the same")
	}
	callbackURL := "/"
	if callback, exists := optionalString(body, "callbackURL"); exists && callback != nil {
		callbackURL = *callback
	}
	verified, _ := recordBool(current.User, "emailVerified")
	canUpdateWithoutVerification := !verified && settings.UpdateEmailWithoutVerification
	verificationSender := a.options.EmailVerification.SendVerificationEmail
	confirmationSender := settings.SendChangeEmailConfirmation
	canSendConfirmation := verificationSender != nil && verified && confirmationSender != nil
	if !canUpdateWithoutVerification && !canSendConfirmation && verificationSender == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "BAD_REQUEST", "Verification email isn't enabled",
		)
	}
	existing, err := a.findUserByEmail(ctx.GoContext(), a.adapter, newEmail)
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if existing != nil {
		_, _ = a.createEmailToken(currentEmail, newEmail, "", a.options.EmailVerification.ExpiresIn)
		return jsonResponse(contract.StatusOK, map[string]any{"status": true})
	}
	if canUpdateWithoutVerification {
		updated, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model:  "user",
			Where:  []storage.Where{{Field: "email", Value: currentEmail, Mode: storage.Insensitive}},
			Update: storage.Record{"email": newEmail},
		})
		if err != nil {
			return contract.Response{}, internalServerError(err)
		}
		if err := a.refreshSecondaryUser(ctx.GoContext(), updated); err != nil {
			return contract.Response{}, internalServerError(err)
		}
		a.setSessionCookies(ctx, current.Session, updated, false)
		if verificationSender != nil {
			if err := a.sendEmailChangeVerification(ctx, updated, newEmail, "", callbackURL); err != nil {
				return contract.Response{}, err
			}
		}
		return jsonResponse(contract.StatusOK, map[string]any{"status": true})
	}
	if canSendConfirmation {
		token, err := a.createEmailToken(
			currentEmail, newEmail, "change-email-confirmation", a.options.EmailVerification.ExpiresIn,
		)
		if err != nil {
			return contract.Response{}, err
		}
		verificationURL := a.emailChangeURL(ctx, token, callbackURL)
		message := ChangeEmailConfirmationMessage{
			User: userFromRecord(current.User), NewEmail: newEmail, URL: verificationURL, Token: token,
		}
		if err := a.runBackground(ctx.GoContext(), func(background context.Context) error {
			return confirmationSender(background, message)
		}); err != nil {
			return contract.Response{}, err
		}
		return jsonResponse(contract.StatusOK, map[string]any{"status": true})
	}
	if err := a.sendEmailChangeVerification(
		ctx, current.User, newEmail, "change-email-verification", callbackURL,
	); err != nil {
		return contract.Response{}, err
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) sendEmailChangeVerification(
	ctx *engine.Context,
	user storage.Record,
	newEmail, requestType, callbackURL string,
) error {
	tokenEmail := recordText(user, "email")
	updateTo := newEmail
	if requestType == "" {
		tokenEmail, updateTo = newEmail, ""
	}
	token, err := a.createEmailToken(
		tokenEmail, updateTo, requestType, a.options.EmailVerification.ExpiresIn,
	)
	if err != nil {
		return err
	}
	copyUser := cloneStorageRecord(user)
	copyUser["email"] = newEmail
	message := EmailVerificationMessage{
		User: userFromRecord(copyUser), URL: a.emailChangeURL(ctx, token, callbackURL), Token: token,
	}
	sender := a.options.EmailVerification.SendVerificationEmail
	return a.runBackground(ctx.GoContext(), func(background context.Context) error {
		return sender(background, message)
	})
}

func (a *Auth) emailChangeURL(ctx *engine.Context, token, callbackURL string) string {
	return a.baseURLForRequest(ctx.Request()) + "/verify-email?token=" +
		percentEncodeURIComponent(token) + "&callbackURL=" + percentEncodeURIComponent(defaultCallback(callbackURL))
}

func (a *Auth) checkCurrentPassword(
	ctx *engine.Context,
	user storage.Record,
	password string,
	credentialError bool,
) error {
	userID, _ := recordString(user, "id")
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return internalServerError(err)
	}
	for _, account := range accounts {
		providerID, _ := recordString(account, "providerId")
		hash, hasPassword := recordString(account, "password")
		if providerID != "credential" || !hasPassword || hash == "" {
			continue
		}
		if !a.options.EmailAndPassword.Password.Verify(hash, password) {
			return baseError(contract.StatusBadRequest, ErrorInvalidPassword)
		}
		return nil
	}
	if credentialError {
		return baseError(contract.StatusBadRequest, ErrorCredentialAccountNotFound)
	}
	return baseError(contract.StatusBadRequest, ErrorInvalidPassword)
}
