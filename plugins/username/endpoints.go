package username

import (
	"context"
	"errors"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (plugin *compiledPlugin) signInUsername(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	username, err := requiredString(body, "username")
	if err != nil {
		return contract.Response{}, err
	}
	password, err := requiredString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	rememberMe, err := optionalBool(body, "rememberMe")
	if err != nil {
		return contract.Response{}, err
	}
	callbackURL, err := optionalString(body, "callbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	if callbackURL != nil && *callbackURL != "" && plugin.options.Runtime.ValidateRedirect != nil {
		if err := plugin.options.Runtime.ValidateRedirect(ctx, *callbackURL, "callbackURL"); err != nil {
			return contract.Response{}, err
		}
	}
	if username == "" || password == "" {
		plugin.warn("Username or password not found")
		return contract.Response{}, usernameError(contract.StatusUnauthorized, CodeInvalidUsernameOrPassword)
	}

	// This deliberately mirrors single-auth 1.6.26's sign-in-specific order:
	// the pre-normalization option normalizes before endpoint validation.
	usernameToValidate := username
	if plugin.options.ValidationOrder.Username == PreNormalization {
		usernameToValidate = plugin.usernameNormal(username)
	}
	code, err := plugin.validateUsernameRepresentation(usernameToValidate)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if code != "" {
		switch code {
		case CodeUsernameTooShort:
			plugin.warn("Username too short")
		case CodeUsernameTooLong:
			plugin.warn("Username too long")
		}
		return contract.Response{}, usernameError(422, code)
	}

	user, err := plugin.findUserByUsername(ctx.GoContext(), plugin.usernameNormal(usernameToValidate))
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		// Equalize the expensive password path so the endpoint does not disclose
		// which usernames exist through timing.
		if _, hashErr := plugin.options.Runtime.HashPasswordContext(ctx, password); hashErr != nil {
			return contract.Response{}, internalError(hashErr)
		}
		plugin.warn("User not found")
		return contract.Response{}, usernameError(contract.StatusUnauthorized, CodeInvalidUsernameOrPassword)
	}

	userID, ok := recordString(user, "id")
	if !ok || userID == "" {
		return contract.Response{}, internalError(errors.New("username: user id is invalid"))
	}
	account, err := plugin.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "account",
		Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential"},
		},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if account == nil {
		return contract.Response{}, usernameError(contract.StatusUnauthorized, CodeInvalidUsernameOrPassword)
	}
	currentPassword, ok := recordString(account, "password")
	if !ok || currentPassword == "" {
		plugin.warn("Password not found")
		return contract.Response{}, usernameError(contract.StatusUnauthorized, CodeInvalidUsernameOrPassword)
	}
	if !plugin.options.Runtime.VerifyPassword(currentPassword, password) {
		plugin.warn("Invalid password")
		return contract.Response{}, usernameError(contract.StatusUnauthorized, CodeInvalidUsernameOrPassword)
	}

	verified, _ := recordBool(user, "emailVerified")
	if plugin.options.Runtime.RequireEmailVerification && !verified {
		if plugin.options.Runtime.SendVerificationEmail == nil {
			return contract.Response{}, usernameError(contract.StatusForbidden, CodeEmailNotVerified)
		}
		if plugin.options.Runtime.SendOnSignIn {
			if err := plugin.sendVerification(ctx, user, callbackURL); err != nil {
				return contract.Response{}, internalError(err)
			}
		}
		return contract.Response{}, usernameError(contract.StatusForbidden, CodeEmailNotVerified)
	}

	dontRemember := rememberMe != nil && !*rememberMe
	state, err := plugin.options.Runtime.IssueSession(ctx, userID, dontRemember)
	if err != nil || state == nil || state.Session == nil {
		return contract.Response{}, failedToCreateSession(err)
	}
	token, ok := recordString(state.Session, "token")
	if !ok || token == "" {
		return contract.Response{}, failedToCreateSession(errors.New("username: session token is invalid"))
	}
	responseUser := state.User
	if responseUser == nil {
		responseUser = user
	}
	responseBody := map[string]any{
		"redirect": callbackURL != nil && *callbackURL != "",
		"token":    token,
		"user":     plugin.options.Runtime.SerializeUser(cloneRecord(responseUser)),
	}
	if callbackURL != nil {
		responseBody["url"] = *callbackURL
		if *callbackURL != "" {
			ctx.SetResponseHeader("Location", *callbackURL)
		}
	}
	return contract.JSONResponse(contract.StatusOK, responseBody)
}

func (plugin *compiledPlugin) isUsernameAvailable(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	username, err := requiredString(body, "username")
	if err != nil {
		return contract.Response{}, err
	}
	if username == "" {
		return contract.Response{}, usernameError(422, CodeInvalidUsername)
	}
	code, err := plugin.validateUsernameRepresentation(username)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if code != "" {
		return contract.Response{}, usernameError(422, code)
	}
	user, err := plugin.findUserByUsername(ctx.GoContext(), plugin.usernameNormal(username))
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"available": user == nil})
}

func (plugin *compiledPlugin) sendVerification(
	ctx *engine.Context,
	user storage.Record,
	callbackURL *string,
) error {
	email, _ := recordString(user, "email")
	token, err := baCrypto.SignJWTAt(
		map[string]any{"email": strings.ToLower(email)},
		plugin.options.Runtime.Secret,
		plugin.options.Runtime.VerificationExpiresIn,
		plugin.options.Runtime.Clock(),
	)
	if err != nil {
		return err
	}
	if plugin.options.Runtime.ResolveBaseURL == nil {
		return errors.New("username: Runtime.ResolveBaseURL is required for email verification")
	}
	baseURL, err := plugin.options.Runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return err
	}
	callback := "/"
	if callbackURL != nil && *callbackURL != "" {
		callback = *callbackURL
	}
	message := VerificationMessage{
		User:  modelUserFromRecord(user),
		URL:   strings.TrimSuffix(baseURL, "/") + "/verify-email?token=" + token + "&callbackURL=" + encodeURIComponent(callback),
		Token: token,
	}
	return plugin.options.Runtime.RunBackground(ctx.GoContext(), func(backgroundContext context.Context) error {
		return plugin.options.Runtime.SendVerificationEmail(backgroundContext, message)
	})
}

func (plugin *compiledPlugin) warn(message string) {
	if plugin.options.Runtime.Logger != nil {
		plugin.options.Runtime.Logger.Warn(message)
	}
}
