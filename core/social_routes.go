package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

type oauthUserResult struct {
	user       storage.Record
	session    storage.Record
	isRegister bool
	error      string
}

func (a *Auth) socialProvider(id string) *providers.Provider {
	provider := a.options.SocialProviders[id]
	if provider == nil || provider.ID == "" {
		return nil
	}
	return provider
}

func (a *Auth) signInSocial(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	if err := validateSocialBody(body, true); err != nil {
		return contract.Response{}, err
	}
	providerID, ok := requiredString(body, "provider")
	if !ok || providerID == "" {
		return contract.Response{}, missingField("provider")
	}
	provider := a.socialProvider(providerID)
	if provider == nil {
		return contract.Response{}, baseError(contract.StatusNotFound, ErrorProviderNotFound)
	}

	if rawIDToken, exists := body["idToken"]; exists && rawIDToken != nil {
		idToken, parseErr := requireStringMap(rawIDToken, "idToken")
		if parseErr != nil {
			return contract.Response{}, validationError(parseErr.Error())
		}
		token, ok := requiredString(idToken, "token")
		if !ok || token == "" {
			return contract.Response{}, missingField("idToken.token")
		}
		if !provider.Metadata.SupportsIDToken && provider.Options.VerifyIDToken == nil {
			return contract.Response{}, baseError(contract.StatusNotFound, ErrorIDTokenNotSupported)
		}
		nonce := ""
		if value, exists := optionalString(idToken, "nonce"); exists && value != nil {
			nonce = *value
		}
		valid, verifyErr := provider.VerifyIDToken(ctx.GoContext(), token, nonce)
		if verifyErr != nil || !valid {
			return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorInvalidToken)
		}
		tokens := oauth2.Tokens{IDToken: token}
		if value, exists := optionalString(idToken, "accessToken"); exists && value != nil {
			tokens.AccessToken = *value
		}
		if value, exists := optionalString(idToken, "refreshToken"); exists && value != nil {
			tokens.RefreshToken = *value
		}
		var authorizationUser []providers.AuthorizationUser
		if rawUser, exists := idToken["user"]; exists && rawUser != nil {
			userObject, objectErr := requireStringMap(rawUser, "idToken.user")
			if objectErr != nil {
				return contract.Response{}, validationError(objectErr.Error())
			}
			authorizationUser = append(authorizationUser, parseAuthorizationUser(userObject))
		}
		info, infoErr := provider.GetUserInfo(ctx.GoContext(), tokens, authorizationUser...)
		if infoErr != nil || info == nil || info.User.ID == "" {
			return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorFailedToGetUserInfo)
		}
		if info.User.Email == nil || *info.User.Email == "" {
			return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorUserEmailNotFound)
		}
		requestSignUp := false
		if value, exists := optionalBool(body, "requestSignUp"); exists && value != nil {
			requestSignUp = *value
		}
		disableSignUp := (provider.Options.DisableImplicitSignUp && !requestSignUp) || provider.Options.DisableSignUp
		accountTokens := oauth2.Tokens{AccessToken: tokens.AccessToken}
		verificationCallbackURL := optionalBodyString(body, "callbackURL")
		result, handleErr := a.handleOAuthUserInfo(ctx, provider, info.User, accountTokens, disableSignUp, verificationCallbackURL)
		if handleErr != nil {
			return contract.Response{}, handleErr
		}
		if result.error != "" {
			return contract.Response{}, contract.NewAPIError(
				contract.StatusUnauthorized, "OAUTH_LINK_ERROR", result.error,
			)
		}
		a.setSessionCookies(ctx, result.session, result.user, false)
		sessionToken, _ := recordString(result.session, "token")
		return jsonResponse(contract.StatusOK, map[string]any{
			"redirect": false,
			"token":    sessionToken,
			"url":      nil,
			"user":     a.publicUser(result.user),
		})
	}

	stateData, state, err := a.generateOAuthState(ctx, body, nil)
	if err != nil {
		return contract.Response{}, err
	}
	scopes, scopeErr := optionalStringSlice(body, "scopes")
	if scopeErr != nil {
		return contract.Response{}, scopeErr
	}
	loginHint := ""
	if value, exists := optionalString(body, "loginHint"); exists && value != nil {
		loginHint = *value
	}
	authorizeURL, err := provider.CreateAuthorizationURL(providers.AuthorizationInput{
		State: state, CodeVerifier: stateData.CodeVerifier,
		RedirectURI: a.baseURLForRequest(ctx.Request()) + "/callback/" + url.PathEscape(provider.ID),
		Scopes:      scopes, LoginHint: loginHint,
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	disableRedirect := false
	if value, exists := optionalBool(body, "disableRedirect"); exists && value != nil {
		disableRedirect = *value
	}
	if !disableRedirect {
		ctx.SetResponseHeader("Location", authorizeURL.String())
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"url": authorizeURL.String(), "redirect": !disableRedirect,
	})
}

func (a *Auth) callbackOAuth(ctx *engine.Context) (contract.Response, error) {
	providerID, _ := ctx.Param("id")
	if ctx.Request().Method() == http.MethodPost {
		body := map[string]any{}
		if len(strings.TrimSpace(string(ctx.Request().Body()))) != 0 {
			parsed, err := decodeObjectBody(ctx.Request())
			if err != nil {
				return a.redirectOAuthError(ctx.Request(), "", "invalid_callback_request", ""), nil
			}
			body = parsed
		}
		query, _ := ctx.Request().Query()
		for key, values := range query {
			if len(values) != 0 {
				body[key] = values[0]
			}
		}
		values := url.Values{}
		for _, key := range []string{"code", "error", "device_id", "error_description", "state", "user"} {
			if value, ok := body[key].(string); ok {
				values.Set(key, value)
			}
		}
		location := a.baseURLForRequest(ctx.Request()) + "/callback/" + url.PathEscape(providerID)
		if encoded := values.Encode(); encoded != "" {
			location += "?" + encoded
		}
		return redirectResponse(location), nil
	}

	query, err := ctx.Request().Query()
	if err != nil {
		return a.redirectOAuthError(ctx.Request(), "", "invalid_callback_request", ""), nil
	}
	stateData, err := a.parseOAuthState(ctx, query.Get("state"))
	if err != nil {
		code, errorURL := oauthStateFailure(err)
		return a.redirectOAuthError(ctx.Request(), errorURL, code, ""), nil
	}
	resolvedErrorURL := stateData.ErrorURL
	if resolvedErrorURL == "" {
		resolvedErrorURL = a.oauthErrorURL(ctx.Request())
	}
	if providerError := query.Get("error"); providerError != "" {
		return a.redirectOAuthError(
			ctx.Request(), resolvedErrorURL, providerError, query.Get("error_description"),
		), nil
	}
	code := query.Get("code")
	if code == "" {
		return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "no_code", ""), nil
	}
	provider := a.socialProvider(providerID)
	if provider == nil {
		return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "oauth_provider_not_found", ""), nil
	}
	tokens, err := provider.ValidateAuthorizationCode(ctx.GoContext(), providers.CodeInput{
		Code: code, CodeVerifier: stateData.CodeVerifier, DeviceID: query.Get("device_id"),
		RedirectURI: a.baseURLForRequest(ctx.Request()) + "/callback/" + url.PathEscape(provider.ID),
	})
	if err != nil || tokens == nil {
		return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "invalid_code", ""), nil
	}
	var authorizationUser []providers.AuthorizationUser
	if raw := query.Get("user"); raw != "" {
		var userObject map[string]any
		if json.Unmarshal([]byte(raw), &userObject) == nil {
			authorizationUser = append(authorizationUser, parseAuthorizationUser(userObject))
		}
	}
	info, err := provider.GetUserInfo(ctx.GoContext(), *tokens, authorizationUser...)
	if err != nil || info == nil || info.User.ID == "" {
		return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "unable_to_get_user_info", ""), nil
	}
	if stateData.CallbackURL == "" {
		return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "no_callback_url", ""), nil
	}

	if stateData.Link != nil {
		if !a.providerLinkTrusted(provider.ID, info.User.EmailVerified) || !a.accountLinkingEnabled() {
			return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "unable_to_link_account", ""), nil
		}
		if !a.options.Account.AccountLinking.AllowDifferentEmails &&
			(info.User.Email == nil || !strings.EqualFold(*info.User.Email, stateData.Link.Email)) {
			return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "email_doesn't_match", ""), nil
		}
		if err := a.linkOAuthAccount(ctx, stateData.Link.UserID, provider, info.User, *tokens); err != nil {
			if apiErr, ok := contract.AsAPIError(err); ok && apiErr.Code == "ACCOUNT_ALREADY_LINKED_TO_DIFFERENT_USER" {
				return a.redirectOAuthError(
					ctx.Request(), resolvedErrorURL, "account_already_linked_to_different_user", "",
				), nil
			}
			return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "unable_to_link_account", ""), nil
		}
		return redirectResponse(stateData.CallbackURL), nil
	}

	if info.User.Email == nil || *info.User.Email == "" {
		return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, "email_not_found", ""), nil
	}
	requestSignUp := stateData.RequestSignUp != nil && *stateData.RequestSignUp
	disableSignUp := (provider.Options.DisableImplicitSignUp && !requestSignUp) || provider.Options.DisableSignUp
	result, err := a.handleOAuthUserInfo(ctx, provider, info.User, *tokens, disableSignUp, stateData.CallbackURL)
	if err != nil {
		if apiErr, ok := contract.AsAPIError(err); ok && apiErr.Code != "" {
			return a.redirectOAuthError(ctx.Request(), resolvedErrorURL, apiErr.Code, apiErr.Message), nil
		}
		return contract.Response{}, err
	}
	if result.error != "" {
		return a.redirectOAuthError(
			ctx.Request(), resolvedErrorURL, strings.ReplaceAll(result.error, " ", "_"), "",
		), nil
	}
	a.setSessionCookies(ctx, result.session, result.user, false)
	target := stateData.CallbackURL
	if result.isRegister && stateData.NewUserURL != "" {
		target = stateData.NewUserURL
	}
	return redirectResponse(target), nil
}

func (a *Auth) linkSocialAccount(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	if err := validateSocialBody(body, false); err != nil {
		return contract.Response{}, err
	}
	providerID, ok := requiredString(body, "provider")
	if !ok || providerID == "" {
		return contract.Response{}, missingField("provider")
	}
	provider := a.socialProvider(providerID)
	if provider == nil {
		return contract.Response{}, baseError(contract.StatusNotFound, ErrorProviderNotFound)
	}
	userID, _ := recordString(current.User, "id")
	email, _ := recordString(current.User, "email")
	if rawIDToken, exists := body["idToken"]; exists && rawIDToken != nil {
		idToken, parseErr := requireStringMap(rawIDToken, "idToken")
		if parseErr != nil {
			return contract.Response{}, validationError(parseErr.Error())
		}
		token, ok := requiredString(idToken, "token")
		if !ok || token == "" {
			return contract.Response{}, missingField("idToken.token")
		}
		if !provider.Metadata.SupportsIDToken && provider.Options.VerifyIDToken == nil {
			return contract.Response{}, baseError(contract.StatusNotFound, ErrorIDTokenNotSupported)
		}
		nonce := ""
		if value, exists := optionalString(idToken, "nonce"); exists && value != nil {
			nonce = *value
		}
		valid, verifyErr := provider.VerifyIDToken(ctx.GoContext(), token, nonce)
		if verifyErr != nil || !valid {
			return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorInvalidToken)
		}
		tokens := oauth2.Tokens{IDToken: token}
		if value, exists := optionalString(idToken, "accessToken"); exists && value != nil {
			tokens.AccessToken = *value
		}
		if value, exists := optionalString(idToken, "refreshToken"); exists && value != nil {
			tokens.RefreshToken = *value
		}
		tokens.Scopes, err = optionalStringSlice(idToken, "scopes")
		if err != nil {
			return contract.Response{}, err
		}
		info, infoErr := provider.GetUserInfo(ctx.GoContext(), tokens)
		if infoErr != nil || info == nil || info.User.ID == "" {
			return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorFailedToGetUserInfo)
		}
		if info.User.Email == nil || *info.User.Email == "" {
			return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorUserEmailNotFound)
		}
		if !a.providerLinkTrusted(provider.ID, info.User.EmailVerified) || !a.accountLinkingEnabled() {
			return contract.Response{}, contract.NewAPIError(
				contract.StatusUnauthorized, "LINKING_NOT_ALLOWED", "Account not linked - linking not allowed",
			)
		}
		if !a.options.Account.AccountLinking.AllowDifferentEmails && !strings.EqualFold(*info.User.Email, email) {
			return contract.Response{}, contract.NewAPIError(
				contract.StatusUnauthorized,
				"LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
				"Account not linked - different emails not allowed",
			)
		}
		lock := a.accountOperationLock("provider-account:" + provider.ID + "\x00" + info.User.ID)
		lock.Lock()
		defer lock.Unlock()
		existing, findErr := a.findAccountByProvider(ctx.GoContext(), provider.ID, info.User.ID)
		if findErr != nil {
			return contract.Response{}, internalServerError(findErr)
		}
		if existing != nil {
			existingUserID, _ := recordString(existing, "userId")
			if existingUserID != userID {
				return contract.Response{}, baseError(422, ErrorSocialAccountAlreadyLinked)
			}
			return jsonResponse(contract.StatusOK, map[string]any{
				"url": "", "status": true, "redirect": false,
			})
		}
		if err := a.createOAuthAccount(ctx.GoContext(), a.adapter, userID, provider.ID, info.User.ID, tokens); err != nil {
			return contract.Response{}, contract.NewAPIError(
				417, "LINKING_FAILED", "Account not linked - unable to create account",
			).WithCause(err)
		}
		_ = a.applyProviderProfile(ctx.GoContext(), userID, info.User)
		return jsonResponse(contract.StatusOK, map[string]any{
			"url": "", "status": true, "redirect": false,
		})
	}

	data, state, err := a.generateOAuthState(ctx, body, &oauthLinkState{UserID: userID, Email: email})
	if err != nil {
		return contract.Response{}, err
	}
	scopes, scopeErr := optionalStringSlice(body, "scopes")
	if scopeErr != nil {
		return contract.Response{}, scopeErr
	}
	authorizeURL, err := provider.CreateAuthorizationURL(providers.AuthorizationInput{
		State: state, CodeVerifier: data.CodeVerifier,
		RedirectURI: a.baseURLForRequest(ctx.Request()) + "/callback/" + url.PathEscape(provider.ID),
		Scopes:      scopes,
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	disableRedirect := false
	if value, exists := optionalBool(body, "disableRedirect"); exists && value != nil {
		disableRedirect = *value
	}
	if !disableRedirect {
		ctx.SetResponseHeader("Location", authorizeURL.String())
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"url": authorizeURL.String(), "redirect": !disableRedirect,
	})
}

func (a *Auth) handleOAuthUserInfo(
	ctx *engine.Context,
	provider *providers.Provider,
	info oauth2.UserInfo,
	tokens oauth2.Tokens,
	disableSignUp bool,
	verificationCallbackURL string,
) (oauthUserResult, error) {
	return a.handleOAuthUserInfoWithTrust(
		ctx, provider, info, tokens, disableSignUp, verificationCallbackURL,
		false, true,
	)
}

func (a *Auth) handleOAuthUserInfoWithTrust(
	ctx *engine.Context,
	provider *providers.Provider,
	info oauth2.UserInfo,
	tokens oauth2.Tokens,
	disableSignUp bool,
	verificationCallbackURL string,
	isTrustedProvider bool,
	trustProviderByName bool,
) (oauthUserResult, error) {
	if info.ID == "" {
		return oauthUserResult{error: "unable to get user info"}, nil
	}
	if info.Email == nil {
		return oauthUserResult{error: "email not found"}, nil
	}
	lock := a.accountOperationLock("provider-account:" + provider.ID + "\x00" + info.ID)
	lock.Lock()
	defer lock.Unlock()
	email := strings.ToLower(*info.Email)
	linkedAccount, err := a.findAccountByProvider(ctx.GoContext(), provider.ID, info.ID)
	if err != nil {
		return oauthUserResult{}, internalServerError(err)
	}
	var user storage.Record
	if linkedAccount != nil {
		userID, _ := recordString(linkedAccount, "userId")
		user, err = a.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
	} else {
		user, err = a.findUserByEmail(ctx.GoContext(), a.adapter, email)
	}
	if err != nil {
		return oauthUserResult{}, internalServerError(err)
	}
	isRegister := user == nil
	if user == nil {
		if disableSignUp {
			return oauthUserResult{error: "signup disabled"}, nil
		}
		var createdUser, createdAccount, session storage.Record
		err = a.runTransaction(ctx.GoContext(), func(tx storage.TransactionAdapter) error {
			var createErr error
			createdUser, createErr = a.createOAuthUser(ctx.GoContext(), tx, info)
			if createErr != nil {
				return createErr
			}
			userID, _ := recordString(createdUser, "id")
			createdAccount, createErr = a.createOAuthAccountRecord(
				ctx.GoContext(), tx, userID, provider.ID, info.ID, tokens,
			)
			if createErr != nil {
				return createErr
			}
			session, createErr = a.createSession(ctx, tx, userID, false)
			return createErr
		})
		if err != nil {
			if _, ok := contract.AsAPIError(err); ok {
				return oauthUserResult{}, err
			}
			return oauthUserResult{error: "unable to create user"}, nil
		}
		if !info.EmailVerified {
			if verificationCallbackURL == "" {
				verificationCallbackURL = "/"
			}
			if err := a.maybeSendVerification(
				ctx.GoContext(), ctx.Request(), createdUser,
				map[string]any{"callbackURL": verificationCallbackURL}, true,
			); err != nil {
				return oauthUserResult{}, err
			}
		}
		a.setAccountCookie(ctx, createdAccount)
		return oauthUserResult{user: createdUser, session: session, isRegister: true}, nil
	}

	userID, _ := recordString(user, "id")
	if linkedAccount == nil {
		localVerified, _ := recordBool(user, "emailVerified")
		requireLocalVerified := true
		if configured := a.options.Account.AccountLinking.RequireLocalEmailVerified; configured != nil {
			requireLocalVerified = *configured
		}
		providerTrusted := info.EmailVerified || isTrustedProvider
		if trustProviderByName {
			providerTrusted = providerTrusted || a.providerNamedTrusted(provider.ID)
		}
		if !providerTrusted ||
			(requireLocalVerified && !localVerified) || !a.accountLinkingEnabled() ||
			a.options.Account.AccountLinking.DisableImplicitLinking {
			return oauthUserResult{error: "account not linked"}, nil
		}
		if err := a.createOAuthAccount(
			ctx.GoContext(), a.adapter, userID, provider.ID, info.ID, tokens,
		); err != nil {
			a.logger.Error("Unable to link account", err)
			return oauthUserResult{error: "unable to link account"}, nil
		}
		if info.EmailVerified && !localVerified && strings.EqualFold(email, mustRecordString(user, "email")) {
			updated, updateErr := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
				Update: storage.Record{"emailVerified": true},
			})
			if updateErr == nil && updated != nil {
				user = updated
			}
		}
		if updated := a.applyProviderProfile(ctx.GoContext(), userID, info); updated != nil {
			user = updated
		}
	} else {
		if a.options.Account.UpdateAccountOnSignIn == nil || *a.options.Account.UpdateAccountOnSignIn {
			if err := a.updateOAuthAccount(ctx.GoContext(), linkedAccount, tokens); err != nil {
				return oauthUserResult{}, internalServerError(err)
			}
		}
		localVerified, _ := recordBool(user, "emailVerified")
		if info.EmailVerified && !localVerified && strings.EqualFold(email, mustRecordString(user, "email")) {
			updated, updateErr := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
				Update: storage.Record{"emailVerified": true},
			})
			if updateErr == nil && updated != nil {
				user = updated
			}
		}
	}
	if provider.Options.OverrideUserInfo {
		update := a.providerProfileUpdate(info)
		update["email"] = email
		currentEmail := mustRecordString(user, "email")
		currentVerified, _ := recordBool(user, "emailVerified")
		update["emailVerified"] = info.EmailVerified
		if strings.EqualFold(email, currentEmail) {
			update["emailVerified"] = currentVerified || info.EmailVerified
		}
		updated, updateErr := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}, Update: update,
		})
		if updateErr != nil {
			return oauthUserResult{}, internalServerError(updateErr)
		}
		if updated != nil {
			user = updated
		}
	}
	if err := a.refreshSecondaryUser(ctx.GoContext(), user); err != nil {
		return oauthUserResult{}, internalServerError(err)
	}
	session, err := a.createSession(ctx, a.adapter, userID, false)
	if err != nil {
		if _, ok := contract.AsAPIError(err); ok {
			return oauthUserResult{}, err
		}
		return oauthUserResult{error: "unable to create session"}, nil
	}
	if session == nil {
		return oauthUserResult{error: "unable to create session"}, nil
	}
	if account, _ := a.findAccountByProvider(ctx.GoContext(), provider.ID, info.ID); account != nil {
		a.setAccountCookie(ctx, account)
	}
	return oauthUserResult{user: user, session: session, isRegister: isRegister}, nil
}

func (a *Auth) createOAuthUser(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	info oauth2.UserInfo,
) (storage.Record, error) {
	now := a.options.Clock().UTC()
	id, generated, err := generateIdentifier(a.options, "user", 32)
	if err != nil {
		return nil, err
	}
	email := ""
	if info.Email != nil {
		email = strings.ToLower(*info.Email)
	}
	data := storage.Record{
		"name": info.Name, "email": email, "emailVerified": info.EmailVerified,
		"createdAt": now, "updatedAt": now,
	}
	if info.Image != "" {
		data["image"] = info.Image
	}
	for key, value := range a.providerAdditionalFields(info.Extra) {
		data[key] = value
	}
	if generated {
		data["id"] = id
	}
	return adapter.Create(ctx, storage.CreateParams{
		Model: "user", Data: data, ForceAllowID: generated,
	})
}

func (a *Auth) createOAuthAccount(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	userID, providerID, accountID string,
	tokens oauth2.Tokens,
) error {
	_, err := a.createOAuthAccountRecord(ctx, adapter, userID, providerID, accountID, tokens)
	return err
}

// createOAuthAccountRecord returns the row produced by the same transaction
// that created it. Stateless OAuth callbacks need that value to seed the
// account_data cookie without relying on a post-commit adapter lookup.
func (a *Auth) createOAuthAccountRecord(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	userID, providerID, accountID string,
	tokens oauth2.Tokens,
) (storage.Record, error) {
	now := a.options.Clock().UTC()
	id, generated, err := generateIdentifier(a.options, "account", 32)
	if err != nil {
		return nil, err
	}
	data, err := a.oauthTokenRecord(tokens)
	if err != nil {
		return nil, err
	}
	data["userId"] = userID
	data["providerId"] = providerID
	data["accountId"] = accountID
	data["createdAt"] = now
	data["updatedAt"] = now
	if generated {
		data["id"] = id
	}
	return adapter.Create(ctx, storage.CreateParams{
		Model: "account", Data: data, ForceAllowID: generated,
	})
}

func (a *Auth) updateOAuthAccount(
	ctx context.Context,
	account storage.Record,
	tokens oauth2.Tokens,
) error {
	update, err := a.oauthTokenRecord(tokens)
	if err != nil || len(update) == 0 {
		return err
	}
	id, _ := recordString(account, "id")
	_, err = a.adapter.Update(ctx, storage.UpdateParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: id}}, Update: update,
	})
	return err
}

func (a *Auth) oauthTokenRecord(tokens oauth2.Tokens) (storage.Record, error) {
	data := storage.Record{}
	var err error
	if tokens.AccessToken != "" {
		data["accessToken"], err = a.storeOAuthToken(tokens.AccessToken)
		if err != nil {
			return nil, err
		}
	}
	if tokens.RefreshToken != "" {
		data["refreshToken"], err = a.storeOAuthToken(tokens.RefreshToken)
		if err != nil {
			return nil, err
		}
	}
	if tokens.IDToken != "" {
		data["idToken"] = tokens.IDToken
	}
	if tokens.AccessTokenExpiresAt != nil {
		data["accessTokenExpiresAt"] = tokens.AccessTokenExpiresAt.UTC()
	}
	if tokens.RefreshTokenExpiresAt != nil {
		data["refreshTokenExpiresAt"] = tokens.RefreshTokenExpiresAt.UTC()
	}
	if tokens.Scopes != nil {
		data["scope"] = strings.Join(tokens.Scopes, ",")
	}
	return data, nil
}

func (a *Auth) storeOAuthToken(token string) (string, error) {
	if token == "" || !a.options.Account.EncryptOAuthTokens {
		return token, nil
	}
	return a.encryptOAuthValue([]byte(token))
}

func (a *Auth) loadOAuthToken(token string) (string, error) {
	if token == "" || !a.options.Account.EncryptOAuthTokens {
		return token, nil
	}
	_, versioned := baCrypto.ParseEnvelope(token)
	bareEncrypted := len(token)%2 == 0 && isHexString(token)
	if !versioned && !bareEncrypted {
		return token, nil
	}
	plain, err := baCrypto.DecryptWithConfig(a.options.secretConfig, token)
	return string(plain), err
}

func (a *Auth) findAccountByProvider(
	ctx context.Context,
	providerID, accountID string,
) (storage.Record, error) {
	return a.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "account", Where: []storage.Where{
			{Field: "providerId", Value: providerID},
			{Field: "accountId", Value: accountID},
		},
	})
}

func (a *Auth) linkOAuthAccount(
	ctx *engine.Context,
	userID string,
	provider *providers.Provider,
	info oauth2.UserInfo,
	tokens oauth2.Tokens,
) error {
	if info.ID == "" {
		return contract.NewAPIError(
			contract.StatusBadRequest,
			"INVALID_PROVIDER_ACCOUNT",
			"Provider account ID is required",
		)
	}
	lock := a.accountOperationLock("provider-account:" + provider.ID + "\x00" + info.ID)
	lock.Lock()
	defer lock.Unlock()
	existing, err := a.findAccountByProvider(ctx.GoContext(), provider.ID, info.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		existingUserID, _ := recordString(existing, "userId")
		if existingUserID != userID {
			return contract.NewAPIError(
				contract.StatusBadRequest,
				"ACCOUNT_ALREADY_LINKED_TO_DIFFERENT_USER",
				"Account already linked to a different user",
			)
		}
		if err := a.updateOAuthAccount(ctx.GoContext(), existing, tokens); err != nil {
			return err
		}
	} else if err := a.createOAuthAccount(
		ctx.GoContext(), a.adapter, userID, provider.ID, info.ID, tokens,
	); err != nil {
		return err
	}
	_ = a.applyProviderProfile(ctx.GoContext(), userID, info)
	return nil
}

func (a *Auth) applyProviderProfile(
	ctx context.Context,
	userID string,
	info oauth2.UserInfo,
) storage.Record {
	if !a.options.Account.AccountLinking.UpdateUserInfoOnLink {
		return nil
	}
	updated, err := a.adapter.Update(ctx, storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		Update: a.providerProfileUpdate(info),
	})
	if err != nil {
		a.logger.Warn("Could not update user info on account link", err)
		return nil
	}
	if updated != nil {
		_ = a.refreshSecondaryUser(ctx, updated)
	}
	return updated
}

func (a *Auth) providerProfileUpdate(info oauth2.UserInfo) storage.Record {
	result := a.providerAdditionalFields(info.Extra)
	if info.Name != "" {
		result["name"] = info.Name
	}
	if info.Image != "" {
		result["image"] = info.Image
	}
	return result
}

func (a *Auth) providerAdditionalFields(profile map[string]any) storage.Record {
	result := storage.Record{}
	table := a.options.Schema.Models["user"]
	for field, attribute := range table.Fields {
		if isCoreUserField(field) || !attribute.IsInput() {
			continue
		}
		if value, exists := profile[field]; exists {
			result[field] = value
		}
	}
	return result
}

func (a *Auth) accountLinkingEnabled() bool {
	return a.options.Account.AccountLinking.Enabled == nil || *a.options.Account.AccountLinking.Enabled
}

func (a *Auth) providerLinkTrusted(providerID string, emailVerified bool) bool {
	return emailVerified || a.providerNamedTrusted(providerID)
}

func (a *Auth) providerNamedTrusted(providerID string) bool {
	for _, trusted := range a.options.Account.AccountLinking.TrustedProviders {
		if trusted == providerID {
			return true
		}
	}
	return false
}

func parseAuthorizationUser(value map[string]any) providers.AuthorizationUser {
	result := providers.AuthorizationUser{}
	result.Email, _ = value["email"].(string)
	if name, ok := value["name"].(map[string]any); ok {
		result.FirstName, _ = name["firstName"].(string)
		result.LastName, _ = name["lastName"].(string)
	}
	return result
}

func optionalStringSlice(body map[string]any, name string) ([]string, error) {
	value, exists := body[name]
	if !exists || value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		if stringsValue, ok := value.([]string); ok {
			return append([]string(nil), stringsValue...), nil
		}
		return nil, validationError(name + ": Expected array")
	}
	result := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, validationError(fmt.Sprintf("%s.%d: Expected string", name, index))
		}
		result[index] = text
	}
	return result, nil
}

func validateSocialBody(body map[string]any, signIn bool) error {
	stringFields := []string{"callbackURL", "errorCallbackURL"}
	if signIn {
		stringFields = append(stringFields, "newUserCallbackURL", "loginHint")
	}
	for _, field := range stringFields {
		if raw, exists := body[field]; exists {
			if _, ok := raw.(string); !ok {
				return validationError(field + ": Expected string")
			}
		}
	}
	for _, field := range []string{"disableRedirect", "requestSignUp"} {
		if raw, exists := body[field]; exists {
			if _, ok := raw.(bool); !ok {
				return validationError(field + ": Expected boolean")
			}
		}
	}
	if raw, exists := body["scopes"]; exists {
		if raw == nil {
			return validationError("scopes: Expected array")
		}
		if _, err := optionalStringSlice(body, "scopes"); err != nil {
			return err
		}
	}
	if raw, exists := body["additionalData"]; exists {
		if _, ok := raw.(map[string]any); !ok {
			return validationError("additionalData: Expected object")
		}
	}
	if raw, exists := body["idToken"]; exists {
		idToken, ok := raw.(map[string]any)
		if !ok {
			return validationError("idToken: Expected object")
		}
		for _, field := range []string{"token", "nonce", "accessToken", "refreshToken"} {
			if value, present := idToken[field]; present {
				if _, ok := value.(string); !ok {
					return validationError("idToken." + field + ": Expected string")
				}
			}
		}
		if rawScopes, present := idToken["scopes"]; present && !signIn {
			if rawScopes == nil {
				return validationError("idToken.scopes: Expected array")
			}
			if _, err := optionalStringSlice(idToken, "scopes"); err != nil {
				return err
			}
		}
		if rawExpiresAt, present := idToken["expiresAt"]; present && signIn {
			if !isJSONNumber(rawExpiresAt) {
				return validationError("idToken.expiresAt: Expected number")
			}
		}
		if rawUser, present := idToken["user"]; present && signIn {
			user, ok := rawUser.(map[string]any)
			if !ok {
				return validationError("idToken.user: Expected object")
			}
			if rawEmail, exists := user["email"]; exists {
				if _, ok := rawEmail.(string); !ok {
					return validationError("idToken.user.email: Expected string")
				}
			}
			if rawName, exists := user["name"]; exists {
				name, ok := rawName.(map[string]any)
				if !ok {
					return validationError("idToken.user.name: Expected object")
				}
				for _, field := range []string{"firstName", "lastName"} {
					if value, exists := name[field]; exists {
						if _, ok := value.(string); !ok {
							return validationError("idToken.user.name." + field + ": Expected string")
						}
					}
				}
			}
		}
	}
	return nil
}

func isJSONNumber(value any) bool {
	switch value.(type) {
	case json.Number, float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, string(ErrorValidation), message)
}

func mustRecordString(record storage.Record, key string) string {
	value, _ := recordString(record, key)
	return value
}

func isHexString(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}
