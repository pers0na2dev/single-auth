package core

import (
	"context"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/storage"
)

type validAccessToken struct {
	AccessToken          string
	AccessTokenExpiresAt *time.Time
	Scopes               []string
	IDToken              string
}

func (a *Auth) getAccessToken(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	providerID, ok := requiredString(body, "providerId")
	if !ok || providerID == "" {
		return contract.Response{}, missingField("providerId")
	}
	accountID, err := accountTokenOptionalString(body, "accountId")
	if err != nil {
		return contract.Response{}, err
	}
	userID, err := accountTokenOptionalString(body, "userId")
	if err != nil {
		return contract.Response{}, err
	}
	resolvedUserID, err := a.resolveAccountUserID(ctx, userID)
	if err != nil {
		return contract.Response{}, err
	}
	tokens, err := a.getValidAccessToken(ctx, resolvedUserID, providerID, accountID, nil)
	if err != nil {
		return contract.Response{}, err
	}
	return jsonResponse(contract.StatusOK, validAccessTokenJSON(tokens))
}

func (a *Auth) refreshToken(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	providerID, ok := requiredString(body, "providerId")
	if !ok || providerID == "" {
		return contract.Response{}, missingField("providerId")
	}
	accountID, err := accountTokenOptionalString(body, "accountId")
	if err != nil {
		return contract.Response{}, err
	}
	userID, err := accountTokenOptionalString(body, "userId")
	if err != nil {
		return contract.Response{}, err
	}
	resolvedUserID, err := a.resolveAccountUserID(ctx, userID)
	if err != nil {
		return contract.Response{}, err
	}
	provider := a.socialProvider(providerID)
	if provider == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest,
			"PROVIDER_NOT_SUPPORTED",
			"Provider "+providerID+" is not supported.",
		)
	}
	if !provider.Metadata.SupportsRefresh && provider.Options.RefreshAccessToken == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest,
			"TOKEN_REFRESH_NOT_SUPPORTED",
			"Provider "+providerID+" does not support token refreshing.",
		)
	}
	lock := a.accountOperationLock(
		"token-refresh:" + resolvedUserID + "\x00" + providerID + "\x00" + accountID,
	)
	lock.Lock()
	defer lock.Unlock()
	account, usedCookie, err := a.resolveOAuthAccount(ctx, resolvedUserID, providerID, accountID)
	if err != nil {
		return contract.Response{}, err
	}
	if usedCookie && a.options.stateful {
		selectionAccountID := accountID
		if selectionAccountID == "" {
			selectionAccountID = mustRecordString(account, "accountId")
		}
		account, err = a.findOAuthAccountForUser(
			ctx.GoContext(), resolvedUserID, providerID, selectionAccountID,
		)
		if err != nil {
			return contract.Response{}, internalServerError(err)
		}
		if account == nil {
			return contract.Response{}, baseError(contract.StatusBadRequest, ErrorAccountNotFound)
		}
	}
	refreshToken, _ := recordString(account, "refreshToken")
	if refreshToken == "" {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "REFRESH_TOKEN_NOT_FOUND", "Refresh token not found",
		)
	}
	decrypted, err := a.loadOAuthToken(refreshToken)
	if err != nil {
		return contract.Response{}, failedToRefreshAccessToken(err)
	}
	tokens, err := provider.RefreshAccessToken(ctx.GoContext(), decrypted)
	if err != nil {
		return contract.Response{}, failedToRefreshAccessToken(err)
	}
	updated, response, err := a.persistRefreshedTokens(ctx, account, tokens, decrypted, true)
	if err != nil {
		return contract.Response{}, failedToRefreshAccessToken(err)
	}
	if usedCookie && accountCookieEnabled(a.options.Account) {
		a.setAccountCookie(ctx, updated)
	}
	return jsonResponse(contract.StatusOK, response)
}

func (a *Auth) accountInfo(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, validationError("Invalid query")
	}
	providedAccountID := query.Get("accountId")
	providedProviderID := query.Get("providerId")
	providedUserID := query.Get("userId")
	resolvedUserID, err := a.resolveAccountUserID(ctx, providedUserID)
	if err != nil {
		return contract.Response{}, err
	}
	var account storage.Record
	if providedAccountID == "" {
		account = a.getAccountCookie(ctx.Request())
		if account != nil && !a.accountMatches(account, resolvedUserID, providedProviderID, "") {
			account = nil
		}
	} else {
		accounts, findErr := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
			Model: "account", Where: []storage.Where{
				{Field: "userId", Value: resolvedUserID},
				{Field: "accountId", Value: providedAccountID},
			},
		})
		if findErr != nil {
			return contract.Response{}, internalServerError(findErr)
		}
		matches := make([]storage.Record, 0, len(accounts))
		for _, candidate := range accounts {
			if providedProviderID == "" || mustRecordString(candidate, "providerId") == providedProviderID {
				matches = append(matches, candidate)
			}
		}
		if len(matches) > 1 {
			return contract.Response{}, contract.NewAPIError(
				contract.StatusBadRequest,
				"AMBIGUOUS_ACCOUNT",
				"Multiple accounts share this account ID. Pass a providerId to disambiguate.",
			)
		}
		if len(matches) == 1 {
			account = matches[0]
		}
	}
	if account == nil || !a.accountMatches(account, resolvedUserID, "", "") {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorAccountNotFound)
	}
	providerID := mustRecordString(account, "providerId")
	provider := a.socialProvider(providerID)
	if provider == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest,
			"PROVIDER_NOT_CONFIGURED",
			"Account is not associated with a configured social provider.",
		)
	}
	accountID := mustRecordString(account, "accountId")
	tokens, err := a.getValidAccessToken(
		ctx, resolvedUserID, providerID, accountID, account,
	)
	if err != nil {
		return contract.Response{}, err
	}
	if tokens.AccessToken == "" {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "ACCESS_TOKEN_NOT_FOUND", "Access token not found",
		)
	}
	providerTokens := oauth2.Tokens{
		AccessToken: tokens.AccessToken, IDToken: tokens.IDToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt, Scopes: tokens.Scopes,
	}
	info, err := provider.GetUserInfo(ctx.GoContext(), providerTokens)
	if err != nil {
		return contract.Response{}, err
	}
	if info == nil {
		return jsonResponse(contract.StatusOK, nil)
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"user": oauthUserInfoJSON(info.User), "data": info.Data,
	})
}

func (a *Auth) resolveAccountUserID(ctx *engine.Context, provided string) (string, error) {
	current, err := a.sessionForEndpoint(ctx, true)
	if err == nil {
		return mustRecordString(current.User, "id"), nil
	}
	requestHasHeaders := requestHeader(ctx.Request(), "Cookie") != "" ||
		requestHeader(ctx.Request(), "Authorization") != ""
	if !ctx.IsDirect() || requestHasHeaders {
		return "", unauthorized()
	}
	if provided == "" {
		return "", contract.NewAPIError(
			contract.StatusBadRequest,
			"USER_ID_OR_SESSION_REQUIRED",
			"Either userId or session is required",
		)
	}
	return provided, nil
}

func (a *Auth) getValidAccessToken(
	ctx *engine.Context,
	resolvedUserID, providerID, accountID string,
	resolvedAccount storage.Record,
) (validAccessToken, error) {
	provider := a.socialProvider(providerID)
	if provider == nil {
		return validAccessToken{}, contract.NewAPIError(
			contract.StatusBadRequest,
			"PROVIDER_NOT_SUPPORTED",
			"Provider "+providerID+" is not supported.",
		)
	}
	account := resolvedAccount
	if account == nil {
		var err error
		account, _, err = a.resolveOAuthAccount(ctx, resolvedUserID, providerID, accountID)
		if err != nil {
			return validAccessToken{}, err
		}
	}
	if !a.accountMatches(account, resolvedUserID, providerID, accountID) {
		return validAccessToken{}, baseError(contract.StatusBadRequest, ErrorAccountNotFound)
	}

	accessToken, _ := recordString(account, "accessToken")
	refreshToken, _ := recordString(account, "refreshToken")
	expiresAt, hasExpiry := recordTime(account, "accessTokenExpiresAt")
	newTokens := oauth2.Tokens{}
	refreshed := false
	accessTokenLoaded := false
	if hasExpiry && expiresAt.Sub(a.options.Clock()) < 5*time.Second && refreshToken != "" &&
		(provider.Metadata.SupportsRefresh || provider.Options.RefreshAccessToken != nil) {
		lock := a.accountOperationLock(
			"token-auto-refresh:" + resolvedUserID + "\x00" + providerID + "\x00" + mustRecordString(account, "accountId"),
		)
		lock.Lock()
		defer lock.Unlock()
		if a.options.stateful {
			selectionAccountID := accountID
			if selectionAccountID == "" {
				selectionAccountID = mustRecordString(account, "accountId")
			}
			fresh, findErr := a.findOAuthAccountForUser(
				ctx.GoContext(), resolvedUserID, providerID, selectionAccountID,
			)
			if findErr != nil {
				return validAccessToken{}, failedToGetAccessToken(findErr)
			}
			if fresh == nil {
				return validAccessToken{}, baseError(contract.StatusBadRequest, ErrorAccountNotFound)
			}
			account = fresh
			accessToken, _ = recordString(account, "accessToken")
			refreshToken, _ = recordString(account, "refreshToken")
			expiresAt, hasExpiry = recordTime(account, "accessTokenExpiresAt")
		}
		if !hasExpiry || expiresAt.Sub(a.options.Clock()) >= 5*time.Second || refreshToken == "" {
			decrypted, decryptErr := a.loadOAuthToken(accessToken)
			if decryptErr != nil {
				return validAccessToken{}, failedToGetAccessToken(decryptErr)
			}
			accessToken = decrypted
			accessTokenLoaded = true
		} else {
			decryptedRefresh, err := a.loadOAuthToken(refreshToken)
			if err != nil {
				return validAccessToken{}, failedToGetAccessToken(err)
			}
			newTokens, err = provider.RefreshAccessToken(ctx.GoContext(), decryptedRefresh)
			if err != nil {
				return validAccessToken{}, failedToGetAccessToken(err)
			}
			updated, _, err := a.persistRefreshedTokens(ctx, account, newTokens, decryptedRefresh, false)
			if err != nil {
				return validAccessToken{}, failedToGetAccessToken(err)
			}
			account = updated
			accessToken = newTokens.AccessToken
			refreshed = true
			if accountCookieEnabled(a.options.Account) {
				a.setAccountCookie(ctx, updated)
			}
		}
	}
	if !refreshed && !accessTokenLoaded {
		var err error
		accessToken, err = a.loadOAuthToken(accessToken)
		if err != nil {
			return validAccessToken{}, failedToGetAccessToken(err)
		}
	}
	result := validAccessToken{AccessToken: accessToken}
	if refreshed && newTokens.AccessTokenExpiresAt != nil {
		value := newTokens.AccessTokenExpiresAt.UTC()
		result.AccessTokenExpiresAt = &value
	} else if hasExpiry {
		value := expiresAt.UTC()
		result.AccessTokenExpiresAt = &value
	}
	scope, _ := recordString(account, "scope")
	if scope != "" {
		result.Scopes = strings.Split(scope, ",")
	} else {
		result.Scopes = []string{}
	}
	if refreshed && newTokens.IDToken != "" {
		result.IDToken = newTokens.IDToken
	} else {
		result.IDToken, _ = recordString(account, "idToken")
	}
	return result, nil
}

func (a *Auth) resolveOAuthAccount(
	ctx *engine.Context,
	resolvedUserID, providerID, accountID string,
) (storage.Record, bool, error) {
	account := a.getAccountCookie(ctx.Request())
	if account != nil && a.accountMatches(account, resolvedUserID, providerID, accountID) {
		return account, true, nil
	}
	resolved, err := a.findOAuthAccountForUser(
		ctx.GoContext(), resolvedUserID, providerID, accountID,
	)
	if err != nil {
		return nil, false, internalServerError(err)
	}
	if resolved != nil {
		return resolved, false, nil
	}
	return nil, false, baseError(contract.StatusBadRequest, ErrorAccountNotFound)
}

func (a *Auth) findOAuthAccountForUser(
	ctx context.Context,
	resolvedUserID, providerID, accountID string,
) (storage.Record, error) {
	accounts, err := a.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: resolvedUserID}},
	})
	if err != nil {
		return nil, err
	}
	for _, candidate := range accounts {
		if a.accountMatches(candidate, resolvedUserID, providerID, accountID) {
			return candidate, nil
		}
	}
	return nil, nil
}

func (a *Auth) accountMatches(account storage.Record, userID, providerID, accountID string) bool {
	if account == nil || (a.options.stateful && userID != "" && mustRecordString(account, "userId") != userID) {
		return false
	}
	if providerID != "" && mustRecordString(account, "providerId") != providerID {
		return false
	}
	return accountID == "" || mustRecordString(account, "accountId") == accountID
}

func (a *Auth) persistRefreshedTokens(
	ctx *engine.Context,
	account storage.Record,
	tokens oauth2.Tokens,
	decryptedOldRefresh string,
	updateScope bool,
) (storage.Record, map[string]any, error) {
	storedAccess, err := a.storeOAuthToken(tokens.AccessToken)
	if err != nil {
		return nil, nil, err
	}
	storedOldRefresh, _ := recordString(account, "refreshToken")
	storedRefresh := storedOldRefresh
	responseRefresh := decryptedOldRefresh
	if tokens.RefreshToken != "" {
		storedRefresh, err = a.storeOAuthToken(tokens.RefreshToken)
		if err != nil {
			return nil, nil, err
		}
		responseRefresh = tokens.RefreshToken
	}
	refreshExpiry, _ := recordTime(account, "refreshTokenExpiresAt")
	if tokens.RefreshTokenExpiresAt != nil {
		refreshExpiry = tokens.RefreshTokenExpiresAt.UTC()
	}
	scope, _ := recordString(account, "scope")
	if updateScope && len(tokens.Scopes) != 0 {
		scope = strings.Join(tokens.Scopes, ",")
	}
	idToken, _ := recordString(account, "idToken")
	if tokens.IDToken != "" {
		idToken = tokens.IDToken
	}
	update := storage.Record{
		"accessToken": storedAccess, "refreshToken": storedRefresh,
		"scope": scope, "idToken": idToken,
	}
	if tokens.AccessTokenExpiresAt != nil {
		update["accessTokenExpiresAt"] = tokens.AccessTokenExpiresAt.UTC()
	}
	if !refreshExpiry.IsZero() {
		update["refreshTokenExpiresAt"] = refreshExpiry
	}
	id, _ := recordString(account, "id")
	updated := account
	if id != "" {
		updated, err = a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: id}}, Update: update,
		})
		if err != nil {
			return nil, nil, err
		}
	}
	if updated == nil {
		updated = cloneStorageRecord(account)
		for key, value := range update {
			updated[key] = value
		}
	}
	response := map[string]any{
		"accessToken": tokens.AccessToken, "refreshToken": responseRefresh,
		"scope":      scope,
		"providerId": mustRecordString(account, "providerId"),
		"accountId":  mustRecordString(account, "accountId"),
	}
	if tokens.AccessTokenExpiresAt != nil {
		response["accessTokenExpiresAt"] = tokens.AccessTokenExpiresAt.UTC()
	}
	if !refreshExpiry.IsZero() {
		response["refreshTokenExpiresAt"] = refreshExpiry
	}
	if idToken != "" {
		response["idToken"] = idToken
	}
	return updated, response, nil
}

func validAccessTokenJSON(tokens validAccessToken) map[string]any {
	result := map[string]any{"accessToken": tokens.AccessToken, "scopes": tokens.Scopes}
	if tokens.AccessTokenExpiresAt != nil {
		result["accessTokenExpiresAt"] = tokens.AccessTokenExpiresAt.UTC()
	}
	if tokens.IDToken != "" {
		result["idToken"] = tokens.IDToken
	}
	return result
}

func oauthUserInfoJSON(info oauth2.UserInfo) map[string]any {
	result := map[string]any{
		"id": info.ID, "name": info.Name, "emailVerified": info.EmailVerified,
	}
	if info.Email != nil {
		result["email"] = *info.Email
	}
	if info.Image != "" {
		result["image"] = info.Image
	}
	for key, value := range info.Extra {
		if _, exists := result[key]; !exists {
			result[key] = value
		}
	}
	return result
}

func (a *Auth) setAccountCookie(ctx *engine.Context, account storage.Record) {
	if !accountCookieEnabled(a.options.Account) || account == nil {
		return
	}
	payload := make(map[string]any, len(account))
	for key, value := range account {
		payload[key] = value
	}
	config := a.cookiesForRequest(ctx.Request())
	options := config.accountData
	if options.MaxAge == nil {
		maxAge := 5 * 60
		options.MaxAge = &maxAge
	}
	tokenLifetime := time.Duration(*options.MaxAge) * time.Second
	var token string
	var err error
	if len(a.options.secretConfig.Keys) == 0 {
		token, err = baCrypto.EncodeJWEAt(
			payload, a.options.Secret, "single-auth-account", tokenLifetime,
			a.options.Clock(), a.options.Random,
		)
	} else {
		token, err = baCrypto.EncodeJWEWithConfigAt(
			payload, a.options.secretConfig, "single-auth-account", tokenLifetime,
			a.options.Clock(), a.options.Random,
		)
	}
	if err != nil {
		return
	}
	incoming := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
	store := cookies.NewStore("account_data", config.accountDataName, options, incoming, a.warn)
	for _, chunk := range store.ChunkValue(token, nil) {
		ctx.AddSetCookie(cookies.Serialize(chunk.Name, chunk.Value, chunk.Options))
	}
}

func accountCookieEnabled(options AccountOptions) bool {
	return options.StoreAccountCookie != nil && *options.StoreAccountCookie
}

func (a *Auth) getAccountCookie(request contract.Request) storage.Record {
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	token, ok := cookies.GetChunked(header, a.cookiesForRequest(request).accountDataName)
	if !ok {
		return nil
	}
	var claims map[string]any
	var err error
	if len(a.options.secretConfig.Keys) == 0 {
		claims, err = baCrypto.DecodeJWEAt(
			token, a.options.Secret, "single-auth-account", a.options.Clock(),
		)
	} else {
		claims, err = baCrypto.DecodeJWEWithConfigAt(
			token, a.options.secretConfig, "single-auth-account", a.options.Clock(),
		)
	}
	if err != nil {
		return nil
	}
	delete(claims, "iat")
	delete(claims, "exp")
	delete(claims, "jti")
	return storage.Record(claims)
}

func accountTokenOptionalString(body map[string]any, name string) (string, error) {
	value, exists := body[name]
	if !exists {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", validationError(name + ": Expected string")
	}
	return text, nil
}

func optionalBodyString(body map[string]any, name string) string {
	if value, exists := optionalString(body, name); exists && value != nil {
		return *value
	}
	return ""
}

func failedToGetAccessToken(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest,
		"FAILED_TO_GET_ACCESS_TOKEN",
		"Failed to get a valid access token",
	).WithCause(err)
}

func failedToRefreshAccessToken(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest,
		"FAILED_TO_REFRESH_ACCESS_TOKEN",
		"Failed to refresh access token",
	).WithCause(err)
}
