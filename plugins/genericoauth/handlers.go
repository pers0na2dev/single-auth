package genericoauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

const maxBodyBytes = 4 << 20

func (p *plugin) signIn(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	providerID, ok := requiredString(body, "providerId")
	if !ok {
		return contract.Response{}, validation("[body.providerId] Invalid input: expected string, received undefined")
	}
	config, exists := p.configs[providerID]
	if !exists {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", ErrorMessages[ErrorProviderConfigNotFound]+" "+providerID)
	}
	callbackURL, err := optionalStringField(body, "callbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	errorURL, err := optionalStringField(body, "errorCallbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	newUserURL, err := optionalStringField(body, "newUserCallbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	disableRedirect, err := optionalBoolField(body, "disableRedirect")
	if err != nil {
		return contract.Response{}, err
	}
	requestScopes, err := optionalStringSlice(body, "scopes")
	if err != nil {
		return contract.Response{}, err
	}
	requestSignUp, err := optionalBoolPointer(body, "requestSignUp")
	if err != nil {
		return contract.Response{}, err
	}
	additionalData, err := optionalObject(body, "additionalData")
	if err != nil {
		return contract.Response{}, err
	}

	authorizationURL := config.AuthorizationURL
	tokenURL := config.TokenURL
	if config.DiscoveryURL != "" {
		document, discoveryErr := p.providerState[providerID].discovery(ctx.GoContext(), true)
		if discoveryErr != nil {
			if p.runtime.Logger != nil {
				p.runtime.Logger.Error(discoveryErr.Error(), discoveryErr, map[string]any{"discoveryUrl": config.DiscoveryURL})
			}
		} else {
			authorizationURL = document.AuthorizationEndpoint
			tokenURL = document.TokenEndpoint
		}
	}
	if authorizationURL == "" || tokenURL == "" {
		return contract.Response{}, invalidConfiguration()
	}
	state, err := p.runtime.CreateOAuthState(ctx, singleauth.PluginOAuthStateInput{
		CallbackURL: callbackURL, ErrorURL: errorURL, NewUserURL: newUserURL,
		RequestSignUp: requestSignUp, AdditionalData: reservedAdditionalData(additionalData),
	})
	if err != nil {
		return contract.Response{}, err
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	scopes := config.Scopes
	if requestScopes != nil {
		scopes = append(append([]string(nil), requestScopes...), config.Scopes...)
	}
	authorizeURL, err := createAuthorizationURL(
		config, authorizationURL, state.State, state.CodeVerifier, scopes,
		strings.TrimRight(baseURL, "/")+"/oauth2/callback/"+url.PathEscape(providerID),
		resolveParams(config.AuthorizationURLParams, ctx),
	)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"url": authorizeURL.String(), "redirect": !disableRedirect,
	})
}

func (p *plugin) callback(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, validation("Invalid query")
	}
	defaultErrorURL, err := p.defaultErrorURL(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if providerError := query.Get("error"); providerError != "" || query.Get("code") == "" {
		if providerError == "" {
			providerError = "oAuth_code_missing"
		}
		return redirectError(defaultErrorURL, defaultErrorURL, providerError, query.Get("error_description")), nil
	}
	providerID, ok := ctx.Param("providerId")
	if !ok || providerID == "" {
		return contract.Response{}, apiError(contract.StatusBadRequest, ErrorProviderIDRequired, ErrorMessages[ErrorProviderIDRequired])
	}
	config, exists := p.configs[providerID]
	if !exists {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", ErrorMessages[ErrorProviderConfigNotFound]+" "+providerID)
	}
	state, err := p.parseState(ctx, query.Get("state"))
	if err != nil {
		code, errorURL := stateFailure(err)
		return redirectError(errorURL, defaultErrorURL, code, ""), nil
	}
	resolvedErrorURL := state.ErrorURL
	if resolvedErrorURL == "" {
		resolvedErrorURL = defaultErrorURL
	}

	providerState := p.providerState[providerID]
	tokenURL := config.TokenURL
	userInfoURL := config.UserInfoURL
	expectedIssuer := config.Issuer
	if config.DiscoveryURL != "" {
		document, discoveryErr := providerState.discovery(ctx.GoContext(), true)
		if discoveryErr == nil {
			tokenURL = document.TokenEndpoint
			userInfoURL = document.UserInfoEndpoint
			providerState.setUserInfoURL(userInfoURL)
			if expectedIssuer == "" {
				expectedIssuer = document.Issuer
			}
		}
	}
	if expectedIssuer != "" {
		issuer := query.Get("iss")
		if issuer != "" && issuer != expectedIssuer {
			if p.runtime.Logger != nil {
				p.runtime.Logger.Error("OAuth issuer mismatch", map[string]string{"expected": expectedIssuer, "received": issuer})
			}
			return redirectError(resolvedErrorURL, defaultErrorURL, "issuer_mismatch", ""), nil
		}
		if issuer == "" && config.RequireIssuerValidation {
			if p.runtime.Logger != nil {
				p.runtime.Logger.Error("OAuth issuer parameter missing", map[string]string{"expected": expectedIssuer})
			}
			return redirectError(resolvedErrorURL, defaultErrorURL, "issuer_missing", ""), nil
		}
	}

	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	redirectURI := strings.TrimRight(baseURL, "/") + "/oauth2/callback/" + url.PathEscape(providerID)
	var tokens oauth2.Tokens
	if config.GetToken != nil {
		tokens, err = config.GetToken(ctx.GoContext(), TokenRequest{
			Code: query.Get("code"), RedirectURI: redirectURI,
			CodeVerifier: conditional(config.PKCE, state.CodeVerifier),
		})
		if err == nil {
			tokens = oauth2.ApplyDefaultAccessTokenExpiry(tokens, config.AccessTokenExpiresIn, p.clock())
		}
	} else if tokenURL == "" {
		err = apiError(contract.StatusBadRequest, ErrorInvalidOAuthConfig, ErrorMessages[ErrorInvalidOAuthConfig])
	} else {
		tokens, err = exchangeAuthorizationCode(
			ctx.GoContext(), providerState.client, providerState.clock, config, tokenURL,
			TokenRequest{Code: query.Get("code"), RedirectURI: redirectURI, CodeVerifier: conditional(config.PKCE, state.CodeVerifier)},
			resolveParams(config.TokenURLParams, ctx),
		)
	}
	if err != nil {
		if p.runtime.Logger != nil {
			p.runtime.Logger.Error(errorName(err), err)
		}
		return redirectError(resolvedErrorURL, defaultErrorURL, "oauth_code_verification_failed", ""), nil
	}

	profile, err := providerState.getProfile(ctx.GoContext(), tokens, userInfoURL)
	if err != nil {
		return contract.Response{}, err
	}
	if profile == nil {
		return redirectError(resolvedErrorURL, defaultErrorURL, "user_info_is_missing", ""), nil
	}
	mapped, err := providerState.mapProfile(ctx.GoContext(), profile)
	if err != nil {
		return contract.Response{}, err
	}
	userInfo, hasID := resolveProfile(profile, mapped)
	if userInfo.Email == nil || *userInfo.Email == "" {
		if p.runtime.Logger != nil {
			p.runtime.Logger.Error("The OAuth provider "+providerID+" did not return an email address.", profile)
		}
		return redirectError(resolvedErrorURL, defaultErrorURL, "email_is_missing", ""), nil
	}
	email := strings.ToLower(*userInfo.Email)
	userInfo.Email = &email
	if !hasID || userInfo.ID == "" {
		if p.runtime.Logger != nil {
			p.runtime.Logger.Error("Provider did not return an account id (e.g. `sub`). Unable to sign in.", profile)
		}
		return redirectError(resolvedErrorURL, defaultErrorURL, "id_is_missing", ""), nil
	}
	if userInfo.Name == "" {
		if p.runtime.Logger != nil {
			p.runtime.Logger.Error("Unable to get user info", profile)
		}
		return redirectError(resolvedErrorURL, defaultErrorURL, "name_is_missing", ""), nil
	}

	provider := p.providers[providerID]
	if state.Link != nil {
		if !p.runtime.AllowDifferentEmails && !strings.EqualFold(state.Link.Email, email) {
			return redirectError(resolvedErrorURL, defaultErrorURL, "email_doesn't_match", ""), nil
		}
		if err := p.runtime.LinkOAuthAccount(ctx, state.Link.UserID, provider, userInfo, tokens); err != nil {
			if apiErr, ok := contract.AsAPIError(err); ok && apiErr.Code == "ACCOUNT_ALREADY_LINKED_TO_DIFFERENT_USER" {
				return redirectError(resolvedErrorURL, defaultErrorURL, "account_already_linked_to_different_user", ""), nil
			}
			return redirectError(resolvedErrorURL, defaultErrorURL, "unable_to_link_account", ""), nil
		}
		return redirect(state.CallbackURL), nil
	}

	disableSignUp := config.DisableSignUp || config.DisableImplicitSignUp && (state.RequestSignUp == nil || !*state.RequestSignUp)
	result, err := p.runtime.HandleOAuthUser(ctx, singleauth.PluginOAuthUserInput{
		Provider: provider, ProviderID: providerID, User: userInfo, Tokens: tokens,
		DisableSignUp: disableSignUp, CallbackURL: state.CallbackURL,
	})
	if err != nil {
		if apiErr, ok := contract.AsAPIError(err); ok && apiErr.Code != "" {
			return redirectError(resolvedErrorURL, defaultErrorURL, apiErr.Code, apiErr.Message), nil
		}
		return contract.Response{}, err
	}
	if result.LinkError != "" {
		return redirectError(resolvedErrorURL, defaultErrorURL, strings.ReplaceAll(result.LinkError, " ", "_"), ""), nil
	}
	if result.State.Session == nil || result.State.User == nil {
		return contract.Response{}, apiError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error")
	}
	if err := p.runtime.RefreshSession(ctx, result.State, false); err != nil {
		return contract.Response{}, err
	}
	target := state.CallbackURL
	if result.IsRegister && state.NewUserURL != "" {
		target = state.NewUserURL
	}
	return redirect(target), nil
}

func (p *plugin) link(ctx *engine.Context) (contract.Response, error) {
	session, err := p.runtime.ResolveSession(ctx, singleauth.PluginSessionRequired)
	if err != nil || session == nil {
		if err != nil {
			return contract.Response{}, err
		}
		return contract.Response{}, apiError(contract.StatusUnauthorized, ErrorSessionRequired, ErrorMessages[ErrorSessionRequired])
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	providerID, ok := requiredString(body, "providerId")
	if !ok {
		return contract.Response{}, validation("[body.providerId] Invalid input: expected string, received undefined")
	}
	callbackURL, ok := requiredString(body, "callbackURL")
	if !ok {
		return contract.Response{}, validation("[body.callbackURL] Invalid input: expected string, received undefined")
	}
	config, exists := p.configs[providerID]
	if !exists {
		return contract.Response{}, apiError(contract.StatusNotFound, "PROVIDER_NOT_FOUND", "Provider not found")
	}
	requestScopes, err := optionalStringSlice(body, "scopes")
	if err != nil {
		return contract.Response{}, err
	}
	errorURL, err := optionalStringField(body, "errorCallbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	authorizationURL := config.AuthorizationURL
	if authorizationURL == "" && config.DiscoveryURL != "" {
		document, discoveryErr := p.providerState[providerID].discovery(ctx.GoContext(), true)
		if discoveryErr != nil {
			if p.runtime.Logger != nil {
				p.runtime.Logger.Error(discoveryErr.Error(), discoveryErr, map[string]any{"discoveryUrl": config.DiscoveryURL})
			}
		} else {
			authorizationURL = document.AuthorizationEndpoint
		}
	}
	if authorizationURL == "" {
		return contract.Response{}, invalidConfiguration()
	}
	userID := recordString(session.User, "id")
	email := recordString(session.User, "email")
	state, err := p.runtime.CreateOAuthState(ctx, singleauth.PluginOAuthStateInput{
		CallbackURL: callbackURL, ErrorURL: errorURL,
		AdditionalData: linkAdditionalData(userID, email),
	})
	if err != nil {
		return contract.Response{}, err
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	scopes := config.Scopes
	if requestScopes != nil {
		scopes = requestScopes
	}
	redirectURI := config.RedirectURI
	if redirectURI == "" {
		redirectURI = strings.TrimRight(baseURL, "/") + "/oauth2/callback/" + url.PathEscape(providerID)
	}
	authorizeURL, err := createAuthorizationURL(
		config, authorizationURL, state.State, state.CodeVerifier, scopes,
		redirectURI, resolveParams(config.AuthorizationURLParams, ctx),
	)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"url": authorizeURL.String(), "redirect": true})
}

func (p *plugin) defaultErrorURL(ctx *engine.Context) (string, error) {
	if p.runtime.ErrorURL != "" {
		return p.runtime.ErrorURL, nil
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return "", err
	}
	return strings.TrimRight(baseURL, "/") + "/error", nil
}

func (p *plugin) clock() (result time.Time) { return p.runtime.Clock() }

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	raw := ctx.Request().Body()
	if len(raw) > maxBodyBytes {
		return nil, validation("Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	object := map[string]any{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return object, nil
	}
	if err := decoder.Decode(&object); err != nil {
		return nil, validation("Invalid JSON body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, validation("Invalid JSON body")
	}
	return object, nil
}

func requiredString(object map[string]any, key string) (string, bool) {
	value, ok := object[key].(string)
	return value, ok && value != ""
}

func optionalStringField(object map[string]any, key string) (string, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return "", nil
	}
	result, ok := value.(string)
	if !ok {
		return "", validation(fmt.Sprintf("[body.%s] Invalid input: expected string", key))
	}
	return result, nil
}

func optionalBoolField(object map[string]any, key string) (bool, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return false, nil
	}
	result, ok := value.(bool)
	if !ok {
		return false, validation(fmt.Sprintf("[body.%s] Invalid input: expected boolean", key))
	}
	return result, nil
}

func optionalBoolPointer(object map[string]any, key string) (*bool, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return nil, nil
	}
	result, ok := value.(bool)
	if !ok {
		return nil, validation(fmt.Sprintf("[body.%s] Invalid input: expected boolean", key))
	}
	return &result, nil
}

func optionalStringSlice(object map[string]any, key string) ([]string, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return nil, nil
	}
	list, ok := value.([]any)
	if !ok {
		if stringsList, ok := value.([]string); ok {
			return append([]string(nil), stringsList...), nil
		}
		return nil, validation(fmt.Sprintf("[body.%s] Invalid input: expected array", key))
	}
	result := make([]string, len(list))
	for index, item := range list {
		stringItem, ok := item.(string)
		if !ok {
			return nil, validation(fmt.Sprintf("[body.%s.%d] Invalid input: expected string", key, index))
		}
		result[index] = stringItem
	}
	return result, nil
}

func optionalObject(object map[string]any, key string) (map[string]any, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return nil, nil
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, validation(fmt.Sprintf("[body.%s] Invalid input: expected object", key))
	}
	return result, nil
}

func validation(message string) *contract.APIError {
	return apiError(422, "VALIDATION_ERROR", message)
}

func conditional(enabled bool, value string) string {
	if enabled {
		return value
	}
	return ""
}

func errorName(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%T", err)
}
