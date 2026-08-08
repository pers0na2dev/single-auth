package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

type oidcSignInInput struct {
	CallbackURL   string
	ErrorURL      string
	NewUserURL    string
	LoginHint     string
	RequestSignUp *bool
	Scopes        []string
}

func (p *plugin) startOIDC(
	ctx *engine.Context,
	provider *resolvedProvider,
	input oidcSignInInput,
) (contract.Response, error) {
	config, err := p.ensureOIDCConfig(ctx, provider)
	if err != nil {
		return contract.Response{}, discoveryAPIError(err)
	}
	additional := map[string]any(nil)
	if strings.TrimSpace(p.options.RedirectURI) != "" {
		additional = map[string]any{"ssoProviderId": provider.ProviderID}
	}
	state, err := p.runtime.CreateOAuthState(ctx, singleauth.PluginOAuthStateInput{
		CallbackURL: input.CallbackURL, ErrorURL: input.ErrorURL,
		NewUserURL: input.NewUserURL, RequestSignUp: input.RequestSignUp,
		AdditionalData: additional,
	})
	if err != nil {
		return contract.Response{}, err
	}
	redirectURI, err := p.oidcRedirectURI(ctx, provider.ProviderID)
	if err != nil {
		return contract.Response{}, err
	}
	scopes := input.Scopes
	if scopes == nil {
		scopes = config.Scopes
	}
	if scopes == nil {
		scopes = []string{"openid", "email", "profile", "offline_access"}
	}
	verifier := ""
	if oidcPKCEEnabled(config) {
		verifier = state.CodeVerifier
	}
	authorizationURL, err := oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
		ID: provider.Issuer,
		Options: oauth2.ProviderOptions{
			ClientID: config.ClientID, ClientSecret: config.ClientSecret,
		},
		AuthorizationEndpoint: config.AuthorizationEndpoint,
		RedirectURI:           redirectURI, State: state.State, CodeVerifier: verifier,
		Scopes: append([]string(nil), scopes...), LoginHint: input.LoginHint,
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"url": authorizationURL.String(), "redirect": true,
	})
}

func (p *plugin) oidcCallback(ctx *engine.Context) (contract.Response, error) {
	providerID, _ := ctx.Param("providerId")
	return p.handleOIDCCallback(ctx, providerID)
}

func (p *plugin) oidcSharedCallback(ctx *engine.Context) (contract.Response, error) {
	return p.handleOIDCCallback(ctx, "")
}

func (p *plugin) handleOIDCCallback(ctx *engine.Context, providerID string) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters")
	}
	defaultErrorURL := p.runtime.OAuthErrorURL(ctx.Request())
	state, err := p.runtime.ConsumeOAuthState(ctx, query.Get("state"))
	if err != nil {
		code := "invalid_state"
		target := defaultErrorURL
		var stateErr *singleauth.PluginOAuthStateError
		if errors.As(err, &stateErr) {
			if stateErr.Code != "" {
				code = stateErr.Code
			}
			if stateErr.ErrorURL != "" {
				target = stateErr.ErrorURL
			}
		}
		return redirectWithQuery(target, map[string]string{"error": code}), nil
	}
	errorURL := firstNonEmpty(state.ErrorURL, state.CallbackURL, defaultErrorURL)
	if providerID == "" {
		providerID, _ = state.AdditionalData["ssoProviderId"].(string)
		if providerID == "" {
			return redirectWithQuery(errorURL, map[string]string{
				"error": "invalid_state", "error_description": "missing_provider_id",
			}), nil
		}
	}
	providerError := query.Get("error")
	code := query.Get("code")
	if providerError != "" || code == "" {
		if providerError == "" {
			providerError = "invalid_provider"
		}
		return redirectWithQuery(errorURL, map[string]string{
			"error": providerError, "error_description": query.Get("error_description"),
		}), nil
	}

	provider, findErr := p.findProvider(ctx, providerID, "")
	if findErr != nil {
		return contract.Response{}, findErr
	}
	if provider == nil || provider.OIDCConfig == nil {
		return redirectWithQuery(errorURL, map[string]string{
			"error": "invalid_provider", "error_description": "provider not found",
		}), nil
	}
	if p.domainVerificationEnabled && !provider.DomainVerified {
		return contract.Response{}, apiError(contract.StatusUnauthorized, "UNAUTHORIZED", "Provider domain has not been verified")
	}
	config, configErr := p.ensureOIDCConfig(ctx, provider)
	if configErr != nil {
		return redirectWithQuery(errorURL, map[string]string{
			"error": "discovery_failed", "error_description": configErr.Error(),
		}), nil
	}
	if config.TokenEndpoint == "" {
		return redirectWithQuery(errorURL, map[string]string{
			"error": "invalid_provider", "error_description": "token_endpoint_not_found",
		}), nil
	}
	redirectURI, redirectErr := p.oidcRedirectURI(ctx, providerID)
	if redirectErr != nil {
		return contract.Response{}, redirectErr
	}
	verifier := ""
	if oidcPKCEEnabled(config) {
		verifier = state.CodeVerifier
	}
	authentication := oauth2.AuthenticationBasic
	if config.TokenEndpointAuthentication == "client_secret_post" {
		authentication = oauth2.AuthenticationPost
	}
	tokenRequest := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{
		Code: code, CodeVerifier: verifier, RedirectURI: redirectURI,
		Options:        oauth2.ProviderOptions{ClientID: config.ClientID, ClientSecret: config.ClientSecret},
		Authentication: authentication,
	})
	client := p.oidcHTTPClient()
	tokenData, exchangeErr := oauth2.DoForm(ctx.GoContext(), client, config.TokenEndpoint, tokenRequest)
	if exchangeErr != nil {
		return redirectWithQuery(errorURL, map[string]string{
			"error": "invalid_provider", "error_description": exchangeErr.Error(),
		}), nil
	}
	tokens := oauth2.NormalizeTokens(tokenData, p.runtime.Clock())

	userInfo, rawProfile, infoErr := p.resolveOIDCUser(ctx.GoContext(), provider, config, tokens)
	if infoErr != nil {
		return redirectWithQuery(errorURL, map[string]string{
			"error": "invalid_provider", "error_description": infoErr.Error(),
		}), nil
	}
	if userInfo.Email == nil || *userInfo.Email == "" || userInfo.ID == "" {
		return redirectWithQuery(errorURL, map[string]string{
			"error": "invalid_provider", "error_description": "missing_user_info",
		}), nil
	}
	email := strings.ToLower(*userInfo.Email)
	userInfo.Email = &email
	trustedProvider := provider.DomainVerified && validateOIDCEmailDomain(email, provider.Domain)
	trustProviderByName := false
	providerDescriptor := &providers.Provider{
		ID: provider.ProviderID, Name: provider.ProviderID,
		Options: providers.Options{OverrideUserInfo: config.OverrideUserInfo},
	}
	disableSignUp := p.options.DisableImplicitSignUp &&
		(state.RequestSignUp == nil || !*state.RequestSignUp)
	result, handleErr := p.runtime.HandleOAuthUser(ctx, singleauth.PluginOAuthUserInput{
		Provider: providerDescriptor, ProviderID: provider.ProviderID,
		User: userInfo, Tokens: tokens, DisableSignUp: disableSignUp,
		CallbackURL: state.CallbackURL, IsTrustedProvider: trustedProvider,
		TrustProviderByName: &trustProviderByName,
	})
	if handleErr != nil {
		if typed, ok := contract.AsAPIError(handleErr); ok {
			return redirectWithQuery(errorURL, map[string]string{
				"error": typed.Code, "error_description": typed.Message,
			}), nil
		}
		return contract.Response{}, handleErr
	}
	if result.LinkError != "" {
		return redirectWithQuery(errorURL, map[string]string{
			"error": strings.ReplaceAll(result.LinkError, " ", "_"),
		}), nil
	}
	if result.State.Session == nil || result.State.User == nil {
		return contract.Response{}, apiError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error")
	}
	providerProfile := resolvedProviderProfile(provider, config)
	if p.options.ProvisionUser != nil && (result.IsRegister || p.options.ProvisionUserOnEveryLogin) {
		if err := p.options.ProvisionUser(ctx.GoContext(), ProvisionUserInput{
			User: cloneRecord(result.State.User), UserInfo: cloneRecord(rawProfile),
			Tokens: tokens, Provider: providerProfile,
		}); err != nil {
			return contract.Response{}, err
		}
	}
	if err := p.assignOrganizationFromProvider(ctx, result.State.User, rawProfile, provider, tokens); err != nil {
		return contract.Response{}, err
	}
	if err := p.runtime.RefreshSession(ctx, result.State, false); err != nil {
		return contract.Response{}, err
	}
	target := state.CallbackURL
	if result.IsRegister && state.NewUserURL != "" {
		target = state.NewUserURL
	}
	return redirectResponse(target), nil
}

func (p *plugin) oidcRedirectURI(ctx *engine.Context, providerID string) (string, error) {
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return "", err
	}
	baseURL = strings.TrimRight(baseURL, "/")
	configured := strings.TrimSpace(p.options.RedirectURI)
	if configured == "" {
		return baseURL + "/sso/callback/" + url.PathEscape(providerID), nil
	}
	if parsed, parseErr := absoluteHTTPURL(configured); parseErr == nil && parsed != nil {
		return parsed.String(), nil
	}
	return baseURL + "/" + strings.TrimLeft(configured, "/"), nil
}

func (p *plugin) resolveOIDCUser(
	ctx context.Context,
	provider *resolvedProvider,
	config OIDCConfig,
	tokens oauth2.Tokens,
) (oauth2.UserInfo, storage.Record, error) {
	var profile storage.Record
	if config.UserInfoEndpoint != "" {
		if tokens.AccessToken == "" {
			return oauth2.UserInfo{}, nil, errors.New("access_token_not_found")
		}
		fetched, err := p.fetchOIDCUserInfo(ctx, config.UserInfoEndpoint, tokens.AccessToken)
		if err != nil {
			return oauth2.UserInfo{}, nil, err
		}
		profile = fetched
	} else if tokens.IDToken != "" {
		if config.JWKSEndpoint == "" {
			return oauth2.UserInfo{}, nil, errors.New("jwks_endpoint_not_found")
		}
		verified, err := oauth2.ValidateToken(ctx, p.oidcHTTPClient(), tokens.IDToken, config.JWKSEndpoint, oauth2.ValidateTokenOptions{
			Audience: []string{config.ClientID}, Issuer: []string{provider.Issuer},
		})
		if err != nil {
			return oauth2.UserInfo{}, nil, errors.New("token_not_verified")
		}
		profile = storage.Record(verified.Payload)
	} else {
		return oauth2.UserInfo{}, nil, errors.New("user_info_endpoint_not_found")
	}
	return mapOIDCProfile(profile, config.Mapping, p.options.TrustEmailVerified), cloneRecord(profile), nil
}

func (p *plugin) fetchOIDCUserInfo(ctx context.Context, endpoint, accessToken string) (storage.Record, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	response, err := oauth2.DoRefusingRedirects(p.oidcHTTPClient(), request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxOIDCResponseBytes {
		return nil, errors.New("userinfo_response_too_large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo endpoint returned %d", response.StatusCode)
	}
	profile := storage.Record{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&profile); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("userinfo endpoint returned invalid JSON")
	}
	return profile, nil
}

func (p *plugin) oidcHTTPClient() *http.Client {
	if p.options.OIDC.HTTPClient != nil {
		return p.options.OIDC.HTTPClient
	}
	return http.DefaultClient
}

func mapOIDCProfile(profile storage.Record, mapping OIDCMapping, trustEmailVerified bool) oauth2.UserInfo {
	idClaim := firstNonEmpty(mapping.ID, "sub")
	emailClaim := firstNonEmpty(mapping.Email, "email")
	verifiedClaim := firstNonEmpty(mapping.EmailVerified, "email_verified")
	nameClaim := firstNonEmpty(mapping.Name, "name")
	imageClaim := firstNonEmpty(mapping.Image, "picture")
	email := oidcString(profile[emailClaim])
	extra := make(map[string]any, len(mapping.ExtraFields))
	for target, claim := range mapping.ExtraFields {
		extra[target] = profile[claim]
	}
	return oauth2.UserInfo{
		ID: oidcString(profile[idClaim]), Name: oidcString(profile[nameClaim]),
		Email: oidcStringPointer(email), Image: oidcString(profile[imageClaim]),
		EmailVerified: trustEmailVerified && parseOIDCEmailVerified(profile[verifiedClaim]),
		Extra:         extra,
	}
}

func parseOIDCEmailVerified(value any) bool {
	if verified, ok := value.(bool); ok {
		return verified
	}
	verified, _ := value.(string)
	return verified == "true"
}

func validateOIDCEmailDomain(email, domains string) bool {
	parts := strings.Split(email, "@")
	return len(parts) > 1 && domainMatches(parts[len(parts)-1], domains)
}

func oidcString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return ""
	}
}

func oidcStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func resolvedProviderProfile(provider *resolvedProvider, config OIDCConfig) SSOProviderProfile {
	return SSOProviderProfile{
		ProviderID: provider.ProviderID, Issuer: provider.Issuer,
		Domain: provider.Domain, OrganizationID: provider.OrganizationID,
		DomainVerified: provider.DomainVerified, OIDCConfig: cloneOIDCConfig(&config),
		SAMLConfig: provider.SAMLConfig,
	}
}

func (p *plugin) assignOrganizationFromProvider(
	ctx *engine.Context,
	user storage.Record,
	userInfo storage.Record,
	provider *resolvedProvider,
	tokens oauth2.Tokens,
) error {
	if provider == nil {
		return nil
	}
	userID := recordStringValue(user, "id")
	tokenCopy := tokens
	return AssignOrganizationFromProvider(ctx.GoContext(), OrganizationAssignmentContext{
		Adapter: p.adapter(ctx), HasPlugin: p.runtime.HasPlugin, Clock: p.runtime.Clock,
	}, AssignOrganizationFromProviderOptions{
		User: OrganizationAssignmentUser{
			ID: userID, Email: recordStringValue(user, "email"), Fields: cloneRecord(user),
		},
		UserInfo: cloneRecord(userInfo), Provider: providerStorageRecord(provider),
		Tokens: &tokenCopy, Provisioning: p.options.OrganizationProvisioning,
	})
}

func providerStorageRecord(provider *resolvedProvider) storage.Record {
	if provider == nil {
		return nil
	}
	return storage.Record{
		"providerId": provider.ProviderID, "issuer": provider.Issuer,
		"domain": provider.Domain, "organizationId": provider.OrganizationID,
		"domainVerified": provider.DomainVerified,
	}
}

func optionalBoolPointer(object map[string]any, key string) (*bool, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return nil, nil
	}
	result, ok := value.(bool)
	if !ok {
		return nil, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid "+key)
	}
	return &result, nil
}

func optionalStringSlice(object map[string]any, key string) ([]string, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return nil, nil
	}
	if values, ok := value.([]string); ok {
		return append([]string(nil), values...), nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid "+key)
	}
	result := make([]string, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid "+key)
		}
		result[index] = text
	}
	return result, nil
}
