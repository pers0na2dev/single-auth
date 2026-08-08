package genericoauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

type providerRuntime struct {
	config Config
	clock  func() time.Time
	client *http.Client

	mu               sync.RWMutex
	finalUserInfoURL string
}

func newProvider(config Config, runtime Runtime) (*providers.Provider, *providerRuntime, error) {
	clock := runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	client := config.HTTPClient
	if client == nil {
		client = runtime.HTTPClient
	}
	if client == nil {
		client = http.DefaultClient
	}
	state := &providerRuntime{
		config:           config,
		clock:            clock,
		client:           client,
		finalUserInfoURL: config.UserInfoURL,
	}
	providerOptions := providers.Options{
		ClientID: config.ClientID, ClientSecret: config.ClientSecret,
		Scopes: append([]string(nil), config.Scopes...), RedirectURI: config.RedirectURI,
		DisableImplicitSignUp: config.DisableImplicitSignUp,
		DisableSignUp:         config.DisableSignUp,
		OverrideUserInfo:      config.OverrideUserInfo,
		HTTPClient:            client,
	}
	metadata := providers.Metadata{
		AuthorizationEndpoint: config.AuthorizationURL,
		TokenEndpoint:         config.TokenURL,
		UserInfoEndpoint:      config.UserInfoURL,
		DefaultScopes:         append([]string(nil), config.Scopes...),
		TokenAuthentication:   authentication(config.Authentication),
	}
	custom := providers.CustomProvider{
		ID: config.ProviderID, Name: config.ProviderID,
		Options: providerOptions, Metadata: metadata,
		CreateAuthorizationURL: func(input providers.AuthorizationInput) (*url.URL, error) {
			document, err := state.discovery(context.Background(), config.AuthorizationURL == "")
			if err != nil {
				return nil, err
			}
			authorizationURL := config.AuthorizationURL
			if authorizationURL == "" {
				authorizationURL = document.AuthorizationEndpoint
			}
			if document.UserInfoEndpoint != "" && state.userInfoURL() == "" {
				state.setUserInfoURL(document.UserInfoEndpoint)
			}
			if authorizationURL == "" {
				return nil, invalidConfiguration()
			}
			redirectURI := input.RedirectURI
			if runtime.BaseURL != "" {
				redirectURI = strings.TrimRight(runtime.BaseURL, "/") + normalizeBasePath(runtime.BasePath) + "/oauth2/callback/" + url.PathEscape(config.ProviderID)
			}
			return createAuthorizationURL(config, authorizationURL, input.State, input.CodeVerifier, config.Scopes, redirectURI, nil)
		},
		ValidateAuthorizationCode: func(ctx context.Context, input providers.CodeInput) (*oauth2.Tokens, error) {
			if config.GetToken != nil {
				tokens, err := config.GetToken(ctx, TokenRequest{
					Code: input.Code, RedirectURI: input.RedirectURI,
					CodeVerifier: input.CodeVerifier, DeviceID: input.DeviceID,
				})
				if err != nil {
					return nil, err
				}
				tokens = oauth2.ApplyDefaultAccessTokenExpiry(tokens, config.AccessTokenExpiresIn, state.clock())
				return &tokens, nil
			}
			document, err := state.discovery(ctx, config.DiscoveryURL != "")
			if err != nil {
				return nil, err
			}
			tokenURL := config.TokenURL
			if document.TokenEndpoint != "" {
				tokenURL = document.TokenEndpoint
			}
			if document.UserInfoEndpoint != "" {
				state.setUserInfoURL(document.UserInfoEndpoint)
			}
			if tokenURL == "" {
				return nil, apiError(http.StatusBadRequest, ErrorTokenURLNotFound, ErrorMessages[ErrorTokenURLNotFound])
			}
			tokens, err := exchangeAuthorizationCode(ctx, state.client, state.clock, config, tokenURL, TokenRequest{
				Code: input.Code, RedirectURI: input.RedirectURI,
				CodeVerifier: input.CodeVerifier, DeviceID: input.DeviceID,
			}, nil)
			if err != nil {
				return nil, err
			}
			return &tokens, nil
		},
		RefreshAccessToken: func(ctx context.Context, refreshToken string) (oauth2.Tokens, error) {
			document, err := state.discovery(ctx, config.DiscoveryURL != "")
			if err != nil {
				return oauth2.Tokens{}, err
			}
			tokenURL := config.TokenURL
			if document.TokenEndpoint != "" {
				tokenURL = document.TokenEndpoint
			}
			if tokenURL == "" {
				return oauth2.Tokens{}, apiError(http.StatusBadRequest, ErrorTokenURLNotFound, ErrorMessages[ErrorTokenURLNotFound])
			}
			return exchangeRefreshToken(ctx, state.client, state.clock, config, tokenURL, refreshToken)
		},
		GetUserInfo: func(ctx context.Context, tokens oauth2.Tokens, _ *providers.AuthorizationUser) (*providers.UserInfoResult, error) {
			profile, err := state.getProfile(ctx, tokens, state.userInfoURL())
			if err != nil || profile == nil {
				return nil, err
			}
			mapped, err := state.mapProfile(ctx, profile)
			if err != nil {
				return nil, err
			}
			info, ok := resolveProfile(profile, mapped)
			if !ok {
				return nil, nil
			}
			return &providers.UserInfoResult{User: info, Data: cloneProfile(profile)}, nil
		},
	}
	provider, err := providers.NewCustomProvider(custom)
	if err != nil {
		return nil, nil, err
	}
	return provider, state, nil
}

func (state *providerRuntime) discovery(ctx context.Context, fetch bool) (discoveryDocument, error) {
	if !fetch || state.config.DiscoveryURL == "" {
		return discoveryDocument{}, nil
	}
	var document discoveryDocument
	if err := fetchJSON(ctx, state.client, state.config.DiscoveryURL, state.config.DiscoveryHeaders, &document); err != nil {
		return discoveryDocument{}, err
	}
	return document, nil
}

func (state *providerRuntime) userInfoURL() string {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.finalUserInfoURL
}

func (state *providerRuntime) setUserInfoURL(value string) {
	state.mu.Lock()
	state.finalUserInfoURL = value
	state.mu.Unlock()
}

func (state *providerRuntime) getProfile(ctx context.Context, tokens oauth2.Tokens, userInfoURL string) (Profile, error) {
	if state.config.GetUserInfo != nil {
		profile, err := state.config.GetUserInfo(ctx, tokens)
		return cloneProfile(profile), err
	}
	return getUserInfo(ctx, state.client, tokens, userInfoURL)
}

func (state *providerRuntime) mapProfile(ctx context.Context, profile Profile) (Profile, error) {
	if state.config.MapProfileToUser == nil {
		return cloneProfile(profile), nil
	}
	mapped, err := state.config.MapProfileToUser(ctx, cloneProfile(profile))
	return cloneProfile(mapped), err
}

func createAuthorizationURL(
	config Config,
	endpoint, state, verifier string,
	scopes []string,
	redirectURI string,
	params map[string]string,
) (*url.URL, error) {
	codeVerifier := ""
	if config.PKCE {
		codeVerifier = verifier
	}
	return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
		ID: config.ProviderID,
		Options: oauth2.ProviderOptions{
			ClientID: config.ClientID, ClientSecret: config.ClientSecret,
			RedirectURI: config.RedirectURI,
		},
		AuthorizationEndpoint: endpoint,
		State:                 state, CodeVerifier: codeVerifier,
		Scopes: append([]string(nil), scopes...), RedirectURI: redirectURI,
		Prompt: config.Prompt, AccessType: config.AccessType,
		ResponseType: config.ResponseType, ResponseMode: config.ResponseMode,
		AdditionalParams: orderedParams(params),
	})
}

func exchangeAuthorizationCode(
	ctx context.Context,
	client *http.Client,
	clock func() time.Time,
	config Config,
	tokenURL string,
	input TokenRequest,
	params map[string]string,
) (oauth2.Tokens, error) {
	request := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{
		Code: input.Code, CodeVerifier: input.CodeVerifier,
		RedirectURI: input.RedirectURI, DeviceID: input.DeviceID,
		Options: oauth2.ProviderOptions{
			ClientID: config.ClientID, ClientSecret: config.ClientSecret,
			RedirectURI: config.RedirectURI,
		},
		Authentication:   authentication(config.Authentication),
		Headers:          cloneStringMap(config.AuthorizationHeaders),
		AdditionalParams: orderedParams(params),
	})
	data, err := oauth2.DoForm(ctx, client, tokenURL, request)
	if err != nil {
		return oauth2.Tokens{}, err
	}
	tokens := oauth2.NormalizeTokens(data, clock())
	return oauth2.ApplyDefaultAccessTokenExpiry(tokens, config.AccessTokenExpiresIn, clock()), nil
}

func exchangeRefreshToken(
	ctx context.Context,
	client *http.Client,
	clock func() time.Time,
	config Config,
	tokenURL, refreshToken string,
) (oauth2.Tokens, error) {
	request := oauth2.CreateRefreshAccessTokenRequest(oauth2.RefreshTokenRequestOptions{
		RefreshToken:   refreshToken,
		Options:        oauth2.ProviderOptions{ClientID: config.ClientID, ClientSecret: config.ClientSecret},
		Authentication: authentication(config.Authentication),
	})
	data, err := oauth2.DoForm(ctx, client, tokenURL, request)
	if err != nil {
		return oauth2.Tokens{}, err
	}
	tokens := oauth2.NormalizeTokens(data, clock())
	tokens.Raw = nil
	return oauth2.ApplyDefaultAccessTokenExpiry(tokens, config.AccessTokenExpiresIn, clock()), nil
}

func getUserInfo(ctx context.Context, client *http.Client, tokens oauth2.Tokens, endpoint string) (Profile, error) {
	if tokens.IDToken != "" {
		if payload, err := decodeJWTPayload(tokens.IDToken); err == nil && nonEmptyID(payload["sub"]) && stringValue(payload["email"]) != "" {
			profile := cloneProfile(payload)
			profile["id"] = payload["sub"]
			profile["emailVerified"] = boolValue(payload["email_verified"])
			profile["image"] = stringValue(payload["picture"])
			return profile, nil
		}
	}
	if endpoint == "" {
		return nil, nil
	}
	profile := Profile{}
	if err := fetchJSON(ctx, client, endpoint, map[string]string{"Authorization": "Bearer " + tokens.AccessToken}, &profile); err != nil {
		return nil, nil
	}
	resolved := cloneProfile(profile)
	if nonEmptyID(profile["id"]) {
		resolved["id"] = profile["id"]
	} else if nonEmptyID(profile["sub"]) {
		resolved["id"] = profile["sub"]
	} else {
		delete(resolved, "id")
	}
	resolved["email"] = stringValue(profile["email"])
	resolved["emailVerified"] = boolValue(profile["email_verified"])
	resolved["image"] = stringValue(profile["picture"])
	resolved["name"] = stringValue(profile["name"])
	return resolved, nil
}

func resolveProfile(profile, mapped Profile) (oauth2.UserInfo, bool) {
	rawID := mapped["id"]
	if !nonEmptyID(rawID) {
		rawID = profile["id"]
	}
	if !nonEmptyID(rawID) {
		rawID = profile["sub"]
	}
	hasID := nonEmptyID(rawID)
	email := stringValue(mapped["email"])
	if email == "" {
		email = stringValue(profile["email"])
	}
	name := stringValue(mapped["name"])
	if name == "" {
		name = stringValue(profile["name"])
	}
	image := stringValue(profile["image"])
	if value, exists := mapped["image"]; exists {
		image = stringValue(value)
	}
	verified := boolValue(profile["emailVerified"])
	if value, exists := mapped["emailVerified"]; exists {
		verified = boolValue(value)
	}
	extra := cloneProfile(profile)
	for key, value := range mapped {
		extra[key] = value
	}
	return oauth2.UserInfo{
		ID: stringValue(rawID), Name: name, Email: stringPointer(email), Image: image,
		EmailVerified: verified, Extra: extra,
	}, hasID
}

func decodeJWTPayload(token string) (Profile, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	profile := Profile{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&profile); err != nil {
		return nil, err
	}
	return profile, nil
}

func fetchJSON(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("OAuth endpoint %q returned %d: %s", endpoint, response.StatusCode, strings.TrimSpace(string(raw)))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return nil
}

func authentication(value oauth2.Authentication) oauth2.Authentication {
	if value == oauth2.AuthenticationBasic {
		return value
	}
	return oauth2.AuthenticationPost
}

func orderedParams(values map[string]string) []oauth2.Param {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	params := make([]oauth2.Param, 0, len(keys))
	for _, key := range keys {
		params = append(params, oauth2.Param{Name: key, Value: values[key]})
	}
	return params
}

func resolveParams(source ParamSource, ctx *engine.Context) map[string]string {
	if source.Resolve != nil {
		return cloneStringMap(source.Resolve(ctx))
	}
	return cloneStringMap(source.Static)
}

func cloneProfile(value Profile) Profile {
	if value == nil {
		return nil
	}
	result := make(Profile, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 32)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case uint:
		return strconv.FormatUint(uint64(typed), 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	default:
		return ""
	}
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func nonEmptyID(value any) bool {
	return value != nil && stringValue(value) != ""
}

func normalizeBasePath(value string) string {
	if value == "" {
		return "/api/auth"
	}
	if value == "/" {
		return ""
	}
	return "/" + strings.Trim(value, "/")
}
