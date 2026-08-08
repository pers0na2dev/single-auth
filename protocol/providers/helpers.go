package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

func providerOptions(options Options) oauth2.ProviderOptions {
	return oauth2.ProviderOptions{
		ClientID:              options.ClientID,
		ClientSecret:          options.ClientSecret,
		ClientKey:             options.ClientKey,
		Scopes:                cloneStrings(options.Scopes),
		DisableDefaultScope:   options.DisableDefaultScope,
		RedirectURI:           options.RedirectURI,
		AuthorizationEndpoint: options.AuthorizationEndpoint,
		DisableIDTokenSignIn:  options.DisableIDTokenSignIn,
		DisableImplicitSignUp: options.DisableImplicitSignUp,
		DisableSignUp:         options.DisableSignUp,
		Prompt:                options.Prompt,
		ResponseMode:          options.ResponseMode,
		OverrideUserInfo:      options.OverrideUserInfo,
	}
}

func combinedScopes(options Options, defaults, request []string, requestFirst bool) []string {
	scopes := make([]string, 0, len(defaults)+len(options.Scopes)+len(request))
	if !options.DisableDefaultScope {
		scopes = append(scopes, defaults...)
	}
	if requestFirst {
		scopes = append(scopes, request...)
		scopes = append(scopes, options.Scopes...)
	} else {
		scopes = append(scopes, options.Scopes...)
		scopes = append(scopes, request...)
	}
	return scopes
}

func cloneStrings(values []string) []string { return append([]string(nil), values...) }

func addParams(values ...string) []oauth2.Param {
	params := make([]oauth2.Param, 0, len(values)/2)
	for index := 0; index+1 < len(values); index += 2 {
		if values[index+1] != "" {
			params = append(params, oauth2.Param{Name: values[index], Value: values[index+1]})
		}
	}
	return params
}

func createURL(id string, options Options, endpoint string, defaults []string, input AuthorizationInput, configure func(*oauth2.AuthorizationURLOptions)) (*url.URL, error) {
	args := oauth2.AuthorizationURLOptions{
		ID:                    id,
		Options:               providerOptions(options),
		AuthorizationEndpoint: endpoint,
		RedirectURI:           input.RedirectURI,
		State:                 input.State,
		CodeVerifier:          input.CodeVerifier,
		Scopes:                combinedScopes(options, defaults, input.Scopes, false),
	}
	if configure != nil {
		configure(&args)
	}
	return oauth2.CreateAuthorizationURL(args)
}

type exchangeConfig struct {
	options   oauth2.ProviderOptions
	headers   map[string]string
	params    []oauth2.Param
	resources []string
}

type exchangeOption func(*exchangeConfig)

func withExchangeOptions(options oauth2.ProviderOptions) exchangeOption {
	return func(config *exchangeConfig) { config.options = options }
}

func withExchangeHeaders(headers map[string]string) exchangeOption {
	return func(config *exchangeConfig) { config.headers = headers }
}

func withExchangeParams(params ...oauth2.Param) exchangeOption {
	return func(config *exchangeConfig) { config.params = params }
}

func exchange(ctx context.Context, provider *Provider, input CodeInput, authentication oauth2.Authentication, options ...exchangeOption) (*oauth2.Tokens, error) {
	configuration := exchangeConfig{options: providerOptions(provider.Options)}
	for _, option := range options {
		option(&configuration)
	}
	request := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{
		Code:             input.Code,
		CodeVerifier:     input.CodeVerifier,
		RedirectURI:      input.RedirectURI,
		Options:          configuration.options,
		Authentication:   authentication,
		DeviceID:         input.DeviceID,
		Headers:          configuration.headers,
		AdditionalParams: configuration.params,
		Resources:        configuration.resources,
	})
	data, err := oauth2.DoForm(ctx, provider.clientFor(ctx), provider.Metadata.TokenEndpoint, request)
	if err != nil {
		return nil, err
	}
	tokens := oauth2.NormalizeTokens(data, time.Now())
	return &tokens, nil
}

func refresh(ctx context.Context, provider *Provider, token string, authentication oauth2.Authentication, options oauth2.ProviderOptions, extra ...oauth2.Param) (oauth2.Tokens, error) {
	request := oauth2.CreateRefreshAccessTokenRequest(oauth2.RefreshTokenRequestOptions{
		RefreshToken:   token,
		Options:        options,
		Authentication: authentication,
		ExtraParams:    extra,
	})
	data, err := oauth2.DoForm(ctx, provider.clientFor(ctx), provider.Metadata.TokenEndpoint, request)
	if err != nil {
		return oauth2.Tokens{}, err
	}
	return normalizeRefreshTokens(data, time.Now()), nil
}

// normalizeRefreshTokens mirrors the reference implementation's refreshAccessToken helper. The
// refresh helper deliberately constructs a new token object instead of keeping
// the provider response under Raw (authorization-code exchange does keep it).
func normalizeRefreshTokens(data map[string]any, now time.Time) oauth2.Tokens {
	tokens := oauth2.Tokens{
		TokenType:    stringValue(data["token_type"]),
		AccessToken:  stringValue(data["access_token"]),
		RefreshToken: stringValue(data["refresh_token"]),
		IDToken:      stringValue(data["id_token"]),
	}
	if scopes, ok := data["scope"].(string); ok {
		tokens.Scopes = strings.Split(scopes, " ")
	}
	if seconds, err := strconv.ParseFloat(stringValue(data["expires_in"]), 64); err == nil && seconds != 0 {
		expires := now.Add(time.Duration(seconds * float64(time.Second)))
		tokens.AccessTokenExpiresAt = &expires
	}
	if seconds, err := strconv.ParseFloat(stringValue(data["refresh_token_expires_in"]), 64); err == nil && seconds != 0 {
		expires := now.Add(time.Duration(seconds * float64(time.Second)))
		tokens.RefreshTokenExpiresAt = &expires
	}
	return tokens
}

func defaultRefresh(provider *Provider, authentication oauth2.Authentication, extra ...oauth2.Param) func(context.Context, string) (oauth2.Tokens, error) {
	return func(ctx context.Context, token string) (oauth2.Tokens, error) {
		options := providerOptions(provider.Options)
		return refresh(ctx, provider, token, authentication, options, extra...)
	}
}

func doJSON(ctx context.Context, client *http.Client, method, endpoint string, headers map[string]string, body io.Reader, output any) error {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
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
	if response.StatusCode >= 300 && response.StatusCode <= 399 {
		return fmt.Errorf("%w: %q; configure the final endpoint URL", oauth2.ErrOAuthRedirect, endpoint)
	}
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("provider endpoint %q returned %d: %s", endpoint, response.StatusCode, strings.TrimSpace(string(raw)))
	}
	if output == nil || len(raw) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(output)
}

func doFormFollowingRedirects(ctx context.Context, client *http.Client, endpoint string, request oauth2.FormRequest) (map[string]any, error) {
	return doFormJSON(ctx, client, endpoint, request)
}

func doFormJSON(ctx context.Context, client *http.Client, endpoint string, request oauth2.FormRequest) (map[string]any, error) {
	data := map[string]any{}
	err := doJSON(ctx, client, http.MethodPost, endpoint, request.Headers, strings.NewReader(request.Body.Encode()), &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func fetchProfile(ctx context.Context, provider *Provider, method, endpoint string, headers map[string]string, body io.Reader) (map[string]any, error) {
	profile := make(map[string]any)
	if err := doJSON(ctx, provider.clientFor(ctx), method, endpoint, headers, body, &profile); err != nil {
		return nil, err
	}
	return profile, nil
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
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
	default:
		return ""
	}
}

func boolValue(value any) bool {
	valueAsBool, _ := value.(bool)
	return valueAsBool
}

func object(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func array(value any) []any {
	result, _ := value.([]any)
	return result
}

func at(profile map[string]any, keys ...string) any {
	var current any = profile
	for _, key := range keys {
		mapped, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = mapped[key]
	}
	return current
}

func emailPointer(value any) *string {
	if value == nil {
		return nil
	}
	text, ok := value.(string)
	if !ok {
		return nil
	}
	return &text
}

func mappedUser(ctx context.Context, provider *Provider, profile map[string]any, id, name string, email any, image string, verified bool) (oauth2.UserInfo, error) {
	user := oauth2.UserInfo{ID: id, Name: name, Email: emailPointer(email), Image: image, EmailVerified: verified, Extra: map[string]any{}}
	if provider.Options.MapProfileToUser == nil {
		return user, nil
	}
	mapped, err := provider.Options.MapProfileToUser(ctx, profile)
	if err != nil {
		return oauth2.UserInfo{}, err
	}
	applyUserMap(&user, mapped)
	return user, nil
}

func applyUserMap(user *oauth2.UserInfo, mapped map[string]any) {
	for key, value := range mapped {
		switch key {
		case "id":
			user.ID = stringValue(value)
		case "name":
			if value == nil {
				user.Name = ""
			} else {
				user.Name = stringValue(value)
			}
		case "email":
			user.Email = emailPointer(value)
		case "image":
			user.Image = stringValue(value)
		case "emailVerified":
			user.EmailVerified = boolValue(value)
		default:
			if user.Extra == nil {
				user.Extra = map[string]any{}
			}
			user.Extra[key] = value
		}
	}
}

func result(ctx context.Context, provider *Provider, profile map[string]any, id, name string, email any, image string, verified bool) (*UserInfoResult, error) {
	user, err := mappedUser(ctx, provider, profile, id, name, email, image, verified)
	if err != nil {
		return nil, err
	}
	return &UserInfoResult{User: user, Data: profile}, nil
}

func resultOrNilOnFetchError(ctx context.Context, provider *Provider, method, endpoint string, headers map[string]string, body io.Reader, mapper func(map[string]any) (*UserInfoResult, error)) (*UserInfoResult, error) {
	profile, err := fetchProfile(ctx, provider, method, endpoint, headers, body)
	if err != nil {
		return nil, nil
	}
	return mapper(profile)
}

func decodeJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errorsInternal("JWT must have three parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func errorsInternal(message string) error { return fmt.Errorf("providers: %s", message) }

func discordDefaultAvatar(id, discriminator string) string {
	number := int64(0)
	if discriminator == "0" {
		integer := new(big.Int)
		if _, ok := integer.SetString(id, 10); ok {
			integer.Rsh(integer, 22)
			number = new(big.Int).Mod(integer, big.NewInt(6)).Int64()
		}
	} else {
		parsed, _ := strconv.ParseInt(discriminator, 10, 64)
		number = parsed % 5
	}
	return fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", number)
}

func primaryClientID(value any) string {
	primary, _ := oauth2.PrimaryClientID(value)
	return primary
}

func clientIDs(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return cloneStrings(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
		return values
	default:
		return nil
	}
}

func encodeURIComponent(value string) string {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune("-_.!~*'()", rune(b)) {
			builder.WriteByte(b)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(hex[b>>4])
		builder.WriteByte(hex[b&15])
	}
	return builder.String()
}
