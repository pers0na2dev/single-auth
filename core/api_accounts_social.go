package core

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/model"
)

type ListedAccount struct {
	Account model.Account
	Scopes  []string
}

type ListUserAccountsInput struct{ Headers contract.Headers }

type ListUserAccountsResult struct {
	Accounts []ListedAccount
	Headers  contract.Headers
}

func (api DirectAPI) ListUserAccounts(
	ctx context.Context,
	input ListUserAccountsInput,
) (ListUserAccountsResult, error) {
	response, value, err := api.invokeJSON(ctx, "listUserAccounts", http.MethodGet, input.Headers, nil)
	if err != nil {
		return ListUserAccountsResult{}, err
	}
	items, ok := value.([]any)
	if !ok {
		return ListUserAccountsResult{}, unexpectedDirectResult("listUserAccounts")
	}
	accounts := make([]ListedAccount, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return ListUserAccountsResult{}, unexpectedDirectResult("listUserAccounts item")
		}
		scopes, err := directStringSlice(object["scopes"])
		if err != nil {
			return ListUserAccountsResult{}, unexpectedDirectResult("listUserAccounts.scopes")
		}
		accounts = append(accounts, ListedAccount{Account: decodeAccount(object), Scopes: scopes})
	}
	return ListUserAccountsResult{Accounts: accounts, Headers: response.Headers()}, nil
}

type UnlinkAccountInput struct {
	ProviderID string
	AccountID  string
	Headers    contract.Headers
}

func (api DirectAPI) UnlinkAccount(ctx context.Context, input UnlinkAccountInput) (StatusResult, error) {
	body := map[string]any{"providerId": input.ProviderID}
	if input.AccountID != "" {
		body["accountId"] = input.AccountID
	}
	return api.statusCall(ctx, "unlinkAccount", input.Headers, body)
}

type SocialIDTokenInput struct {
	Token        string
	AccessToken  string
	RefreshToken string
	Nonce        string
	ExpiresAt    *float64
	Scopes       []string
	User         map[string]any
}

func (input SocialIDTokenInput) body() map[string]any {
	result := map[string]any{"token": input.Token}
	if input.AccessToken != "" {
		result["accessToken"] = input.AccessToken
	}
	if input.RefreshToken != "" {
		result["refreshToken"] = input.RefreshToken
	}
	if input.Nonce != "" {
		result["nonce"] = input.Nonce
	}
	if input.ExpiresAt != nil {
		result["expiresAt"] = *input.ExpiresAt
	}
	if input.Scopes != nil {
		result["scopes"] = append([]string(nil), input.Scopes...)
	}
	if input.User != nil {
		result["user"] = input.User
	}
	return result
}

type SignInSocialInput struct {
	Provider           string
	CallbackURL        string
	ErrorCallbackURL   string
	NewUserCallbackURL string
	DisableRedirect    *bool
	RequestSignUp      *bool
	Scopes             []string
	LoginHint          string
	IDToken            *SocialIDTokenInput
	AdditionalData     map[string]any
	Headers            contract.Headers
}

type SignInSocialResult struct {
	URL      model.Value[string]
	Redirect bool
	Token    *string
	User     *model.User
	Headers  contract.Headers
}

func (api DirectAPI) SignInSocial(ctx context.Context, input SignInSocialInput) (SignInSocialResult, error) {
	body := socialBody(input.Provider, input.CallbackURL, input.ErrorCallbackURL,
		input.NewUserCallbackURL, input.DisableRedirect, input.Scopes)
	if input.RequestSignUp != nil {
		body["requestSignUp"] = *input.RequestSignUp
	}
	if input.LoginHint != "" {
		body["loginHint"] = input.LoginHint
	}
	if input.IDToken != nil {
		body["idToken"] = input.IDToken.body()
	}
	if input.AdditionalData != nil {
		body["additionalData"] = input.AdditionalData
	}
	response, value, err := api.invokeJSON(ctx, "signInSocial", http.MethodPost, input.Headers, body)
	if err != nil {
		return SignInSocialResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return SignInSocialResult{}, unexpectedDirectResult("signInSocial")
	}
	result := SignInSocialResult{Headers: response.Headers()}
	result.Redirect, _ = object["redirect"].(bool)
	if raw, exists := object["url"]; exists {
		if raw == nil {
			result.URL = model.Null[string]()
		} else if text, ok := raw.(string); ok {
			result.URL = model.Present(text)
		} else {
			return SignInSocialResult{}, unexpectedDirectResult("signInSocial.url")
		}
	}
	if raw, exists := object["token"]; exists && raw != nil {
		text, ok := raw.(string)
		if !ok {
			return SignInSocialResult{}, unexpectedDirectResult("signInSocial.token")
		}
		result.Token = &text
	}
	if raw, exists := object["user"]; exists && raw != nil {
		user, ok := raw.(map[string]any)
		if !ok {
			return SignInSocialResult{}, unexpectedDirectResult("signInSocial.user")
		}
		decoded := api.decodeUser(user)
		result.User = &decoded
	}
	return result, nil
}

type LinkSocialAccountInput struct {
	Provider           string
	CallbackURL        string
	ErrorCallbackURL   string
	NewUserCallbackURL string
	DisableRedirect    *bool
	RequestSignUp      *bool
	Scopes             []string
	IDToken            *SocialIDTokenInput
	AdditionalData     map[string]any
	Headers            contract.Headers
}

type LinkSocialAccountResult struct {
	URL      string
	Status   bool
	Redirect bool
	Headers  contract.Headers
}

func (api DirectAPI) LinkSocialAccount(
	ctx context.Context,
	input LinkSocialAccountInput,
) (LinkSocialAccountResult, error) {
	body := socialBody(input.Provider, input.CallbackURL, input.ErrorCallbackURL,
		input.NewUserCallbackURL, input.DisableRedirect, input.Scopes)
	if input.IDToken != nil {
		body["idToken"] = input.IDToken.body()
	}
	if input.RequestSignUp != nil {
		body["requestSignUp"] = *input.RequestSignUp
	}
	if input.AdditionalData != nil {
		body["additionalData"] = input.AdditionalData
	}
	response, value, err := api.invokeJSON(ctx, "linkSocialAccount", http.MethodPost, input.Headers, body)
	if err != nil {
		return LinkSocialAccountResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return LinkSocialAccountResult{}, unexpectedDirectResult("linkSocialAccount")
	}
	result := LinkSocialAccountResult{Headers: response.Headers()}
	result.URL, _ = object["url"].(string)
	result.Status, _ = object["status"].(bool)
	result.Redirect, _ = object["redirect"].(bool)
	return result, nil
}

func socialBody(
	provider, callbackURL, errorCallbackURL, newUserCallbackURL string,
	disableRedirect *bool,
	scopes []string,
) map[string]any {
	body := map[string]any{"provider": provider}
	if callbackURL != "" {
		body["callbackURL"] = callbackURL
	}
	if errorCallbackURL != "" {
		body["errorCallbackURL"] = errorCallbackURL
	}
	if newUserCallbackURL != "" {
		body["newUserCallbackURL"] = newUserCallbackURL
	}
	if disableRedirect != nil {
		body["disableRedirect"] = *disableRedirect
	}
	if scopes != nil {
		body["scopes"] = append([]string(nil), scopes...)
	}
	return body
}

type OAuthCallbackInput struct {
	ProviderID string
	Method     string
	Query      url.Values
	Body       map[string]any
	Headers    contract.Headers
}

func (api DirectAPI) CallbackOAuth(ctx context.Context, input OAuthCallbackInput) (RedirectResult, error) {
	method := input.Method
	if method == "" {
		method = http.MethodGet
	}
	call, err := api.Call(ctx, "callbackOAuth", DirectCallInput{
		Method: method, Headers: input.Headers, Query: input.Query, Body: input.Body,
		Params: map[string]string{"id": input.ProviderID},
	})
	if err != nil {
		return RedirectResult{}, err
	}
	location, _ := call.Response.Headers().Get("Location")
	return RedirectResult{Location: location, Headers: call.Response.Headers()}, nil
}

type AccountTokenInput struct {
	ProviderID string
	AccountID  string
	// UserID is accepted only by direct server calls without session headers.
	UserID  string
	Headers contract.Headers
}

type AccessTokenResult struct {
	AccessToken          string
	AccessTokenExpiresAt *time.Time
	Scopes               []string
	IDToken              string
	Headers              contract.Headers
}

func (api DirectAPI) GetAccessToken(ctx context.Context, input AccountTokenInput) (AccessTokenResult, error) {
	body := accountTokenBody(input)
	response, value, err := api.invokeJSON(ctx, "getAccessToken", http.MethodPost, input.Headers, body)
	if err != nil {
		return AccessTokenResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return AccessTokenResult{}, unexpectedDirectResult("getAccessToken")
	}
	result, err := decodeAccessTokenResult(object)
	if err != nil {
		return AccessTokenResult{}, err
	}
	result.Headers = response.Headers()
	return result, nil
}

type RefreshTokenResult struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 string
	ProviderID            string
	AccountID             string
	IDToken               string
	Headers               contract.Headers
}

func (api DirectAPI) RefreshToken(ctx context.Context, input AccountTokenInput) (RefreshTokenResult, error) {
	response, value, err := api.invokeJSON(ctx, "refreshToken", http.MethodPost, input.Headers, accountTokenBody(input))
	if err != nil {
		return RefreshTokenResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return RefreshTokenResult{}, unexpectedDirectResult("refreshToken")
	}
	result := RefreshTokenResult{Headers: response.Headers()}
	result.AccessToken, _ = object["accessToken"].(string)
	result.RefreshToken, _ = object["refreshToken"].(string)
	result.Scope, _ = object["scope"].(string)
	result.ProviderID, _ = object["providerId"].(string)
	result.AccountID, _ = object["accountId"].(string)
	result.IDToken, _ = object["idToken"].(string)
	if value, ok := directTime(object, "accessTokenExpiresAt"); ok {
		result.AccessTokenExpiresAt = &value
	}
	if value, ok := directTime(object, "refreshTokenExpiresAt"); ok {
		result.RefreshTokenExpiresAt = &value
	}
	return result, nil
}

type AccountInfoInput struct {
	ProviderID string
	AccountID  string
	UserID     string
	Headers    contract.Headers
}

type ProviderUser struct {
	ID            string
	Name          string
	Email         model.Value[string]
	Image         model.Value[string]
	EmailVerified bool
	Extra         model.Fields
}

type AccountInfoResult struct {
	User    ProviderUser
	Data    any
	Headers contract.Headers
}

func (api DirectAPI) AccountInfo(ctx context.Context, input AccountInfoInput) (*AccountInfoResult, error) {
	query := url.Values{}
	if input.ProviderID != "" {
		query.Set("providerId", input.ProviderID)
	}
	if input.AccountID != "" {
		query.Set("accountId", input.AccountID)
	}
	if input.UserID != "" {
		query.Set("userId", input.UserID)
	}
	call, err := api.Call(ctx, "accountInfo", DirectCallInput{
		Method: http.MethodGet, Headers: input.Headers, Query: query,
	})
	if err != nil {
		return nil, err
	}
	if call.Value == nil {
		return nil, nil
	}
	object, ok := call.Value.(map[string]any)
	if !ok {
		return nil, unexpectedDirectResult("accountInfo")
	}
	userObject, ok := object["user"].(map[string]any)
	if !ok {
		return nil, unexpectedDirectResult("accountInfo.user")
	}
	return &AccountInfoResult{
		User: decodeProviderUser(userObject), Data: object["data"], Headers: call.Response.Headers(),
	}, nil
}

func accountTokenBody(input AccountTokenInput) map[string]any {
	body := map[string]any{"providerId": input.ProviderID}
	if input.AccountID != "" {
		body["accountId"] = input.AccountID
	}
	if input.UserID != "" {
		body["userId"] = input.UserID
	}
	return body
}

func decodeAccessTokenResult(object map[string]any) (AccessTokenResult, error) {
	result := AccessTokenResult{}
	result.AccessToken, _ = object["accessToken"].(string)
	result.IDToken, _ = object["idToken"].(string)
	scopes, err := directStringSlice(object["scopes"])
	if err != nil {
		return AccessTokenResult{}, unexpectedDirectResult("accessToken.scopes")
	}
	result.Scopes = scopes
	if value, ok := directTime(object, "accessTokenExpiresAt"); ok {
		result.AccessTokenExpiresAt = &value
	}
	return result, nil
}

func decodeAccount(value map[string]any) model.Account {
	record := model.Record(value)
	id, _ := recordString(record, "id")
	providerID, _ := recordString(record, "providerId")
	accountID, _ := recordString(record, "accountId")
	userID, _ := recordString(record, "userId")
	createdAt, _ := recordTime(record, "createdAt")
	updatedAt, _ := recordTime(record, "updatedAt")
	account := model.Account{
		Core:       model.Core{ID: id, CreatedAt: createdAt, UpdatedAt: updatedAt},
		ProviderID: providerID, AccountID: accountID, UserID: userID,
		AdditionalFields: model.FieldsFromRecord(record,
			"id", "providerId", "accountId", "userId", "accessToken", "refreshToken", "idToken",
			"accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "scopes", "password", "createdAt", "updatedAt"),
	}
	decodeOptionalString(record, "accessToken", &account.AccessToken)
	decodeOptionalString(record, "refreshToken", &account.RefreshToken)
	decodeOptionalString(record, "idToken", &account.IDToken)
	decodeOptionalString(record, "scope", &account.Scope)
	decodeOptionalString(record, "password", &account.Password)
	decodeOptionalTime(record, "accessTokenExpiresAt", &account.AccessTokenExpiresAt)
	decodeOptionalTime(record, "refreshTokenExpiresAt", &account.RefreshTokenExpiresAt)
	return account
}

func decodeProviderUser(value map[string]any) ProviderUser {
	record := model.Record(value)
	result := ProviderUser{Extra: model.FieldsFromRecord(record, "id", "name", "email", "image", "emailVerified")}
	result.ID, _ = recordString(record, "id")
	result.Name, _ = recordString(record, "name")
	result.EmailVerified, _ = recordBool(record, "emailVerified")
	decodeOptionalString(record, "email", &result.Email)
	decodeOptionalString(record, "image", &result.Image)
	return result
}

func decodeOptionalString(record model.Record, key string, target *model.Value[string]) {
	value, exists := record[key]
	if !exists {
		return
	}
	if value == nil {
		*target = model.Null[string]()
		return
	}
	if text, ok := value.(string); ok {
		*target = model.Present(text)
	}
}

func decodeOptionalTime(record model.Record, key string, target *model.Value[time.Time]) {
	value, exists := record[key]
	if !exists {
		return
	}
	if value == nil {
		*target = model.Null[time.Time]()
		return
	}
	if parsed, ok := recordTime(record, key); ok {
		*target = model.Present(parsed)
	}
}

func directTime(object map[string]any, key string) (time.Time, bool) {
	return recordTime(model.Record(object), key)
}

func directStringSlice(value any) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	switch values := value.(type) {
	case []any:
		result := make([]string, 0, len(values))
		for _, item := range values {
			text, ok := item.(string)
			if !ok {
				return nil, unexpectedDirectResult("string slice")
			}
			result = append(result, text)
		}
		return result, nil
	case []string:
		return append([]string(nil), values...), nil
	case string:
		if values == "" {
			return []string{}, nil
		}
		return strings.Split(values, ","), nil
	default:
		return nil, unexpectedDirectResult("string slice")
	}
}
