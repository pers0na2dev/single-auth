package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

func directCookieHeaders(cookieHeader string) contract.Headers {
	if cookieHeader == "" {
		return contract.Headers{}
	}
	return contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader})
}

func TestDirectAPICallSupportsPluginParamsQueryBodyAndErrorPayload(t *testing.T) {
	auth := MustNew(Options{
		Endpoints: []engine.Endpoint{{
			Name: "directEcho", Path: "/echo/:id", Methods: []string{http.MethodPost},
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				query, _ := ctx.Request().Query()
				var body map[string]any
				if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
					return contract.Response{}, err
				}
				id, _ := ctx.Param("id")
				return jsonResponse(contract.StatusOK, map[string]any{
					"id": id, "query": query.Get("q"), "body": body["value"],
				})
			},
		}, {
			Name: "directError", ServerOnly: true, Methods: []string{http.MethodPost},
			Handler: func(*engine.Context) (contract.Response, error) {
				return contract.Response{}, contract.NewAPIError(418, "TEAPOT", "short and stout")
			},
		}},
	})
	call, err := auth.API().Call(t.Context(), "directEcho", DirectCallInput{
		Method: http.MethodPost,
		Params: map[string]string{"id": "a/b"},
		Query:  url.Values{"q": []string{"search"}},
		Body:   map[string]any{"value": "payload"},
	})
	if err != nil {
		t.Fatal(err)
	}
	object, ok := call.Value.(map[string]any)
	if !ok || object["id"] != "a/b" || object["query"] != "search" || object["body"] != "payload" {
		t.Fatalf("direct result = %#v", call.Value)
	}

	failure, err := auth.API().Call(t.Context(), "directError", DirectCallInput{})
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != 418 || apiError.Code != "TEAPOT" {
		t.Fatalf("direct error = %#v", err)
	}
	errorBody, ok := failure.Value.(map[string]any)
	if !ok || errorBody["code"] != "TEAPOT" || errorBody["message"] != "short and stout" {
		t.Fatalf("decoded error body = %#v", failure.Value)
	}
}

func TestExtendedTypedDirectCredentialSessionAndAccountAPI(t *testing.T) {
	optional := storage.Bool(false)
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Schema: storage.Schema{
			Models: map[string]storage.ModelSchema{
				"session": {
					Fields: map[string]storage.FieldAttribute{
						"deviceName": {Type: storage.FieldString, Required: optional},
					},
				},
			},
		},
	})
	signUp, err := auth.API().SignUpEmail(t.Context(), SignUpEmailInput{
		Name: "Typed", Email: "typed@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", signUp.Headers.Values("Set-Cookie"))
	headers := directCookieHeaders(cookieHeader)

	sessions, err := auth.API().ListSessions(t.Context(), ListSessionsInput{Headers: headers})
	if err != nil || len(sessions.Sessions) != 1 || sessions.Sessions[0].Token != *signUp.Token {
		t.Fatalf("sessions = %#v, %v", sessions, err)
	}
	verified, err := auth.API().VerifyPassword(t.Context(), VerifyPasswordInput{
		Password: "password123", Headers: headers,
	})
	if err != nil || !verified.Status {
		t.Fatalf("verify password = %#v, %v", verified, err)
	}
	updatedUser, err := auth.API().UpdateUser(t.Context(), UpdateUserInput{
		Name: model.Present("Updated Typed"), Headers: headers,
	})
	if err != nil || !updatedUser.Status {
		t.Fatalf("update user = %#v, %v", updatedUser, err)
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, updatedUser.Headers.Values("Set-Cookie"))
	headers = directCookieHeaders(cookieHeader)

	fields := model.Fields{}
	fields.Set("deviceName", "Laptop")
	updatedSession, err := auth.API().UpdateSession(t.Context(), UpdateSessionInput{
		Fields: fields, Headers: headers,
	})
	if err != nil || updatedSession.Session.AdditionalFields.Lookup("deviceName").Or("") != "Laptop" {
		t.Fatalf("update session = %#v, %v", updatedSession, err)
	}
	cookieHeader = cookies.ApplySetCookies(cookieHeader, updatedSession.Headers.Values("Set-Cookie"))
	headers = directCookieHeaders(cookieHeader)

	password, err := auth.API().ChangePassword(t.Context(), ChangePasswordInput{
		CurrentPassword: "password123", NewPassword: "password456", Headers: headers,
	})
	if err != nil || password.Token != nil || password.User.ID != signUp.User.ID {
		t.Fatalf("change password = %#v, %v", password, err)
	}
	accounts, err := auth.API().ListUserAccounts(t.Context(), ListUserAccountsInput{Headers: headers})
	if err != nil || len(accounts.Accounts) != 1 || accounts.Accounts[0].Account.ProviderID != "credential" ||
		len(accounts.Accounts[0].Scopes) != 0 {
		t.Fatalf("accounts = %#v, %v", accounts, err)
	}
	other, err := auth.API().RevokeOtherSessions(t.Context(), AuthenticatedInput{Headers: headers})
	if err != nil || !other.Status {
		t.Fatalf("revoke other sessions = %#v, %v", other, err)
	}
}

func TestTypedDirectPasswordResetAndCallback(t *testing.T) {
	var delivered PasswordResetMessage
	auth := MustNew(Options{
		BaseURL: "https://auth.example",
		Secret:  "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(_ context.Context, message PasswordResetMessage) error {
				delivered = message
				return nil
			},
		},
	})
	if _, err := auth.API().SignUpEmail(t.Context(), SignUpEmailInput{
		Name: "Reset", Email: "reset@example.com", Password: "password123",
	}); err != nil {
		t.Fatal(err)
	}
	request, err := auth.API().RequestPasswordReset(t.Context(), RequestPasswordResetInput{
		Email: "reset@example.com", RedirectTo: "/reset-form",
	})
	if err != nil || !request.Status || delivered.Token == "" || !strings.Contains(delivered.URL, delivered.Token) {
		t.Fatalf("reset request = %#v delivered=%#v err=%v", request, delivered, err)
	}
	callback, err := auth.API().RequestPasswordResetCallback(t.Context(), PasswordResetCallbackInput{
		Token: delivered.Token, CallbackURL: "/reset-form",
	})
	if err != nil {
		t.Fatal(err)
	}
	location, parseErr := url.Parse(callback.Location)
	if parseErr != nil || location.Path != "/reset-form" || location.Query().Get("token") != delivered.Token {
		t.Fatalf("callback location = %q, %v", callback.Location, parseErr)
	}
	reset, err := auth.API().ResetPassword(t.Context(), ResetPasswordInput{
		NewPassword: "new-password123", Token: delivered.Token,
	})
	if err != nil || !reset.Status {
		t.Fatalf("reset result = %#v, %v", reset, err)
	}
	signIn, err := auth.API().SignInEmail(t.Context(), SignInEmailInput{
		Email: "reset@example.com", Password: "new-password123",
	})
	if err != nil || signIn.Token == "" {
		t.Fatalf("sign in after reset = %#v, %v", signIn, err)
	}
}

func TestTypedDirectSocialAndTokenAPI(t *testing.T) {
	now := time.Date(2026, 8, 8, 16, 0, 0, 0, time.UTC)
	email := "typed-social@example.com"
	provider, err := providers.Google(providers.Options{
		ClientID: "client", ClientSecret: "secret",
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(_ context.Context, tokens oauth2.Tokens) (*providers.UserInfoResult, error) {
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: "typed-google", Name: "Typed Social", Email: &email, EmailVerified: true,
			}, Data: map[string]any{"token": tokens.AccessToken}}, nil
		},
		RefreshAccessToken: func(context.Context, string) (oauth2.Tokens, error) {
			expires := now.Add(time.Hour)
			return oauth2.Tokens{
				AccessToken: "refreshed-access", RefreshToken: "refreshed-refresh",
				AccessTokenExpiresAt: &expires, Scopes: []string{"openid"}, IDToken: "refreshed-id",
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := MustNew(Options{
		BaseURL: "https://auth.example", Secret: "0123456789abcdef0123456789abcdef",
		Clock:           func() time.Time { return now },
		Account:         AccountOptions{StoreAccountCookie: storage.Bool(false)},
		SocialProviders: map[string]*providers.Provider{"google": provider},
	})
	signedIn, err := auth.API().SignInSocial(t.Context(), SignInSocialInput{
		Provider: "google",
		IDToken:  &SocialIDTokenInput{Token: "id-token", AccessToken: "initial-access"},
	})
	if err != nil || signedIn.Token == nil || signedIn.User == nil || signedIn.User.Email != email || signedIn.Redirect {
		t.Fatalf("social sign in = %#v, %v", signedIn, err)
	}
	cookieHeader := cookies.ApplySetCookies("", signedIn.Headers.Values("Set-Cookie"))
	headers := directCookieHeaders(cookieHeader)
	accounts, err := auth.API().ListUserAccounts(t.Context(), ListUserAccountsInput{Headers: headers})
	if err != nil || len(accounts.Accounts) != 1 || accounts.Accounts[0].Account.AccountID != "typed-google" {
		t.Fatalf("social accounts = %#v, %v", accounts, err)
	}
	account := accounts.Accounts[0].Account
	storedRefresh, err := auth.storeOAuthToken("old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: account.ID}},
		Update: storage.Record{
			"refreshToken": storedRefresh, "accessTokenExpiresAt": now.Add(-time.Second),
			"scope": "openid",
		},
	}); err != nil {
		t.Fatal(err)
	}
	token, err := auth.API().GetAccessToken(t.Context(), AccountTokenInput{
		ProviderID: "google", AccountID: "typed-google", Headers: headers,
	})
	if err != nil || token.AccessToken != "refreshed-access" || len(token.Scopes) != 1 || token.IDToken != "refreshed-id" {
		t.Fatalf("access token = %#v, %v", token, err)
	}
	info, err := auth.API().AccountInfo(t.Context(), AccountInfoInput{
		ProviderID: "google", AccountID: "typed-google", Headers: headers,
	})
	if err != nil || info == nil || info.User.ID != "typed-google" {
		t.Fatalf("account info = %#v, %v", info, err)
	}
}
