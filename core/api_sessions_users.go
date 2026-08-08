package core

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/model"
)

// StatusResult is the common `{status: boolean}` response returned by Better
// Auth mutation endpoints.
type StatusResult struct {
	Status  bool
	Headers contract.Headers
}

type StatusMessageResult struct {
	Status  bool
	Message string
	Headers contract.Headers
}

type SuccessMessageResult struct {
	Success bool
	Message string
	Headers contract.Headers
}

type RedirectResult struct {
	Location string
	Headers  contract.Headers
}

type ListSessionsInput struct{ Headers contract.Headers }

type ListSessionsResult struct {
	Sessions []model.Session
	Headers  contract.Headers
}

func (api DirectAPI) ListSessions(ctx context.Context, input ListSessionsInput) (ListSessionsResult, error) {
	response, value, err := api.invokeJSON(ctx, "listSessions", http.MethodGet, input.Headers, nil)
	if err != nil {
		return ListSessionsResult{}, err
	}
	raw, ok := value.([]any)
	if !ok {
		return ListSessionsResult{}, unexpectedDirectResult("listSessions")
	}
	sessions := make([]model.Session, 0, len(raw))
	for _, entry := range raw {
		object, ok := entry.(map[string]any)
		if !ok {
			return ListSessionsResult{}, unexpectedDirectResult("listSessions item")
		}
		sessions = append(sessions, decodeSession(object))
	}
	return ListSessionsResult{Sessions: sessions, Headers: response.Headers()}, nil
}

type RevokeSessionInput struct {
	Token   string
	Headers contract.Headers
}

func (api DirectAPI) RevokeSession(ctx context.Context, input RevokeSessionInput) (StatusResult, error) {
	return api.statusCall(ctx, "revokeSession", input.Headers, map[string]any{"token": input.Token})
}

type AuthenticatedInput struct{ Headers contract.Headers }

func (api DirectAPI) RevokeSessions(ctx context.Context, input AuthenticatedInput) (StatusResult, error) {
	return api.statusCall(ctx, "revokeSessions", input.Headers, map[string]any{})
}

func (api DirectAPI) RevokeOtherSessions(ctx context.Context, input AuthenticatedInput) (StatusResult, error) {
	return api.statusCall(ctx, "revokeOtherSessions", input.Headers, map[string]any{})
}

type UpdateSessionInput struct {
	Fields  model.Fields
	Headers contract.Headers
}

type UpdateSessionResult struct {
	Session model.Session
	Headers contract.Headers
}

func (api DirectAPI) UpdateSession(ctx context.Context, input UpdateSessionInput) (UpdateSessionResult, error) {
	body := map[string]any{}
	input.Fields.Apply(model.Record(body))
	response, value, err := api.invokeJSON(ctx, "updateSession", http.MethodPost, input.Headers, body)
	if err != nil {
		return UpdateSessionResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return UpdateSessionResult{}, unexpectedDirectResult("updateSession")
	}
	session, ok := object["session"].(map[string]any)
	if !ok {
		return UpdateSessionResult{}, unexpectedDirectResult("updateSession.session")
	}
	return UpdateSessionResult{Session: decodeSession(session), Headers: response.Headers()}, nil
}

type UpdateUserInput struct {
	Name             model.Value[string]
	Image            model.Value[string]
	AdditionalFields model.Fields
	Headers          contract.Headers
}

func (api DirectAPI) UpdateUser(ctx context.Context, input UpdateUserInput) (StatusResult, error) {
	body := map[string]any{}
	applyDirectValue(body, "name", input.Name)
	applyDirectValue(body, "image", input.Image)
	input.AdditionalFields.Apply(model.Record(body))
	return api.statusCall(ctx, "updateUser", input.Headers, body)
}

type ChangePasswordInput struct {
	NewPassword         string
	CurrentPassword     string
	RevokeOtherSessions *bool
	Headers             contract.Headers
}

type ChangePasswordResult struct {
	Token   *string
	User    model.User
	Headers contract.Headers
}

func (api DirectAPI) ChangePassword(ctx context.Context, input ChangePasswordInput) (ChangePasswordResult, error) {
	body := map[string]any{
		"newPassword": input.NewPassword, "currentPassword": input.CurrentPassword,
	}
	if input.RevokeOtherSessions != nil {
		body["revokeOtherSessions"] = *input.RevokeOtherSessions
	}
	response, value, err := api.invokeJSON(ctx, "changePassword", http.MethodPost, input.Headers, body)
	if err != nil {
		return ChangePasswordResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return ChangePasswordResult{}, unexpectedDirectResult("changePassword")
	}
	user, ok := object["user"].(map[string]any)
	if !ok {
		return ChangePasswordResult{}, unexpectedDirectResult("changePassword.user")
	}
	result := ChangePasswordResult{User: api.decodeUser(user), Headers: response.Headers()}
	if token, exists := object["token"]; exists && token != nil {
		text, ok := token.(string)
		if !ok {
			return ChangePasswordResult{}, unexpectedDirectResult("changePassword.token")
		}
		result.Token = &text
	}
	return result, nil
}

type SetPasswordInput struct {
	NewPassword string
	Headers     contract.Headers
}

func (api DirectAPI) SetPassword(ctx context.Context, input SetPasswordInput) (StatusResult, error) {
	return api.statusCall(ctx, "setPassword", input.Headers, map[string]any{"newPassword": input.NewPassword})
}

type RequestPasswordResetInput struct {
	Email      string
	RedirectTo string
	Headers    contract.Headers
}

func (api DirectAPI) RequestPasswordReset(
	ctx context.Context,
	input RequestPasswordResetInput,
) (StatusMessageResult, error) {
	body := map[string]any{"email": input.Email}
	if input.RedirectTo != "" {
		body["redirectTo"] = input.RedirectTo
	}
	response, value, err := api.invokeJSON(ctx, "requestPasswordReset", http.MethodPost, input.Headers, body)
	if err != nil {
		return StatusMessageResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return StatusMessageResult{}, unexpectedDirectResult("requestPasswordReset")
	}
	status, _ := object["status"].(bool)
	message, _ := object["message"].(string)
	return StatusMessageResult{Status: status, Message: message, Headers: response.Headers()}, nil
}

type PasswordResetCallbackInput struct {
	Token       string
	CallbackURL string
	Headers     contract.Headers
}

func (api DirectAPI) RequestPasswordResetCallback(
	ctx context.Context,
	input PasswordResetCallbackInput,
) (RedirectResult, error) {
	result, err := api.Call(ctx, "requestPasswordResetCallback", DirectCallInput{
		Method: http.MethodGet, Headers: input.Headers,
		Params: map[string]string{"token": input.Token},
		Query:  url.Values{"callbackURL": []string{input.CallbackURL}},
	})
	if err != nil {
		return RedirectResult{}, err
	}
	location, _ := result.Response.Headers().Get("Location")
	return RedirectResult{Location: location, Headers: result.Response.Headers()}, nil
}

type ResetPasswordInput struct {
	NewPassword string
	Token       string
	Headers     contract.Headers
}

func (api DirectAPI) ResetPassword(ctx context.Context, input ResetPasswordInput) (StatusResult, error) {
	return api.statusCall(ctx, "resetPassword", input.Headers, map[string]any{
		"newPassword": input.NewPassword, "token": input.Token,
	})
}

type VerifyPasswordInput struct {
	Password string
	Headers  contract.Headers
}

func (api DirectAPI) VerifyPassword(ctx context.Context, input VerifyPasswordInput) (StatusResult, error) {
	return api.statusCall(ctx, "verifyPassword", input.Headers, map[string]any{"password": input.Password})
}

type SendVerificationEmailInput struct {
	Email       string
	CallbackURL string
	Headers     contract.Headers
}

func (api DirectAPI) SendVerificationEmail(
	ctx context.Context,
	input SendVerificationEmailInput,
) (StatusResult, error) {
	body := map[string]any{"email": input.Email}
	if input.CallbackURL != "" {
		body["callbackURL"] = input.CallbackURL
	}
	return api.statusCall(ctx, "sendVerificationEmail", input.Headers, body)
}

type VerifyEmailInput struct {
	Token       string
	CallbackURL string
	Headers     contract.Headers
}

type VerifyEmailResult struct {
	Status   bool
	User     *model.User
	Location string
	Headers  contract.Headers
}

func (api DirectAPI) VerifyEmail(ctx context.Context, input VerifyEmailInput) (VerifyEmailResult, error) {
	query := url.Values{"token": []string{input.Token}}
	if input.CallbackURL != "" {
		query.Set("callbackURL", input.CallbackURL)
	}
	call, err := api.Call(ctx, "verifyEmail", DirectCallInput{
		Method: http.MethodGet, Headers: input.Headers, Query: query,
	})
	if err != nil {
		return VerifyEmailResult{}, err
	}
	result := VerifyEmailResult{Headers: call.Response.Headers()}
	result.Location, _ = call.Response.Headers().Get("Location")
	if call.Value == nil {
		return result, nil
	}
	object, ok := call.Value.(map[string]any)
	if !ok {
		return VerifyEmailResult{}, unexpectedDirectResult("verifyEmail")
	}
	result.Status, _ = object["status"].(bool)
	if user, ok := object["user"].(map[string]any); ok {
		decoded := api.decodeUser(user)
		result.User = &decoded
	}
	return result, nil
}

type ChangeEmailInput struct {
	NewEmail    string
	CallbackURL string
	Headers     contract.Headers
}

func (api DirectAPI) ChangeEmail(ctx context.Context, input ChangeEmailInput) (StatusResult, error) {
	body := map[string]any{"newEmail": input.NewEmail}
	if input.CallbackURL != "" {
		body["callbackURL"] = input.CallbackURL
	}
	return api.statusCall(ctx, "changeEmail", input.Headers, body)
}

type DeleteUserInput struct {
	Password    string
	Token       string
	CallbackURL string
	Headers     contract.Headers
}

func (api DirectAPI) DeleteUser(ctx context.Context, input DeleteUserInput) (SuccessMessageResult, error) {
	body := map[string]any{}
	if input.Password != "" {
		body["password"] = input.Password
	}
	if input.Token != "" {
		body["token"] = input.Token
	}
	if input.CallbackURL != "" {
		body["callbackURL"] = input.CallbackURL
	}
	response, value, err := api.invokeJSON(ctx, "deleteUser", http.MethodPost, input.Headers, body)
	if err != nil {
		return SuccessMessageResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return SuccessMessageResult{}, unexpectedDirectResult("deleteUser")
	}
	success, _ := object["success"].(bool)
	message, _ := object["message"].(string)
	return SuccessMessageResult{Success: success, Message: message, Headers: response.Headers()}, nil
}

type DeleteUserCallbackInput struct {
	Token       string
	CallbackURL string
	Headers     contract.Headers
}

type DeleteUserCallbackResult struct {
	Success  bool
	Message  string
	Location string
	Headers  contract.Headers
}

func (api DirectAPI) DeleteUserCallback(
	ctx context.Context,
	input DeleteUserCallbackInput,
) (DeleteUserCallbackResult, error) {
	query := url.Values{"token": []string{input.Token}}
	if input.CallbackURL != "" {
		query.Set("callbackURL", input.CallbackURL)
	}
	call, err := api.Call(ctx, "deleteUserCallback", DirectCallInput{
		Method: http.MethodGet, Headers: input.Headers, Query: query,
	})
	if err != nil {
		return DeleteUserCallbackResult{}, err
	}
	result := DeleteUserCallbackResult{Headers: call.Response.Headers()}
	result.Location, _ = call.Response.Headers().Get("Location")
	if object, ok := call.Value.(map[string]any); ok {
		result.Success, _ = object["success"].(bool)
		result.Message, _ = object["message"].(string)
	}
	return result, nil
}

func (api DirectAPI) statusCall(
	ctx context.Context,
	name string,
	headers contract.Headers,
	body map[string]any,
) (StatusResult, error) {
	response, value, err := api.invokeJSON(ctx, name, http.MethodPost, headers, body)
	if err != nil {
		return StatusResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return StatusResult{}, unexpectedDirectResult(name)
	}
	status, _ := object["status"].(bool)
	return StatusResult{Status: status, Headers: response.Headers()}, nil
}

func applyDirectValue[T any](body map[string]any, name string, value model.Value[T]) {
	if raw, exists := value.Interface(); exists {
		body[name] = raw
	}
}
