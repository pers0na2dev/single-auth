package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

// DirectAPI is the typed façade over Auth.Invoke. It uses the exact same
// endpoint handlers and before/after hooks as HTTP dispatch.
type DirectAPI struct{ auth *Auth }

// API returns the typed direct API façade.
func (a *Auth) API() DirectAPI { return DirectAPI{auth: a} }

// DirectCallInput is the escape hatch for core and plugin endpoints that do
// not yet have a dedicated typed convenience method. It still runs the exact
// endpoint and before/after-hook pipeline used by all typed methods.
type DirectCallInput struct {
	Method  string
	Scheme  string
	Host    string
	Headers contract.Headers
	Body    any
	Query   url.Values
	Params  map[string]string
	Values  map[string]any
}

// DirectCallResult preserves both the transport-neutral response (including
// Set-Cookie and Location) and its decoded JSON value.
type DirectCallResult struct {
	Response contract.Response
	Value    any
}

// Call invokes an endpoint by direct API name. Unknown JSON shapes remain
// available through Value without lossy re-marshalling.
func (api DirectAPI) Call(
	ctx context.Context,
	name string,
	input DirectCallInput,
) (DirectCallResult, error) {
	if api.auth == nil {
		err := contract.NewAPIError(
			contract.StatusInternalServerError, "AUTH_NOT_INITIALIZED", "Auth is not initialized",
		)
		return DirectCallResult{Response: contract.ResponseFromError(err)}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	headers := input.Headers.Clone()
	var encoded []byte
	if input.Body != nil {
		var err error
		encoded, err = marshalJSON(input.Body)
		if err != nil {
			return DirectCallResult{}, err
		}
		headers.Set("Content-Type", "application/json")
	}
	request := contract.NewRequest(input.Method, "/:direct", contract.RequestOptions{
		Context: ctx, Scheme: input.Scheme, Host: input.Host,
		RawQuery: input.Query.Encode(), Headers: headers, Body: encoded,
	})
	response, invokeErr := api.auth.Invoke(name, engine.DirectInput{
		Request: request, Params: input.Params, Values: input.Values,
	})
	result := DirectCallResult{Response: response}
	if len(response.Body()) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(response.Body()))
		decoder.UseNumber()
		if decodeErr := decoder.Decode(&result.Value); decodeErr != nil {
			if invokeErr != nil {
				return result, invokeErr
			}
			return result, decodeErr
		}
	}
	return result, invokeErr
}

type SignUpEmailInput struct {
	Name             string
	Email            string
	Password         string
	Image            model.Value[string]
	CallbackURL      string
	RememberMe       *bool
	AdditionalFields model.Fields
	Headers          contract.Headers
}

type SignUpEmailResult struct {
	Token   *string
	User    model.User
	Headers contract.Headers
}

type SignInEmailInput struct {
	Email       string
	Password    string
	CallbackURL string
	RememberMe  *bool
	Headers     contract.Headers
}

type SignInEmailResult struct {
	Redirect bool
	Token    string
	URL      model.Value[string]
	User     model.User
	Headers  contract.Headers
}

type GetSessionInput struct {
	Headers contract.Headers
}

type SessionResult struct {
	Session model.Session
	User    model.User
	Headers contract.Headers
}

type SignOutInput struct {
	Headers contract.Headers
}

type SignOutResult struct {
	Success bool
	Headers contract.Headers
}

func (api DirectAPI) SignUpEmail(ctx context.Context, input SignUpEmailInput) (SignUpEmailResult, error) {
	body := map[string]any{
		"name": input.Name, "email": input.Email, "password": input.Password,
	}
	if image, exists := input.Image.Interface(); exists {
		body["image"] = image
	}
	if input.CallbackURL != "" {
		body["callbackURL"] = input.CallbackURL
	}
	if input.RememberMe != nil {
		body["rememberMe"] = *input.RememberMe
	}
	input.AdditionalFields.Apply(model.Record(body))
	response, value, err := api.invokeJSON(ctx, "signUpEmail", http.MethodPost, input.Headers, body)
	if err != nil {
		return SignUpEmailResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return SignUpEmailResult{}, unexpectedDirectResult("signUpEmail")
	}
	result := SignUpEmailResult{Headers: response.Headers()}
	if token, exists := object["token"]; exists && token != nil {
		text, ok := token.(string)
		if !ok {
			return SignUpEmailResult{}, unexpectedDirectResult("signUpEmail.token")
		}
		result.Token = &text
	}
	user, ok := object["user"].(map[string]any)
	if !ok {
		return SignUpEmailResult{}, unexpectedDirectResult("signUpEmail.user")
	}
	result.User = api.decodeUser(user)
	return result, nil
}

func (api DirectAPI) SignInEmail(ctx context.Context, input SignInEmailInput) (SignInEmailResult, error) {
	body := map[string]any{"email": input.Email, "password": input.Password}
	if input.CallbackURL != "" {
		body["callbackURL"] = input.CallbackURL
	}
	if input.RememberMe != nil {
		body["rememberMe"] = *input.RememberMe
	}
	response, value, err := api.invokeJSON(ctx, "signInEmail", http.MethodPost, input.Headers, body)
	if err != nil {
		return SignInEmailResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return SignInEmailResult{}, unexpectedDirectResult("signInEmail")
	}
	result := SignInEmailResult{Headers: response.Headers()}
	result.Redirect, _ = object["redirect"].(bool)
	result.Token, _ = object["token"].(string)
	if rawURL, exists := object["url"]; exists {
		if rawURL == nil {
			result.URL = model.Null[string]()
		} else if text, ok := rawURL.(string); ok {
			result.URL = model.Present(text)
		}
	}
	user, ok := object["user"].(map[string]any)
	if !ok {
		return SignInEmailResult{}, unexpectedDirectResult("signInEmail.user")
	}
	result.User = api.decodeUser(user)
	return result, nil
}

func (api DirectAPI) GetSession(ctx context.Context, input GetSessionInput) (*SessionResult, error) {
	response, value, err := api.invokeJSON(ctx, "getSession", http.MethodGet, input.Headers, nil)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, unexpectedDirectResult("getSession")
	}
	session, sessionOK := object["session"].(map[string]any)
	user, userOK := object["user"].(map[string]any)
	if !sessionOK || !userOK {
		return nil, unexpectedDirectResult("getSession payload")
	}
	return &SessionResult{
		Session: decodeSession(session), User: api.decodeUser(user), Headers: response.Headers(),
	}, nil
}

func (api DirectAPI) SignOut(ctx context.Context, input SignOutInput) (SignOutResult, error) {
	response, value, err := api.invokeJSON(ctx, "signOut", http.MethodPost, input.Headers, map[string]any{})
	if err != nil {
		return SignOutResult{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return SignOutResult{}, unexpectedDirectResult("signOut")
	}
	success, _ := object["success"].(bool)
	return SignOutResult{Success: success, Headers: response.Headers()}, nil
}

func (api DirectAPI) invokeJSON(
	ctx context.Context,
	name, method string,
	headers contract.Headers,
	body any,
) (contract.Response, any, error) {
	result, err := api.Call(ctx, name, DirectCallInput{
		Method: method, Headers: headers, Body: body,
	})
	return result.Response, result.Value, err
}

func decodeUser(value map[string]any) model.User {
	record := model.Record(value)
	user := userFromRecord(record)
	user.AdditionalFields = model.FieldsFromRecord(record,
		"id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt")
	return user
}

func (api DirectAPI) decodeUser(value map[string]any) model.User {
	user := decodeUser(value)
	if api.auth == nil {
		return user
	}
	table, exists := api.auth.options.Schema.Models["user"]
	if !exists {
		return user
	}
	for name, attribute := range table.Fields {
		if attribute.Type != storage.FieldDate {
			continue
		}
		raw, present := user.AdditionalFields.Lookup(name).Get()
		encoded, ok := raw.(string)
		if !present || !ok {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, encoded)
		if err == nil {
			user.AdditionalFields.Set(name, parsed)
		}
	}
	return user
}

func decodeSession(value map[string]any) model.Session {
	record := model.Record(value)
	id, _ := recordString(record, "id")
	userID, _ := recordString(record, "userId")
	token, _ := recordString(record, "token")
	expiresAt, _ := recordTime(record, "expiresAt")
	createdAt, _ := recordTime(record, "createdAt")
	updatedAt, _ := recordTime(record, "updatedAt")
	session := model.Session{
		Core:   model.Core{ID: id, CreatedAt: createdAt, UpdatedAt: updatedAt},
		UserID: userID, Token: token, ExpiresAt: expiresAt,
		AdditionalFields: model.FieldsFromRecord(record,
			"id", "userId", "token", "expiresAt", "ipAddress", "userAgent", "createdAt", "updatedAt"),
	}
	if raw, exists := record["ipAddress"]; exists {
		if raw == nil {
			session.IPAddress = model.Null[string]()
		} else if text, ok := raw.(string); ok {
			session.IPAddress = model.Present(text)
		}
	}
	if raw, exists := record["userAgent"]; exists {
		if raw == nil {
			session.UserAgent = model.Null[string]()
		} else if text, ok := raw.(string); ok {
			session.UserAgent = model.Present(text)
		}
	}
	return session
}

func unexpectedDirectResult(name string) error {
	return fmt.Errorf("single-auth: unexpected direct API result for %s", name)
}
