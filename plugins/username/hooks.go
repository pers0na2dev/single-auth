package username

import (
	"encoding/json"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"

	singleauth "github.com/pers0na2dev/single-auth"
)

func (plugin *compiledPlugin) matchesSignUp(ctx *engine.Context) (bool, error) {
	return ctx != nil && ctx.Path() == "/sign-up/email", nil
}

func (plugin *compiledPlugin) matchesUserInput(ctx *engine.Context) (bool, error) {
	if ctx == nil {
		return false, nil
	}
	return ctx.Path() == "/sign-up/email" || ctx.Path() == "/update-user", nil
}

func (plugin *compiledPlugin) applyDisplayFallback(ctx *engine.Context) (*contract.Response, error) {
	body, ok := decodeEndpointObject(ctx.Request())
	if !ok {
		return nil, nil
	}
	displayUsername, displayIsString := body["displayUsername"].(string)
	_, usernamePresent := body["username"]
	if !displayIsString || usernamePresent {
		return nil, nil
	}
	code, err := plugin.validateUsernameValue(displayUsername)
	if err != nil {
		return nil, err
	}
	if code != "" {
		return nil, nil
	}
	body["username"] = displayUsername
	return nil, replaceEndpointObject(ctx, body)
}

func (plugin *compiledPlugin) validateHTTPInput(ctx *engine.Context) (*contract.Response, error) {
	body, ok := decodeEndpointObject(ctx.Request())
	if !ok {
		return nil, nil
	}
	path := ctx.Path()
	if value, exists := body["username"]; exists {
		if username, isString := value.(string); isString {
			code, err := plugin.validateUsernameValue(username)
			if err != nil {
				return nil, err
			}
			if code != "" {
				return nil, usernameError(contract.StatusBadRequest, code)
			}
			existing, err := plugin.findUserByUsername(ctx.GoContext(), plugin.usernameNormal(username))
			if err != nil {
				return nil, internalError(err)
			}
			if existing != nil {
				switch path {
				case "/sign-up/email":
					return nil, usernameError(contract.StatusBadRequest, CodeUsernameAlreadyTaken)
				case "/update-user":
					state, resolveErr := plugin.options.Runtime.ResolveSession(ctx)
					if resolveErr != nil {
						return nil, resolveErr
					}
					existingID, _ := recordString(existing, "id")
					currentID := ""
					if state != nil {
						currentID, _ = recordString(state.User, "id")
					}
					if currentID == "" || existingID != currentID {
						return nil, usernameError(contract.StatusBadRequest, CodeUsernameAlreadyTaken)
					}
				}
			}
		}
	}
	if displayUsername, isString := body["displayUsername"].(string); isString && plugin.options.DisplayUsernameValidator != nil {
		valid, err := plugin.options.DisplayUsernameValidator(plugin.displayForValidation(displayUsername))
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, usernameError(contract.StatusBadRequest, CodeInvalidDisplayUsername)
		}
	}
	return nil, nil
}

func (plugin *compiledPlugin) applyDisplayDefault(ctx *engine.Context) (*contract.Response, error) {
	body, ok := decodeEndpointObject(ctx.Request())
	if !ok {
		return nil, nil
	}
	username, isString := body["username"].(string)
	if !isString || username == "" || jsTruthy(body["displayUsername"]) {
		return nil, nil
	}
	body["displayUsername"] = username
	return nil, replaceEndpointObject(ctx, body)
}

func jsTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case float64:
		return typed != 0
	case float32:
		return typed != 0
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case json.Number:
		value, err := typed.Float64()
		return err != nil || value != 0
	default:
		return true
	}
}

func (plugin *compiledPlugin) databaseHooks() singleauth.DatabaseHooks {
	return singleauth.DatabaseHooks{"user": {
		Create: singleauth.DatabaseOperationHooks{Before: plugin.beforeUserCreate},
		Update: singleauth.DatabaseOperationHooks{Before: plugin.beforeUserUpdate},
	}}
}

func (plugin *compiledPlugin) beforeUserCreate(
	data storage.Record,
	hook singleauth.DatabaseHookContext,
) (singleauth.DatabaseHookResult, error) {
	username, hasUsername := recordString(data, "username")
	displayUsername, hasDisplay := recordString(data, "displayUsername")
	if hasUsername && username != "" {
		if !skipHTTPHookValidation(hook) {
			if err := plugin.validateUsername(hook.Endpoint, username, displayUsername, ""); err != nil {
				return singleauth.DatabaseHookResult{}, err
			}
		}
		result := storage.Record{
			"username": plugin.usernameNormal(username),
		}
		if hasDisplay && displayUsername != "" {
			result["displayUsername"] = plugin.displayNormal(displayUsername)
		} else {
			// single-auth intentionally preserves the submitted casing here.
			result["displayUsername"] = username
		}
		return singleauth.DatabaseHookResult{Data: result}, nil
	}
	if hasDisplay && displayUsername != "" {
		return singleauth.DatabaseHookResult{Data: storage.Record{
			"displayUsername": plugin.displayNormal(displayUsername),
		}}, nil
	}
	return singleauth.DatabaseHookResult{}, nil
}

func (plugin *compiledPlugin) beforeUserUpdate(
	data storage.Record,
	hook singleauth.DatabaseHookContext,
) (singleauth.DatabaseHookResult, error) {
	username, hasUsername := recordString(data, "username")
	displayUsername, hasDisplay := recordString(data, "displayUsername")
	if hasUsername && username != "" {
		if !skipHTTPHookValidation(hook) {
			currentUserID, _ := recordString(data, "id")
			if hook.Endpoint != nil && plugin.options.Runtime.ResolveSession != nil {
				if state, err := plugin.options.Runtime.ResolveSession(hook.Endpoint); err == nil && state != nil {
					if sessionUserID, ok := recordString(state.User, "id"); ok {
						currentUserID = sessionUserID
					}
				}
			}
			if err := plugin.validateUsername(hook.Endpoint, username, displayUsername, currentUserID); err != nil {
				return singleauth.DatabaseHookResult{}, err
			}
		}
		result := storage.Record{"username": plugin.usernameNormal(username)}
		if hasDisplay && displayUsername != "" {
			result["displayUsername"] = plugin.displayNormal(displayUsername)
		}
		return singleauth.DatabaseHookResult{Data: result}, nil
	}
	if hasDisplay && displayUsername != "" {
		return singleauth.DatabaseHookResult{Data: storage.Record{
			"displayUsername": plugin.displayNormal(displayUsername),
		}}, nil
	}
	return singleauth.DatabaseHookResult{}, nil
}

func skipHTTPHookValidation(hook singleauth.DatabaseHookContext) bool {
	if hook.Endpoint == nil {
		return false
	}
	switch hook.Endpoint.Path() {
	case "/sign-up/email", "/update-user":
		return true
	default:
		return false
	}
}
