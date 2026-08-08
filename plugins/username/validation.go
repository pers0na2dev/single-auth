package username

import (
	"context"
	"regexp"
	"unicode/utf16"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

var defaultUsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

func defaultUsernameValidator(value string) (bool, error) {
	return defaultUsernamePattern.MatchString(value), nil
}

// javascriptStringLength matches String.length, which counts UTF-16 code
// units rather than Unicode scalar values or UTF-8 bytes.
func javascriptStringLength(value string) int {
	return len(utf16.Encode([]rune(value)))
}

func (plugin *compiledPlugin) usernameForValidation(value string) string {
	if plugin.options.ValidationOrder.Username == PostNormalization {
		return plugin.usernameNormal(value)
	}
	return value
}

func (plugin *compiledPlugin) displayForValidation(value string) string {
	if plugin.options.ValidationOrder.DisplayUsername == PostNormalization {
		return plugin.displayNormal(value)
	}
	return value
}

func (plugin *compiledPlugin) validateUsernameValue(value string) (string, error) {
	return plugin.validateUsernameRepresentation(plugin.usernameForValidation(value))
}

func (plugin *compiledPlugin) validateUsernameRepresentation(value string) (string, error) {
	length := javascriptStringLength(value)
	if length < plugin.minLength {
		return CodeUsernameTooShort, nil
	}
	if length > plugin.maxLength {
		return CodeUsernameTooLong, nil
	}
	valid, err := plugin.usernameValidator(value)
	if err != nil {
		return "", err
	}
	if !valid {
		return CodeInvalidUsername, nil
	}
	return "", nil
}

func (plugin *compiledPlugin) validateUsername(
	ctx *engine.Context,
	value string,
	displayUsername string,
	currentUserID string,
) error {
	code, err := plugin.validateUsernameValue(value)
	if err != nil {
		return err
	}
	if code != "" {
		return usernameError(contract.StatusBadRequest, code)
	}
	existing, err := plugin.findUserByUsername(ctx.GoContext(), plugin.usernameNormal(value))
	if err != nil {
		return internalError(err)
	}
	if existing != nil {
		existingID, _ := recordString(existing, "id")
		if currentUserID == "" || existingID != currentUserID {
			return usernameError(contract.StatusBadRequest, CodeUsernameAlreadyTaken)
		}
	}
	if displayUsername != "" && plugin.options.DisplayUsernameValidator != nil {
		valid, err := plugin.options.DisplayUsernameValidator(plugin.displayForValidation(displayUsername))
		if err != nil {
			return err
		}
		if !valid {
			return usernameError(contract.StatusBadRequest, CodeInvalidDisplayUsername)
		}
	}
	return nil
}

func (plugin *compiledPlugin) findUserByUsername(ctx context.Context, username string) (storage.Record, error) {
	return plugin.options.Runtime.Adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "username", Value: username}},
	})
}
