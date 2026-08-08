package username

import "github.com/pers0na2dev/single-auth/core/engine"

const (
	CodeInvalidUsernameOrPassword = "INVALID_USERNAME_OR_PASSWORD"
	CodeEmailNotVerified          = "EMAIL_NOT_VERIFIED"
	CodeUnexpectedError           = "UNEXPECTED_ERROR"
	CodeUsernameAlreadyTaken      = "USERNAME_IS_ALREADY_TAKEN"
	CodeUsernameTooShort          = "USERNAME_TOO_SHORT"
	CodeUsernameTooLong           = "USERNAME_TOO_LONG"
	CodeInvalidUsername           = "INVALID_USERNAME"
	CodeInvalidDisplayUsername    = "INVALID_DISPLAY_USERNAME"
)

var errorMessages = map[string]string{
	CodeInvalidUsernameOrPassword: "Invalid username or password",
	CodeEmailNotVerified:          "Email not verified",
	CodeUnexpectedError:           "Unexpected error",
	CodeUsernameAlreadyTaken:      "Username is already taken. Please try another.",
	CodeUsernameTooShort:          "Username is too short",
	CodeUsernameTooLong:           "Username is too long",
	CodeInvalidUsername:           "Username is invalid",
	CodeInvalidDisplayUsername:    "Display username is invalid",
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}
