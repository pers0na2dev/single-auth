package anonymous

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	ErrorInvalidEmailFormat                         = "INVALID_EMAIL_FORMAT"
	ErrorFailedToCreateUser                         = "FAILED_TO_CREATE_USER"
	ErrorCouldNotCreateSession                      = "COULD_NOT_CREATE_SESSION"
	ErrorAnonymousUsersCannotSignInAgainAnonymously = "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
	ErrorFailedToDeleteAnonymousUser                = "FAILED_TO_DELETE_ANONYMOUS_USER"
	ErrorFailedToDeleteAnonymousUserSessions        = "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS"
	ErrorUserIsNotAnonymous                         = "USER_IS_NOT_ANONYMOUS"
	ErrorDeleteAnonymousUserDisabled                = "DELETE_ANONYMOUS_USER_DISABLED"
)

var errorMessages = map[string]string{
	ErrorInvalidEmailFormat:                         "Email was not generated in a valid format",
	ErrorFailedToCreateUser:                         "Failed to create user",
	ErrorCouldNotCreateSession:                      "Could not create session",
	ErrorAnonymousUsersCannotSignInAgainAnonymously: "Anonymous users cannot sign in again anonymously",
	ErrorFailedToDeleteAnonymousUser:                "Failed to delete anonymous user",
	ErrorFailedToDeleteAnonymousUserSessions:        "Failed to delete anonymous user sessions",
	ErrorUserIsNotAnonymous:                         "User is not anonymous",
	ErrorDeleteAnonymousUserDisabled:                "Deleting anonymous users is disabled",
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}

func anonymousError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func unauthorized() *contract.APIError {
	return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}
