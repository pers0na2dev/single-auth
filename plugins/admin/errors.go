package admin

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	ErrorFailedToCreateUser                   = "FAILED_TO_CREATE_USER"
	ErrorUserAlreadyExists                    = "USER_ALREADY_EXISTS"
	ErrorUserAlreadyExistsUseAnotherEmail     = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
	ErrorYouCannotBanYourself                 = "YOU_CANNOT_BAN_YOURSELF"
	ErrorNotAllowedToChangeUsersRole          = "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
	ErrorNotAllowedToCreateUsers              = "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS"
	ErrorNotAllowedToListUsers                = "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS"
	ErrorNotAllowedToListUsersSessions        = "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS"
	ErrorNotAllowedToBanUsers                 = "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"
	ErrorNotAllowedToImpersonateUsers         = "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS"
	ErrorNotAllowedToRevokeUsersSessions      = "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"
	ErrorNotAllowedToDeleteUsers              = "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS"
	ErrorNotAllowedToSetUsersPassword         = "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD"
	ErrorBannedUser                           = "BANNED_USER"
	ErrorNotAllowedToGetUser                  = "YOU_ARE_NOT_ALLOWED_TO_GET_USER"
	ErrorNoDataToUpdate                       = "NO_DATA_TO_UPDATE"
	ErrorNotAllowedToUpdateUsers              = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS"
	ErrorYouCannotRemoveYourself              = "YOU_CANNOT_REMOVE_YOURSELF"
	ErrorNotAllowedToSetNonExistentValue      = "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"
	ErrorYouCannotImpersonateAdmins           = "YOU_CANNOT_IMPERSONATE_ADMINS"
	ErrorInvalidRoleType                      = "INVALID_ROLE_TYPE"
	ErrorNotAllowedToSetUsersEmail            = "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL"
	ErrorPasswordCannotBeUpdatedViaUpdateUser = "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER"
)

var errorMessages = map[string]string{
	ErrorFailedToCreateUser:                   "Failed to create user",
	ErrorUserAlreadyExists:                    "User already exists.",
	ErrorUserAlreadyExistsUseAnotherEmail:     "User already exists. Use another email.",
	ErrorYouCannotBanYourself:                 "You cannot ban yourself",
	ErrorNotAllowedToChangeUsersRole:          "You are not allowed to change users role",
	ErrorNotAllowedToCreateUsers:              "You are not allowed to create users",
	ErrorNotAllowedToListUsers:                "You are not allowed to list users",
	ErrorNotAllowedToListUsersSessions:        "You are not allowed to list users sessions",
	ErrorNotAllowedToBanUsers:                 "You are not allowed to ban users",
	ErrorNotAllowedToImpersonateUsers:         "You are not allowed to impersonate users",
	ErrorNotAllowedToRevokeUsersSessions:      "You are not allowed to revoke users sessions",
	ErrorNotAllowedToDeleteUsers:              "You are not allowed to delete users",
	ErrorNotAllowedToSetUsersPassword:         "You are not allowed to set users password",
	ErrorBannedUser:                           "You have been banned from this application",
	ErrorNotAllowedToGetUser:                  "You are not allowed to get user",
	ErrorNoDataToUpdate:                       "No data to update",
	ErrorNotAllowedToUpdateUsers:              "You are not allowed to update users",
	ErrorYouCannotRemoveYourself:              "You cannot remove yourself",
	ErrorNotAllowedToSetNonExistentValue:      "You are not allowed to set a non-existent role value",
	ErrorYouCannotImpersonateAdmins:           "You cannot impersonate admins",
	ErrorInvalidRoleType:                      "Invalid role type",
	ErrorNotAllowedToSetUsersEmail:            "You are not allowed to update users email",
	ErrorPasswordCannotBeUpdatedViaUpdateUser: "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}

func adminError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func baseError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error").WithCause(err)
}

func preserveRuntimeError(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return internalError(err)
}
