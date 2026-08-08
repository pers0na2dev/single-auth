package core

// ErrorCode is a stable upstream implementation API error identifier.
type ErrorCode string

const (
	ErrorUserNotFound                    ErrorCode = "USER_NOT_FOUND"
	ErrorFailedToCreateUser              ErrorCode = "FAILED_TO_CREATE_USER"
	ErrorFailedToCreateSession           ErrorCode = "FAILED_TO_CREATE_SESSION"
	ErrorFailedToUpdateUser              ErrorCode = "FAILED_TO_UPDATE_USER"
	ErrorFailedToGetSession              ErrorCode = "FAILED_TO_GET_SESSION"
	ErrorInvalidPassword                 ErrorCode = "INVALID_PASSWORD"
	ErrorInvalidEmail                    ErrorCode = "INVALID_EMAIL"
	ErrorInvalidEmailOrPassword          ErrorCode = "INVALID_EMAIL_OR_PASSWORD"
	ErrorInvalidUser                     ErrorCode = "INVALID_USER"
	ErrorSocialAccountAlreadyLinked      ErrorCode = "SOCIAL_ACCOUNT_ALREADY_LINKED"
	ErrorProviderNotFound                ErrorCode = "PROVIDER_NOT_FOUND"
	ErrorInvalidToken                    ErrorCode = "INVALID_TOKEN"
	ErrorTokenExpired                    ErrorCode = "TOKEN_EXPIRED"
	ErrorIDTokenNotSupported             ErrorCode = "ID_TOKEN_NOT_SUPPORTED"
	ErrorFailedToGetUserInfo             ErrorCode = "FAILED_TO_GET_USER_INFO"
	ErrorUserEmailNotFound               ErrorCode = "USER_EMAIL_NOT_FOUND"
	ErrorEmailNotVerified                ErrorCode = "EMAIL_NOT_VERIFIED"
	ErrorPasswordTooShort                ErrorCode = "PASSWORD_TOO_SHORT"
	ErrorPasswordTooLong                 ErrorCode = "PASSWORD_TOO_LONG"
	ErrorUserAlreadyExists               ErrorCode = "USER_ALREADY_EXISTS"
	ErrorUserAlreadyExistsAnotherEmail   ErrorCode = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
	ErrorEmailCannotBeUpdated            ErrorCode = "EMAIL_CAN_NOT_BE_UPDATED"
	ErrorChangeEmailDisabled             ErrorCode = "CHANGE_EMAIL_DISABLED"
	ErrorCredentialAccountNotFound       ErrorCode = "CREDENTIAL_ACCOUNT_NOT_FOUND"
	ErrorSessionExpired                  ErrorCode = "SESSION_EXPIRED"
	ErrorFailedToUnlinkLastAccount       ErrorCode = "FAILED_TO_UNLINK_LAST_ACCOUNT"
	ErrorAccountNotFound                 ErrorCode = "ACCOUNT_NOT_FOUND"
	ErrorUserAlreadyHasPassword          ErrorCode = "USER_ALREADY_HAS_PASSWORD"
	ErrorCrossSiteNavigationLoginBlocked ErrorCode = "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"
	ErrorVerificationEmailNotEnabled     ErrorCode = "VERIFICATION_EMAIL_NOT_ENABLED"
	ErrorEmailAlreadyVerified            ErrorCode = "EMAIL_ALREADY_VERIFIED"
	ErrorEmailMismatch                   ErrorCode = "EMAIL_MISMATCH"
	ErrorSessionNotFresh                 ErrorCode = "SESSION_NOT_FRESH"
	ErrorLinkedAccountAlreadyExists      ErrorCode = "LINKED_ACCOUNT_ALREADY_EXISTS"
	ErrorInvalidOrigin                   ErrorCode = "INVALID_ORIGIN"
	ErrorInvalidCallbackURL              ErrorCode = "INVALID_CALLBACK_URL"
	ErrorInvalidRedirectURL              ErrorCode = "INVALID_REDIRECT_URL"
	ErrorInvalidErrorCallbackURL         ErrorCode = "INVALID_ERROR_CALLBACK_URL"
	ErrorInvalidNewUserCallbackURL       ErrorCode = "INVALID_NEW_USER_CALLBACK_URL"
	ErrorMissingOrNullOrigin             ErrorCode = "MISSING_OR_NULL_ORIGIN"
	ErrorCallbackURLRequired             ErrorCode = "CALLBACK_URL_REQUIRED"
	ErrorFailedToCreateVerification      ErrorCode = "FAILED_TO_CREATE_VERIFICATION"
	ErrorFieldNotAllowed                 ErrorCode = "FIELD_NOT_ALLOWED"
	ErrorAsyncValidationNotSupported     ErrorCode = "ASYNC_VALIDATION_NOT_SUPPORTED"
	ErrorValidation                      ErrorCode = "VALIDATION_ERROR"
	ErrorMissingField                    ErrorCode = "MISSING_FIELD"
	ErrorMethodNeedsDeferredSession      ErrorCode = "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED"
	ErrorBodyMustBeObject                ErrorCode = "BODY_MUST_BE_AN_OBJECT"
	ErrorPasswordAlreadySet              ErrorCode = "PASSWORD_ALREADY_SET"
)

// BaseErrorMessages is the exact upstream implementation 1.6.26 base error catalog.
var BaseErrorMessages = map[ErrorCode]string{
	ErrorUserNotFound:                    "User not found",
	ErrorFailedToCreateUser:              "Failed to create user",
	ErrorFailedToCreateSession:           "Failed to create session",
	ErrorFailedToUpdateUser:              "Failed to update user",
	ErrorFailedToGetSession:              "Failed to get session",
	ErrorInvalidPassword:                 "Invalid password",
	ErrorInvalidEmail:                    "Invalid email",
	ErrorInvalidEmailOrPassword:          "Invalid email or password",
	ErrorInvalidUser:                     "Invalid user",
	ErrorSocialAccountAlreadyLinked:      "Social account already linked",
	ErrorProviderNotFound:                "Provider not found",
	ErrorInvalidToken:                    "Invalid token",
	ErrorTokenExpired:                    "Token expired",
	ErrorIDTokenNotSupported:             "id_token not supported",
	ErrorFailedToGetUserInfo:             "Failed to get user info",
	ErrorUserEmailNotFound:               "User email not found",
	ErrorEmailNotVerified:                "Email not verified",
	ErrorPasswordTooShort:                "Password too short",
	ErrorPasswordTooLong:                 "Password too long",
	ErrorUserAlreadyExists:               "User already exists.",
	ErrorUserAlreadyExistsAnotherEmail:   "User already exists. Use another email.",
	ErrorEmailCannotBeUpdated:            "Email can not be updated",
	ErrorChangeEmailDisabled:             "Change email is disabled",
	ErrorCredentialAccountNotFound:       "Credential account not found",
	ErrorSessionExpired:                  "Session expired. Re-authenticate to perform this action.",
	ErrorFailedToUnlinkLastAccount:       "You can't unlink your last account",
	ErrorAccountNotFound:                 "Account not found",
	ErrorUserAlreadyHasPassword:          "User already has a password. Provide that to delete the account.",
	ErrorCrossSiteNavigationLoginBlocked: "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
	ErrorVerificationEmailNotEnabled:     "Verification email isn't enabled",
	ErrorEmailAlreadyVerified:            "Email is already verified",
	ErrorEmailMismatch:                   "Email mismatch",
	ErrorSessionNotFresh:                 "Session is not fresh",
	ErrorLinkedAccountAlreadyExists:      "Linked account already exists",
	ErrorInvalidOrigin:                   "Invalid origin",
	ErrorInvalidCallbackURL:              "Invalid callbackURL",
	ErrorInvalidRedirectURL:              "Invalid redirectURL",
	ErrorInvalidErrorCallbackURL:         "Invalid errorCallbackURL",
	ErrorInvalidNewUserCallbackURL:       "Invalid newUserCallbackURL",
	ErrorMissingOrNullOrigin:             "Missing or null Origin",
	ErrorCallbackURLRequired:             "callbackURL is required",
	ErrorFailedToCreateVerification:      "Unable to create verification",
	ErrorFieldNotAllowed:                 "Field not allowed to be set",
	ErrorAsyncValidationNotSupported:     "Async validation is not supported",
	ErrorValidation:                      "Validation Error",
	ErrorMissingField:                    "Field is required",
	ErrorMethodNeedsDeferredSession:      "POST method requires deferSessionRefresh to be enabled in session config",
	ErrorBodyMustBeObject:                "Body must be an object",
	ErrorPasswordAlreadySet:              "User already has a password set",
}

// ErrorMessage returns a stable message or an empty string for unknown codes.
func ErrorMessage(code ErrorCode) string { return BaseErrorMessages[code] }
