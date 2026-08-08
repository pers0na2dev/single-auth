package passkey

import "github.com/pers0na2dev/single-auth/core/engine"

const (
	ErrorChallengeNotFound          = "CHALLENGE_NOT_FOUND"
	ErrorRegistrationNotAllowed     = "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
	ErrorFailedToVerifyRegistration = "FAILED_TO_VERIFY_REGISTRATION"
	ErrorPasskeyNotFound            = "PASSKEY_NOT_FOUND"
	ErrorAuthenticationFailed       = "AUTHENTICATION_FAILED"
	ErrorUnableToCreateSession      = "UNABLE_TO_CREATE_SESSION"
	ErrorFailedToUpdatePasskey      = "FAILED_TO_UPDATE_PASSKEY"
	ErrorPreviouslyRegistered       = "PREVIOUSLY_REGISTERED"
	ErrorRegistrationCancelled      = "REGISTRATION_CANCELLED"
	ErrorAuthenticationCancelled    = "AUTH_CANCELLED"
	ErrorUnknown                    = "UNKNOWN_ERROR"
	ErrorSessionRequired            = "SESSION_REQUIRED"
	ErrorResolveUserRequired        = "RESOLVE_USER_REQUIRED"
	ErrorResolvedUserInvalid        = "RESOLVED_USER_INVALID"
)

var errorMessages = map[string]string{
	ErrorChallengeNotFound:          "Challenge not found",
	ErrorRegistrationNotAllowed:     "You are not allowed to register this passkey",
	ErrorFailedToVerifyRegistration: "Failed to verify registration",
	ErrorPasskeyNotFound:            "Passkey not found",
	ErrorAuthenticationFailed:       "Authentication failed",
	ErrorUnableToCreateSession:      "Unable to create session",
	ErrorFailedToUpdatePasskey:      "Failed to update passkey",
	ErrorPreviouslyRegistered:       "Previously registered",
	ErrorRegistrationCancelled:      "Registration cancelled",
	ErrorAuthenticationCancelled:    "Auth cancelled",
	ErrorUnknown:                    "Unknown error",
	ErrorSessionRequired:            "Passkey registration requires an authenticated session",
	ErrorResolveUserRequired:        "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
	ErrorResolvedUserInvalid:        "Resolved user is invalid",
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}
