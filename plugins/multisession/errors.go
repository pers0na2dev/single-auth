package multisession

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const ErrorInvalidSessionToken = "INVALID_SESSION_TOKEN"

const invalidSessionTokenMessage = "Invalid session token"

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	return map[string]engine.ErrorDefinition{
		ErrorInvalidSessionToken: {Message: invalidSessionTokenMessage},
	}
}

func invalidSessionToken() *contract.APIError {
	return contract.NewAPIError(
		contract.StatusUnauthorized,
		ErrorInvalidSessionToken,
		invalidSessionTokenMessage,
	)
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func unauthorized() *contract.APIError {
	return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}

func preserveRuntimeError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}
