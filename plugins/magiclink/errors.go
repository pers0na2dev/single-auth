package magiclink

import (
	"github.com/pers0na2dev/single-auth/core/contract"
)

func apiError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func validationError(message string) *contract.APIError {
	return apiError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func invalidEmail() *contract.APIError {
	return apiError(contract.StatusBadRequest, "INVALID_EMAIL", "Invalid email")
}

func internalError(err error) *contract.APIError {
	return apiError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error").WithCause(err)
}

func preserveRuntimeError(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return internalError(err)
}
