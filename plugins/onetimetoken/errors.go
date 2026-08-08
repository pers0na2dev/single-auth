package onetimetoken

import "github.com/pers0na2dev/single-auth/core/contract"

func badRequest(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", message)
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}

func preserveRuntimeError(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return internalError(err)
}
