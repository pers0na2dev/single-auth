package haveibeenpwned

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	return map[string]engine.ErrorDefinition{
		ErrorPasswordCompromised: {Message: DefaultCompromisedMessage},
	}
}

func compromisedError(message string) *contract.APIError {
	if message == "" {
		message = DefaultCompromisedMessage
	}
	return contract.NewAPIError(
		contract.StatusBadRequest,
		ErrorPasswordCompromised,
		message,
	)
}

func statusCheckError(status int) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		fmt.Sprintf("Failed to check password. Status: %d", status),
	)
}

func unavailableCheckError(cause error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Failed to check password. Please try again later.",
	).WithCause(cause)
}
