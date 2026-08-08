package genericoauth

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	ErrorInvalidOAuthConfiguration = "INVALID_OAUTH_CONFIGURATION"
	ErrorTokenURLNotFound          = "TOKEN_URL_NOT_FOUND"
	ErrorProviderConfigNotFound    = "PROVIDER_CONFIG_NOT_FOUND"
	ErrorProviderIDRequired        = "PROVIDER_ID_REQUIRED"
	ErrorInvalidOAuthConfig        = "INVALID_OAUTH_CONFIG"
	ErrorSessionRequired           = "SESSION_REQUIRED"
	ErrorIssuerMismatch            = "ISSUER_MISMATCH"
	ErrorIssuerMissing             = "ISSUER_MISSING"
)

var ErrorMessages = map[string]string{
	ErrorInvalidOAuthConfiguration: "Invalid OAuth configuration",
	ErrorTokenURLNotFound:          "Invalid OAuth configuration. Token URL not found.",
	ErrorProviderConfigNotFound:    "No config found for provider",
	ErrorProviderIDRequired:        "Provider ID is required",
	ErrorInvalidOAuthConfig:        "Invalid OAuth configuration.",
	ErrorSessionRequired:           "Session is required",
	ErrorIssuerMismatch:            "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207).",
	ErrorIssuerMissing:             "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207).",
}

func apiError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func invalidConfiguration() *contract.APIError {
	return apiError(contract.StatusBadRequest, ErrorInvalidOAuthConfiguration, ErrorMessages[ErrorInvalidOAuthConfiguration])
}

func errorDefinitions() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(ErrorMessages))
	for code, message := range ErrorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}
