package apikey

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	ErrorInvalidMetadataType               = "INVALID_METADATA_TYPE"
	ErrorMetadataDisabled                  = "METADATA_DISABLED"
	ErrorRefillAmountAndIntervalRequired   = "REFILL_AMOUNT_AND_INTERVAL_REQUIRED"
	ErrorRefillIntervalAndAmountRequired   = "REFILL_INTERVAL_AND_AMOUNT_REQUIRED"
	ErrorUnauthorizedSession               = "UNAUTHORIZED_SESSION"
	ErrorKeyNotFound                       = "KEY_NOT_FOUND"
	ErrorKeyDisabled                       = "KEY_DISABLED"
	ErrorKeyExpired                        = "KEY_EXPIRED"
	ErrorInvalidPrefixLength               = "INVALID_PREFIX_LENGTH"
	ErrorInvalidNameLength                 = "INVALID_NAME_LENGTH"
	ErrorInvalidAPIKey                     = "INVALID_API_KEY"
	ErrorServerOnlyProperty                = "SERVER_ONLY_PROPERTY"
	ErrorNameRequired                      = "NAME_REQUIRED"
	ErrorKeyDisabledExpiration             = "KEY_DISABLED_EXPIRATION"
	ErrorExpiresInTooSmall                 = "EXPIRES_IN_IS_TOO_SMALL"
	ErrorExpiresInTooLarge                 = "EXPIRES_IN_IS_TOO_LARGE"
	ErrorNoValuesToUpdate                  = "NO_VALUES_TO_UPDATE"
	ErrorUsageExceeded                     = "USAGE_EXCEEDED"
	ErrorRateLimited                       = "RATE_LIMITED"
	ErrorInvalidReferenceID                = "INVALID_REFERENCE_ID_FROM_API_KEY"
	ErrorOrganizationIDRequired            = "ORGANIZATION_ID_REQUIRED"
	ErrorUserNotMemberOfOrganization       = "USER_NOT_MEMBER_OF_ORGANIZATION"
	ErrorInsufficientAPIKeyPermissions     = "INSUFFICIENT_API_KEY_PERMISSIONS"
	ErrorNoDefaultAPIKeyConfigurationFound = "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND"
	ErrorOrganizationPluginRequired        = "ORGANIZATION_PLUGIN_REQUIRED"
)

var errorMessages = map[string]string{
	ErrorInvalidMetadataType:               "metadata must be an object or undefined",
	ErrorMetadataDisabled:                  "Metadata is disabled.",
	ErrorRefillAmountAndIntervalRequired:   "refillAmount is required when refillInterval is provided",
	ErrorRefillIntervalAndAmountRequired:   "refillInterval is required when refillAmount is provided",
	ErrorUnauthorizedSession:               "Unauthorized or invalid session",
	ErrorKeyNotFound:                       "API Key not found",
	ErrorKeyDisabled:                       "API Key is disabled",
	ErrorKeyExpired:                        "API Key has expired",
	ErrorInvalidPrefixLength:               "The prefix length is either too large or too small.",
	ErrorInvalidNameLength:                 "The name length is either too large or too small.",
	ErrorInvalidAPIKey:                     "Invalid API key.",
	ErrorServerOnlyProperty:                "The property you're trying to set can only be set from the server auth instance only.",
	ErrorNameRequired:                      "API Key name is required.",
	ErrorKeyDisabledExpiration:             "Custom key expiration values are disabled.",
	ErrorExpiresInTooSmall:                 "The expiresIn is smaller than the predefined minimum value.",
	ErrorExpiresInTooLarge:                 "The expiresIn is larger than the predefined maximum value.",
	ErrorNoValuesToUpdate:                  "No values to update.",
	ErrorUsageExceeded:                     "API Key has reached its usage limit",
	ErrorRateLimited:                       "Rate limit exceeded.",
	ErrorInvalidReferenceID:                "The reference id from the API key is invalid.",
	ErrorOrganizationIDRequired:            "Organization ID is required for organization-owned API keys.",
	ErrorUserNotMemberOfOrganization:       "You are not a member of the organization that owns this API key.",
	ErrorInsufficientAPIKeyPermissions:     "You do not have permission to perform this action on organization API keys.",
	ErrorNoDefaultAPIKeyConfigurationFound: "No default api-key configuration found.",
	ErrorOrganizationPluginRequired:        "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.",
}

// ErrorBody is the stable client-facing API-key error representation.
type ErrorBody struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func apiError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Code: code, Message: message}
	}
	return result
}
