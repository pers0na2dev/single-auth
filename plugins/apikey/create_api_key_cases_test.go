package apikey

type createAPIKeyExpectedCase struct {
	Name string
	Want map[string]any
}

var createAPIKeyExpectedCases = []createAPIKeyExpectedCase{
	{
		Name: "create API key with with metadata when metadata is disabled (should fail)",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "METADATA_DISABLED",
				"message":    "Metadata is disabled.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "create API key's returned metadata should be an object",
		Want: map[string]any{
			"metadata": map[string]any{
				"test": "test-123",
			},
			"metadataIsObject": true,
		},
	},
	{
		Name: "should create an API key with a custom expiresIn",
		Want: map[string]any{
			"expiresAtPresent":                  true,
			"expiresWithinOneSecondOfRequested": true,
		},
	},
	{
		Name: "should create an API key with an expiresIn that's smaller than the allowed minimum",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "EXPIRES_IN_IS_TOO_SMALL",
				"message":    "The expiresIn is smaller than the predefined minimum value.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should create an API key with default permissions",
		Want: map[string]any{
			"permissions": map[string]any{
				"files": []any{
					"read",
				},
			},
		},
	},
	{
		Name: "should create an API key with permissions",
		Want: map[string]any{
			"permissions": map[string]any{
				"files": []any{
					"read",
					"write",
				},
				"users": []any{
					"read",
				},
			},
		},
	},
	{
		Name: "should create API Key with custom remaining",
		Want: map[string]any{
			"remaining": float64(10),
		},
	},
	{
		Name: "should create API key with invalid metadata",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "INVALID_METADATA_TYPE",
				"message":    "metadata must be an object or undefined",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should create API Key with remaining explicitly set to 0 and refillAmount also set",
		Want: map[string]any{
			"refillAmount":   float64(10),
			"refillInterval": float64(1000),
			"remaining":      float64(0),
		},
	},
	{
		Name: "should create API Key with remaining explicitly set to null",
		Want: map[string]any{
			"remaining": nil,
		},
	},
	{
		Name: "should create API Key with remaining explicitly set to null and refillAmount and refillInterval are also set",
		Want: map[string]any{
			"refillAmount":   float64(10),
			"refillInterval": float64(1000),
			"remaining":      nil,
		},
	},
	{
		Name: "should create API Key with remaining undefined and default value of null is respected with refillAmount and refillInterval provided",
		Want: map[string]any{
			"refillAmount":   float64(10),
			"refillInterval": float64(1000),
			"remaining":      nil,
		},
	},
	{
		Name: "should create API key with valid metadata",
		Want: map[string]any{
			"fetchedMetadata": map[string]any{
				"test": "test",
			},
			"metadata": map[string]any{
				"test": "test",
			},
		},
	},
	{
		Name: "should create the API key with a name that's longer than the allowed maximum",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "INVALID_NAME_LENGTH",
				"message":    "The name length is either too large or too small.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should create the API key with a name that's shorter than the allowed minimum",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "INVALID_NAME_LENGTH",
				"message":    "The name length is either too large or too small.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should create the API key with a prefix that's longer than the allowed maximum",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "INVALID_PREFIX_LENGTH",
				"message":    "The prefix length is either too large or too small.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should create the API key with a prefix that's shorter than the allowed minimum",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "INVALID_PREFIX_LENGTH",
				"message":    "The prefix length is either too large or too small.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should create the API key with the given name",
		Want: map[string]any{
			"name": "test-api-key",
		},
	},
	{
		Name: "should create the API key with the given prefix",
		Want: map[string]any{
			"keyStartsWithPrefix":   true,
			"prefix":                "test-api-key_",
			"randomCharacterLength": float64(64),
		},
	},
	{
		Name: "should create the API key with the given refill interval & refill amount",
		Want: map[string]any{
			"refillAmount":   float64(10),
			"refillInterval": float64(10000),
		},
	},
	{
		Name: "should fail to create a key with a custom expiresIn value when customExpiresTime is disabled",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "KEY_DISABLED_EXPIRATION",
				"message":    "Custom key expiration values are disabled.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should fail to create an API key with an expiresIn that's larger than the allowed maximum",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "EXPIRES_IN_IS_TOO_LARGE",
				"message":    "The expiresIn is larger than the predefined maximum value.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should fail to create API key when refill amount is provided, but no refill interval",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "REFILL_AMOUNT_AND_INTERVAL_REQUIRED",
				"message":    "refillAmount is required when refillInterval is provided",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should fail to create API key when refill interval is provided, but no refill amount",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "REFILL_INTERVAL_AND_AMOUNT_REQUIRED",
				"message":    "refillInterval is required when refillAmount is provided",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should fail to create API key with custom rate-limit options from client auth",
		Want: map[string]any{
			"rateLimitMax": map[string]any{
				"code":       "SERVER_ONLY_PROPERTY",
				"message":    "The property you're trying to set can only be set from the server auth instance only.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
			"rateLimitTimeWindow": map[string]any{
				"code":       "SERVER_ONLY_PROPERTY",
				"message":    "The property you're trying to set can only be set from the server auth instance only.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should fail to create API key with custom refillAndAmount from client auth",
		Want: map[string]any{
			"refillAmount": map[string]any{
				"code":       "SERVER_ONLY_PROPERTY",
				"message":    "The property you're trying to set can only be set from the server auth instance only.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
			"refillInterval": map[string]any{
				"code":       "SERVER_ONLY_PROPERTY",
				"message":    "The property you're trying to set can only be set from the server auth instance only.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should fail to create API keys from client without headers",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "UNAUTHORIZED_SESSION",
				"message":    "Unauthorized or invalid session",
				"status":     "UNAUTHORIZED",
				"statusCode": float64(401),
			},
		},
	},
	{
		Name: "should fail to create API Keys from server without headers and userId",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "UNAUTHORIZED_SESSION",
				"message":    "Unauthorized or invalid session",
				"status":     "UNAUTHORIZED",
				"statusCode": float64(401),
			},
		},
	},
	{
		Name: "should fail to create api keys from the client if user id is provided",
		Want: map[string]any{
			"withSession": map[string]any{
				"code":       "UNAUTHORIZED_SESSION",
				"message":    "Unauthorized or invalid session",
				"status":     "UNAUTHORIZED",
				"statusCode": float64(401),
			},
			"withoutSession": map[string]any{
				"code":       "UNAUTHORIZED_SESSION",
				"message":    "Unauthorized or invalid session",
				"status":     "UNAUTHORIZED",
				"statusCode": float64(401),
			},
		},
	},
	{
		Name: "should have the first 6 characters of the key as the start property",
		Want: map[string]any{
			"startLength":     float64(6),
			"startMatchesKey": true,
			"startPresent":    true,
		},
	},
	{
		Name: "should have the real value from rateLimitEnabled",
		Want: map[string]any{
			"rateLimitEnabled": false,
		},
	},
	{
		Name: "should have the start property as null if shouldStore is false",
		Want: map[string]any{
			"start": nil,
		},
	},
	{
		Name: "should have true if the rate limit is undefined",
		Want: map[string]any{
			"rateLimitEnabled": true,
		},
	},
	{
		Name: "should require name in API keys if configured",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "NAME_REQUIRED",
				"message":    "API Key name is required.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should respect rateLimit configuration from plugin options",
		Want: map[string]any{
			"rateLimitEnabled":    false,
			"rateLimitMax":        float64(10),
			"rateLimitTimeWindow": float64(1000),
		},
	},
	{
		Name: "should successfully apply custom rate-limit options on the newly created API key",
		Want: map[string]any{
			"rateLimitMax":        float64(15),
			"rateLimitTimeWindow": float64(1000),
		},
	},
	{
		Name: "should successfully create API keys from client with headers",
		Want: map[string]any{
			"clientError":      true,
			"createdAtPresent": true,
			"enabled":          true,
			"expiresAt":        nil,
			"keyPresent":       true,
			"lastRefillAt":     nil,
			"lastRequest":      nil,
			"metadata":         nil,
			"name":             nil,
			"permissions": map[string]any{
				"files": []any{
					"read",
				},
			},
			"prefix":                nil,
			"randomCharacterLength": float64(64),
			"rateLimitEnabled":      true,
			"rateLimitMax":          float64(10),
			"rateLimitTimeWindow":   float64(8.64e+07),
			"referenceMatches":      true,
			"refillAmount":          nil,
			"refillInterval":        nil,
			"remaining":             nil,
			"requestCount":          float64(0),
			"updatedAtPresent":      true,
		},
	},
	{
		Name: "should successfully create API keys from server with userId",
		Want: map[string]any{
			"createdAtPresent": true,
			"enabled":          true,
			"expiresAt":        nil,
			"keyPresent":       true,
			"lastRefillAt":     nil,
			"lastRequest":      nil,
			"metadata":         nil,
			"name":             nil,
			"permissions": map[string]any{
				"files": []any{
					"read",
				},
			},
			"prefix":                nil,
			"randomCharacterLength": float64(64),
			"rateLimitEnabled":      true,
			"rateLimitMax":          float64(10),
			"rateLimitTimeWindow":   float64(8.64e+07),
			"referenceMatches":      true,
			"refillAmount":          nil,
			"refillInterval":        nil,
			"remaining":             nil,
			"requestCount":          float64(0),
			"updatedAtPresent":      true,
		},
	},
	{
		Name: "should support disabling key hashing",
		Want: map[string]any{
			"storedEqualsPlaintext": true,
		},
	},
	{
		Name: "should use the defined charactersLength if provided",
		Want: map[string]any{
			"startLength":     float64(3),
			"startMatchesKey": true,
			"startPresent":    true,
		},
	},
}
