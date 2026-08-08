package apikey

type verifyUpdateGetListExpectedCase struct {
	Name string
	Want map[string]any
}

var verifyUpdateGetListExpectedCases = []verifyUpdateGetListExpectedCase{
	{
		Name: "should allow explicit remaining updates via body parameter",
		Want: map[string]any{
			"lastRequestNull": true,
			"remaining":       float64(50),
		},
	},
	{
		Name: "should allow us to verify API key after rate-limit window has passed",
		Want: map[string]any{
			"error":              nil,
			"keyNull":            false,
			"keyPresent":         true,
			"lastRequestPresent": true,
			"plaintextOmitted":   true,
			"remaining":          nil,
			"requestCount":       float64(1),
			"valid":              true,
		},
	},
	{
		Name: "should check if verifying an API key's remaining count does go down",
		Want: map[string]any{
			"assertionPathEntered": false,
			"creationError": map[string]any{
				"code":       "SERVER_ONLY_PROPERTY",
				"message":    "The property you're trying to set can only be set from the server auth instance only.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
			"creationSucceeded": false,
		},
	},
	{
		Name: "should fail if the API key has no remaining",
		Want: map[string]any{
			"first": map[string]any{
				"error":              nil,
				"keyNull":            false,
				"keyPresent":         true,
				"lastRequestPresent": true,
				"plaintextOmitted":   true,
				"remaining":          float64(0),
				"requestCount":       float64(1),
				"valid":              true,
			},
			"second": map[string]any{
				"error": map[string]any{
					"code":    "USAGE_EXCEEDED",
					"message": "API Key has reached its usage limit",
				},
				"keyNull":            true,
				"keyPresent":         false,
				"lastRequestPresent": false,
				"plaintextOmitted":   true,
				"remaining":          nil,
				"requestCount":       nil,
				"valid":              false,
			},
		},
	},
	{
		Name: "should fail if the API key is expired",
		Want: map[string]any{
			"error": map[string]any{
				"code":    "KEY_EXPIRED",
				"message": "API Key has expired",
			},
			"keyNull":            true,
			"keyPresent":         false,
			"lastRequestPresent": false,
			"plaintextOmitted":   true,
			"remaining":          nil,
			"requestCount":       nil,
			"valid":              false,
		},
	},
	{
		Name: "should fail to get an API key by ID that doesn't exist",
		Want: map[string]any{
			"dataNull": true,
			"error": map[string]any{
				"code":       "KEY_NOT_FOUND",
				"message":    "API Key not found",
				"status":     "NOT_FOUND",
				"statusCode": float64(404),
			},
		},
	},
	{
		Name: "should fail to list API keys without headers",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "UNAUTHORIZED",
				"message":    "Unauthorized",
				"status":     "UNAUTHORIZED",
				"statusCode": float64(401),
			},
		},
	},
	{
		Name: "should fail to update API key name with a length larger than the allowed maximum",
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
		Name: "should fail to update API key name with a length smaller than the allowed minimum",
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
		Name: "should fail to update API key name without headers or userId",
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
		Name: "should fail to update API key with no values to update",
		Want: map[string]any{
			"error": map[string]any{
				"code":       "NO_VALUES_TO_UPDATE",
				"message":    "No values to update.",
				"status":     "BAD_REQUEST",
				"statusCode": float64(400),
			},
		},
	},
	{
		Name: "should fail to update expiresIn value if `disableCustomExpiresTime` is enabled",
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
		Name: "should fail to update expiresIn value if it's larger than the allowed maximum",
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
		Name: "should fail to update expiresIn value if it's smaller than the allowed minimum",
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
		Name: "should fail to update metadata with invalid metadata type",
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
		Name: "should fail to verify API key 20 times in a row due to rate-limit",
		Want: map[string]any{
			"errorCodes": []any{
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				nil,
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
				"RATE_LIMITED",
			},
			"valids": []any{
				true,
				true,
				true,
				true,
				true,
				true,
				true,
				true,
				true,
				true,
				false,
				false,
				false,
				false,
				false,
				false,
				false,
				false,
				false,
				false,
			},
		},
	},
	{
		Name: "should fail update the refillAmount value since it requires refillInterval as well",
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
		Name: "should fail update the refillInterval value since it requires refillAmount as well",
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
		Name: "should get an API key by id",
		Want: map[string]any{
			"dataPresent":      true,
			"errorNull":        true,
			"idMatches":        true,
			"plaintextOmitted": true,
		},
	},
	{
		Name: "should list API keys with headers",
		Want: map[string]any{
			"nonEmpty":         true,
			"plaintextOmitted": true,
			"totalMatches":     true,
			"totalPositive":    true,
		},
	},
	{
		Name: "should list API keys with metadata as an object",
		Want: map[string]any{
			"allMetadataObjects": true,
			"firstMetadata": map[string]any{
				"test": "list-object",
			},
			"metadataCount": float64(1),
			"nonEmpty":      true,
		},
	},
	{
		Name: "should not auto-decrement remaining when updating API key",
		Want: map[string]any{
			"after":  float64(100),
			"before": float64(100),
		},
	},
	{
		Name: "should not modify lastRequest when updating API key configuration",
		Want: map[string]any{
			"after":  true,
			"before": true,
		},
	},
	{
		Name: "should return 429 when API key rate limit is exceeded via before hook",
		Want: map[string]any{
			"firstError":  true,
			"secondError": true,
			"thirdError": map[string]any{
				"code":       "RATE_LIMITED",
				"message":    "Rate limit exceeded.",
				"status":     "TOO_MANY_REQUESTS",
				"statusCode": float64(429),
			},
		},
	},
	{
		Name: "should successfully receive an object metadata from an API key",
		Want: map[string]any{
			"metadata": map[string]any{
				"test": "get-object",
			},
			"metadataDefined":  true,
			"metadataIsObject": true,
		},
	},
	{
		Name: "should update API key enable value",
		Want: map[string]any{
			"enabled": false,
		},
	},
	{
		Name: "should update API key expiresIn value",
		Want: map[string]any{
			"expiresAtPresent":   true,
			"expiresInSevenDays": true,
		},
	},
	{
		Name: "should update API key name with headers",
		Want: map[string]any{
			"idMatches":        true,
			"name":             "Hello World",
			"nameChanged":      true,
			"plaintextOmitted": true,
		},
	},
	{
		Name: "should update API key remaining count",
		Want: map[string]any{
			"remaining": float64(100),
		},
	},
	{
		Name: "should update metadata with valid metadata type",
		Want: map[string]any{
			"metadata": map[string]any{
				"test": "test-123",
			},
		},
	},
	{
		Name: "should update the refillInterval and refillAmount value",
		Want: map[string]any{
			"refillAmount":   float64(100),
			"refillInterval": float64(10000),
		},
	},
	{
		Name: "update API key's returned metadata should be an object",
		Want: map[string]any{
			"metadata": map[string]any{
				"test": "test-12345",
			},
			"metadataIsObject": true,
		},
	},
	{
		Name: "verify API key with invalid key (should fail)",
		Want: map[string]any{
			"error": map[string]any{
				"code":    "INVALID_API_KEY",
				"message": "Invalid API key.",
			},
			"keyNull":            true,
			"keyPresent":         false,
			"lastRequestPresent": false,
			"plaintextOmitted":   true,
			"remaining":          nil,
			"requestCount":       nil,
			"valid":              false,
		},
	},
	{
		Name: "verify API key without key and userId",
		Want: map[string]any{
			"error":              nil,
			"keyNull":            false,
			"keyPresent":         true,
			"lastRequestPresent": true,
			"plaintextOmitted":   true,
			"remaining":          nil,
			"requestCount":       float64(1),
			"valid":              true,
		},
	},
	{
		Name: "verifyApiKey should still decrement remaining",
		Want: map[string]any{
			"remaining": float64(99),
		},
	},
	{
		Name: "verifyApiKey should still update lastRequest",
		Want: map[string]any{
			"initialLastRequestNull": true,
			"lastRequestPresent":     true,
			"valid":                  true,
		},
	},
}
