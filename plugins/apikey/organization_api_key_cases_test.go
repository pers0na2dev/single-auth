package apikey

type orgAPIKeyExpectedCase struct {
	Name string
	Want map[string]any
}

var orgAPIKeyExpectedCases = []orgAPIKeyExpectedCase{
	{
		Name: "member without apiKey permissions should be denied (default roles)",
		Want: map[string]any{
			"listError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
		},
	},
	{
		Name: "non-member should be denied access to organization API keys",
		Want: map[string]any{
			"createError": map[string]any{
				"code":    "USER_NOT_MEMBER_OF_ORGANIZATION",
				"message": "You are not a member of the organization that owns this API key.",
				"status":  float64(403),
			},
			"deleteError": map[string]any{
				"code":    "USER_NOT_MEMBER_OF_ORGANIZATION",
				"message": "You are not a member of the organization that owns this API key.",
				"status":  float64(403),
			},
			"expectedCode": "USER_NOT_MEMBER_OF_ORGANIZATION",
			"getError": map[string]any{
				"code":    "USER_NOT_MEMBER_OF_ORGANIZATION",
				"message": "You are not a member of the organization that owns this API key.",
				"status":  float64(403),
			},
			"listError": map[string]any{
				"code":    "USER_NOT_MEMBER_OF_ORGANIZATION",
				"message": "You are not a member of the organization that owns this API key.",
				"status":  float64(403),
			},
			"updateError": map[string]any{
				"code":    "USER_NOT_MEMBER_OF_ORGANIZATION",
				"message": "You are not a member of the organization that owns this API key.",
				"status":  float64(403),
			},
		},
	},
	{
		Name: "organization owner should have full CRUD access to API keys",
		Want: map[string]any{
			"createConfigMatches":    true,
			"createOK":               true,
			"createReferenceMatches": true,
			"deleteOK":               true,
			"getOK":                  true,
			"listHasKey":             true,
			"listOK":                 true,
			"updateOK":               true,
		},
	},
	{
		Name: "should correctly separate user and org keys when listing",
		Want: map[string]any{
			"orgListHasOrgKey":   true,
			"orgListHasUserKey":  false,
			"orgListOK":          true,
			"userListHasOrgKey":  false,
			"userListHasUserKey": true,
			"userListOK":         true,
		},
	},
	{
		Name: "verify API key should work for organization-owned keys",
		Want: map[string]any{
			"configMatches":    true,
			"referenceMatches": true,
			"valid":            true,
		},
	},
	{
		Name: "admin role should have full apiKey CRUD permissions",
		Want: map[string]any{
			"createError": map[string]any{
				"code":    nil,
				"message": nil,
				"status":  nil,
			},
			"createOK": true,
			"deleteError": map[string]any{
				"code":    nil,
				"message": nil,
				"status":  nil,
			},
			"deleteOK": true,
			"getError": map[string]any{
				"code":    nil,
				"message": nil,
				"status":  nil,
			},
			"getOK": true,
			"listError": map[string]any{
				"code":    nil,
				"message": nil,
				"status":  nil,
			},
			"listOK": true,
			"updateError": map[string]any{
				"code":    nil,
				"message": nil,
				"status":  nil,
			},
			"updateOK": true,
		},
	},
	{
		Name: "member role with read-only permission should be limited",
		Want: map[string]any{
			"createError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"createOK": false,
			"deleteError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"deleteOK": false,
			"getError": map[string]any{
				"code":    nil,
				"message": nil,
				"status":  nil,
			},
			"getOK": true,
			"listError": map[string]any{
				"code":    nil,
				"message": nil,
				"status":  nil,
			},
			"listOK": true,
			"updateError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"updateOK": false,
		},
	},
	{
		Name: "restricted role with no apiKey permissions should be fully denied",
		Want: map[string]any{
			"createError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"createOK": false,
			"deleteError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"deleteOK": false,
			"getError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"getOK": false,
			"listError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"listOK": false,
			"updateError": map[string]any{
				"code":    "INSUFFICIENT_API_KEY_PERMISSIONS",
				"message": "You do not have permission to perform this action on organization API keys.",
				"status":  float64(403),
			},
			"updateOK": false,
		},
	},
	{
		Name: "should not allow accessing org key with wrong configId",
		Want: map[string]any{
			"getError": map[string]any{
				"code":    "KEY_NOT_FOUND",
				"message": "API Key not found",
				"status":  float64(404),
			},
		},
	},
	{
		Name: "should return error when organization plugin is not installed",
		Want: map[string]any{
			"createError": map[string]any{
				"code":    "ORGANIZATION_PLUGIN_REQUIRED",
				"message": "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.",
				"status":  float64(500),
			},
		},
	},
}
