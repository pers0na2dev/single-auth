package scim

type scimPatchExpectedCase struct {
	Name string
	Mode string
	Want scimPatchResult
}

func scimPatchStringPointer(value string) *string { return &value }

var scimPatchExpectedCases = []scimPatchExpectedCase{
	{
		Name: "should add nested object values with path prefix",
		Mode: "nested-add",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "Nested User",
				EmailPrimary:  true,
				EmailValue:    "nested-test-user-updated",
				ExternalID:    scimPatchStringPointer("nested-test-user"),
				NameFormatted: "Nested User",
				UserName:      "nested-test-user-updated",
			},
		},
	},
	{
		Name: "should fail on invalid updates",
		Mode: "empty-operations",
		Want: scimPatchResult{
			Status: 400,
			Error: &scimPatchErrorResult{
				Status:  400,
				Detail:  scimPatchStringPointer("No valid fields to update"),
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			},
		},
	},
	{
		Name: "should handle add operation case-insensitively",
		Mode: "case-add",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "user-case",
				EmailPrimary:  true,
				EmailValue:    "user-case-insensitive",
				ExternalID:    scimPatchStringPointer("user-case-insensitive"),
				NameFormatted: "user-case",
				UserName:      "user-case-insensitive",
			},
		},
	},
	{
		Name: "should handle replace operation case-insensitively",
		Mode: "case-replace",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "user-case",
				EmailPrimary:  true,
				EmailValue:    "user-case-insensitive",
				ExternalID:    scimPatchStringPointer("user-case-insensitive"),
				NameFormatted: "user-case",
				UserName:      "user-case-insensitive",
			},
		},
	},
	{
		Name: "should ignore add on non-existing path",
		Mode: "unknown-path-add",
		Want: scimPatchResult{
			Status: 400,
			Error: &scimPatchErrorResult{
				Status:  400,
				Detail:  scimPatchStringPointer("No valid fields to update"),
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			},
		},
	},
	{
		Name: "should ignore non-existing operation",
		Mode: "unknown-operation",
		Want: scimPatchResult{
			Status: 400,
			Error: &scimPatchErrorResult{
				Status:  400,
				Code:    scimPatchStringPointer("VALIDATION_ERROR"),
				Message: scimPatchStringPointer("[body.Operations.0.op] Invalid option: expected one of \"replace\"|\"add\"|\"remove\""),
				Schemas: []string{},
			},
		},
	},
	{
		Name: "should ignore replace on non-existing path",
		Mode: "unknown-path-replace",
		Want: scimPatchResult{
			Status: 400,
			Error: &scimPatchErrorResult{
				Status:  400,
				Detail:  scimPatchStringPointer("No valid fields to update"),
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			},
		},
	},
	{
		Name: "should not allow anonymous access",
		Mode: "anonymous",
		Want: scimPatchResult{
			Status: 401,
			Error: &scimPatchErrorResult{
				Status:  401,
				Detail:  scimPatchStringPointer("SCIM token is required"),
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			},
		},
	},
	{
		Name: "should partially update a user resource with add",
		Mode: "partial-add",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "Daniel Perez",
				EmailPrimary:  true,
				EmailValue:    "other-username",
				ExternalID:    scimPatchStringPointer("external-username"),
				NameFormatted: "Daniel Perez",
				UserName:      "other-username",
			},
		},
	},
	{
		Name: "should partially update a user resource with mixed operations",
		Mode: "mixed",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "Daniel Lopez",
				EmailPrimary:  true,
				EmailValue:    "other-username",
				ExternalID:    scimPatchStringPointer("external-username"),
				NameFormatted: "Daniel Lopez",
				UserName:      "other-username",
			},
		},
	},
	{
		Name: "should partially update a user resource with replace",
		Mode: "partial-replace",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "Daniel Perez",
				EmailPrimary:  true,
				EmailValue:    "other-username",
				ExternalID:    scimPatchStringPointer("external-username"),
				NameFormatted: "Daniel Perez",
				UserName:      "other-username",
			},
		},
	},
	{
		Name: "should partially update multiple name sub-attributes with add",
		Mode: "name-add",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "Updated Value",
				EmailPrimary:  true,
				EmailValue:    "sub-attribute-test-user",
				ExternalID:    scimPatchStringPointer("sub-attribute-test-user"),
				NameFormatted: "Updated Value",
				UserName:      "sub-attribute-test-user",
			},
		},
	},
	{
		Name: "should partially update multiple name sub-attributes with replace",
		Mode: "name-replace",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "Updated Value",
				EmailPrimary:  true,
				EmailValue:    "sub-attribute-test-user",
				ExternalID:    scimPatchStringPointer("sub-attribute-test-user"),
				NameFormatted: "Updated Value",
				UserName:      "sub-attribute-test-user",
			},
		},
	},
	{
		Name: "should replace nested object values with path prefix",
		Mode: "nested-replace",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "Nested User",
				EmailPrimary:  true,
				EmailValue:    "nested-test-user-updated",
				ExternalID:    scimPatchStringPointer("nested-test-user"),
				NameFormatted: "Nested User",
				UserName:      "nested-test-user-updated",
			},
		},
	},
	{
		Name: "should return not found for missing users",
		Mode: "missing-user",
		Want: scimPatchResult{
			Status: 404,
			Error: &scimPatchErrorResult{
				Status:  404,
				Detail:  scimPatchStringPointer("User not found"),
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			},
		},
	},
	{
		Name: "should skip add operation when value already exists",
		Mode: "add-existing",
		Want: scimPatchResult{
			Status: 400,
			Error: &scimPatchErrorResult{
				Status:  400,
				Detail:  scimPatchStringPointer("No valid fields to update"),
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			},
		},
	},
	{
		Name: "should support dot notation in paths",
		Mode: "dot-path",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "User Dot",
				EmailPrimary:  true,
				EmailValue:    "username",
				ExternalID:    scimPatchStringPointer("dot-notation-user"),
				NameFormatted: "User Dot",
				UserName:      "username",
			},
		},
	},
	{
		Name: "should support operations without explicit path with add",
		Mode: "no-path-add",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "No Path Name",
				EmailPrimary:  true,
				EmailValue:    "username",
				ExternalID:    scimPatchStringPointer("no-path-test-user"),
				NameFormatted: "No Path Name",
				UserName:      "username",
			},
		},
	},
	{
		Name: "should support operations without explicit path with replace",
		Mode: "no-path-replace",
		Want: scimPatchResult{
			Status: 204,
			Resource: &scimPatchResourceResult{
				Active:        true,
				DisplayName:   "No Path Name",
				EmailPrimary:  true,
				EmailValue:    "username",
				ExternalID:    scimPatchStringPointer("no-path-test-user"),
				NameFormatted: "No Path Name",
				UserName:      "username",
			},
		},
	},
}
