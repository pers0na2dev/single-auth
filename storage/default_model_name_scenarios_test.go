package storage

var defaultModelNameScenarios = []defaultModelNameOracleTest{
	{
		Suite: "initGetDefaultModelName > user.modelName collision with account schema key",
		Title: "resolves a schema key to itself even when a modelName collides with it",
		Initializations: []defaultModelNameOracleInitialization{
			{UsePlural: false, ModelNames: map[string]string{"user": "account", "session": "session", "account": "identity", "verification": "verification"}},
		},
		Resolutions: []defaultModelNameOracleResolution{
			{Model: "account", Result: "account", HasResult: true},
		},
	},
	{
		Suite: "initGetDefaultModelName > user.modelName collision with account schema key",
		Title: "resolves the account's modelName alias to the account schema key",
		Initializations: []defaultModelNameOracleInitialization{
			{UsePlural: false, ModelNames: map[string]string{"user": "account", "session": "session", "account": "identity", "verification": "verification"}},
		},
		Resolutions: []defaultModelNameOracleResolution{
			{Model: "identity", Result: "account", HasResult: true},
		},
	},
	{
		Suite: "initGetDefaultModelName > user.modelName collision with account schema key",
		Title: "still resolves the original schema keys when no alias collides",
		Initializations: []defaultModelNameOracleInitialization{
			{UsePlural: false, ModelNames: map[string]string{"user": "account", "session": "session", "account": "identity", "verification": "verification"}},
		},
		Resolutions: []defaultModelNameOracleResolution{
			{Model: "user", Result: "user", HasResult: true},
			{Model: "session", Result: "session", HasResult: true},
			{Model: "verification", Result: "verification", HasResult: true},
		},
	},
	{
		Suite: "initGetDefaultModelName",
		Title: "handles usePlural by stripping the trailing s before lookup",
		Initializations: []defaultModelNameOracleInitialization{
			{UsePlural: true, ModelNames: map[string]string{"user": "user", "session": "session", "account": "account", "verification": "verification"}},
		},
		Resolutions: []defaultModelNameOracleResolution{
			{Model: "users", Result: "user", HasResult: true},
			{Model: "accounts", Result: "account", HasResult: true},
		},
	},
	{
		Suite: "initGetDefaultModelName",
		Title: "resolves a custom modelName back to its schema key",
		Initializations: []defaultModelNameOracleInitialization{
			{UsePlural: false, ModelNames: map[string]string{"user": "users_table", "session": "session", "account": "account", "verification": "verification"}},
		},
		Resolutions: []defaultModelNameOracleResolution{
			{Model: "users_table", Result: "user", HasResult: true},
			{Model: "user", Result: "user", HasResult: true},
		},
	},
	{
		Suite: "initGetDefaultModelName",
		Title: "returns the schema key for a built-in model with no modelName override",
		Initializations: []defaultModelNameOracleInitialization{
			{UsePlural: false, ModelNames: map[string]string{"user": "user", "session": "session", "account": "account", "verification": "verification"}},
		},
		Resolutions: []defaultModelNameOracleResolution{
			{Model: "user", Result: "user", HasResult: true},
			{Model: "account", Result: "account", HasResult: true},
			{Model: "session", Result: "session", HasResult: true},
		},
	},
	{
		Suite: "initGetDefaultModelName",
		Title: "throws when the model cannot be resolved",
		Initializations: []defaultModelNameOracleInitialization{
			{UsePlural: false, ModelNames: map[string]string{"user": "user", "session": "session", "account": "account", "verification": "verification"}},
		},
		Resolutions: []defaultModelNameOracleResolution{
			{Model: "does_not_exist", Error: &defaultModelNameOracleError{Message: "Model \"does_not_exist\" not found in schema"}},
		},
	},
}
