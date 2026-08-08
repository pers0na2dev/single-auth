package deprecateutil

var deprecateCases = []deprecateOracleTest{
	{ID: "deprecate::should fall back to console.warn if no logger provided", Scenarios: []deprecateOracleScenario{
		{Message: "test message", LoggerProvided: false, Warnings: []string{"[Deprecation] test message"}, Calls: []deprecateOracleCall{
			{Args: []int{}},
		}},
	}},
	{ID: "deprecate::should pass arguments and return value correctly", Scenarios: []deprecateOracleScenario{
		{Message: "test message", LoggerProvided: true, Warnings: []string{"[Deprecation] test message"}, Calls: []deprecateOracleCall{
			{Args: []int{1, 2}, Output: intPointer(3)},
		}},
	}},
	{ID: "deprecate::should preserve this context", Scenarios: []deprecateOracleScenario{
		{Message: "test message", LoggerProvided: true, Warnings: []string{"[Deprecation] test message"}, Calls: []deprecateOracleCall{
			{Args: []int{5}, Output: intPointer(15), ReceiverValue: intPointer(10)},
		}},
	}},
	{ID: "deprecate::should use provided logger if available", Scenarios: []deprecateOracleScenario{
		{Message: "test message", LoggerProvided: true, Warnings: []string{"[Deprecation] test message"}, Calls: []deprecateOracleCall{
			{Args: []int{}},
		}},
	}},
	{ID: "deprecate::should warn once when called multiple times", Scenarios: []deprecateOracleScenario{
		{Message: "test message", LoggerProvided: true, Warnings: []string{"[Deprecation] test message"}, Calls: []deprecateOracleCall{
			{Args: []int{}},
			{Args: []int{}},
			{Args: []int{}},
		}},
	}},
}
