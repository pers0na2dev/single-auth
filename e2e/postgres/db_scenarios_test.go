package postgres_e2e_test

var dbBehaviorScenarios = []dbBehaviorOracleTest{
	{Suite: "db", Title: "db hooks", Observation: dbBehaviorObservation{Image: "test-image", Callback: true}},
	{Suite: "db", Title: "db hooks should preserve a forced UUID on postgres when generateId is uuid", Observation: dbBehaviorObservation{
		ResultIDMatches: true, StoredIDMatches: true, StoredEmailMatches: true,
	}},
	{Suite: "db", Title: "delete hooks", Observation: dbBehaviorObservation{
		UserDeleteBefore: 1, UserDeleteAfter: 1, SessionDeleteBefore: 1, SessionDeleteAfter: 1,
		BeforeUserMatches: true, AfterUserMatches: true, BeforeContextObject: true, AfterContextObject: true,
	}},
	{Suite: "db", Title: "delete hooks abort", Observation: dbBehaviorObservation{
		UserDeleteBefore: 1, BeforeUserMatches: true, BeforeContextObject: true,
	}},
	{Suite: "db", Title: "should work with custom field names", Observation: dbBehaviorObservation{Email: "test@email.com"}},
	{Suite: "db", Title: "should work with custom model names", Observation: dbBehaviorObservation{
		ResponseDataDefined: true, Users: 2, Sessions: 2, Accounts: 2,
	}},
}
