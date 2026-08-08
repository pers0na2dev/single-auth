package redis_e2e_test

var redisSmokeScenarios = []redisSmokeScenario{
	{Title: "should store session data in Redis after email signup", Expected: redisSmokeSessionObservation{TokenPresent: true, KeyCount: 2, ActiveSessionKeyCount: 1, SessionValuePresent: true, UserIDPresent: true, SessionIDPresent: true}},
	{Title: "should have session id in Redis when `storeSessionInDatabase` is true", Expected: redisSmokeSessionObservation{TokenPresent: true, KeyCount: 2, ActiveSessionKeyCount: 1, SessionValuePresent: true, UserIDPresent: true, SessionIDPresent: true}},
	{Title: "should store session data in Redis with stateless mode and Google OAuth", Expected: redisSmokeOAuthObservation{SignInStatus: 200, AuthorizationURLPresent: true, AuthorizationURLIncludesGoogle: true, StatePresent: true, StateCookiePresent: true, CallbackStatus: 302, CallbackLocationPresent: true, CallbackLocationIncludesCallback: true, KeyCount: 2, ActiveSessionKeyCount: 1, SessionValuePresent: true, UserIDPresent: true, SessionIDPresent: true, UserEmail: "google-user@example.com"}},
	{Title: "should use custom authorization endpoint for Google OAuth provider", Expected: redisSmokeCustomEndpointObservation{Status: 200, URLPresent: true, IncludesCustomEndpoint: true, ExcludesDefaultGoogleEndpoint: true, IncludesLocalhost8080: true}},
}
