package oauth2

func fixturePointer[T any](value T) *T { return &value }

var refreshAccessTokenCases = []refreshAccessTokenOracleTest{refreshAccessTokenOracleTest{Title: "should not set refreshTokenExpiresAt when refresh_token_expires_in is not returned", Observation: refreshAccessTokenOracleObservation{Response: map[string]interface{}{"access_token": "new-access-token", "expires_in": 3600, "refresh_token": "new-refresh-token", "token_type": "Bearer"}, RequestMethod: "POST", RequestBody: "grant_type=refresh_token&refresh_token=old-refresh-token&client_id=test-client&client_secret=test-secret", AccessToken: "new-access-token", RefreshToken: "new-refresh-token", TokenType: "Bearer", AccessTokenExpiresIn: fixturePointer(int64(3600))}}, refreshAccessTokenOracleTest{Title: "should set accessTokenExpiresAt when expires_in is returned", Observation: refreshAccessTokenOracleObservation{Response: map[string]interface{}{"access_token": "new-access-token", "expires_in": 3600, "refresh_token": "new-refresh-token", "token_type": "Bearer"}, RequestMethod: "POST", RequestBody: "grant_type=refresh_token&refresh_token=old-refresh-token&client_id=test-client&client_secret=test-secret", AccessToken: "new-access-token", RefreshToken: "new-refresh-token", TokenType: "Bearer", AccessTokenExpiresIn: fixturePointer(int64(3600))}}, refreshAccessTokenOracleTest{Title: "should set refreshTokenExpiresAt when refresh_token_expires_in is returned", Observation: refreshAccessTokenOracleObservation{Response: map[string]interface{}{"access_token": "new-access-token", "expires_in": 3600, "refresh_token": "new-refresh-token", "refresh_token_expires_in": 86400, "token_type": "Bearer"}, RequestMethod: "POST", RequestBody: "grant_type=refresh_token&refresh_token=old-refresh-token&client_id=test-client&client_secret=test-secret", AccessToken: "new-access-token", RefreshToken: "new-refresh-token", TokenType: "Bearer", AccessTokenExpiresIn: fixturePointer(int64(3600)), RefreshTokenExpiresIn: fixturePointer(int64(86400))}}}

var rejectRedirectCases = []rejectRedirectsOracleTest{rejectRedirectsOracleTest{Title: "does not throw on a non-redirect response", Observation: rejectRedirectsOracleObservation{Endpoint: "https://idp.example/token", Cases: []rejectRedirectsOracleCase{rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 200, Type: "basic"}}, rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 304, Type: "basic"}}, rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 400, Type: "basic"}}, rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 401, Type: "basic"}}}}}, rejectRedirectsOracleTest{Title: "throws on a 3xx status (undici-style manual redirect)", Observation: rejectRedirectsOracleObservation{Endpoint: "https://idp.example/token", Cases: []rejectRedirectsOracleCase{rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 301, Type: "basic"}, Threw: true, ErrorName: fixturePointer("SingleAuthError"), ErrorMessage: fixturePointer("The OAuth endpoint \"https://idp.example/token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.")}, rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 302, Type: "basic"}, Threw: true, ErrorName: fixturePointer("SingleAuthError"), ErrorMessage: fixturePointer("The OAuth endpoint \"https://idp.example/token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.")}, rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 303, Type: "basic"}, Threw: true, ErrorName: fixturePointer("SingleAuthError"), ErrorMessage: fixturePointer("The OAuth endpoint \"https://idp.example/token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.")}, rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 307, Type: "basic"}, Threw: true, ErrorName: fixturePointer("SingleAuthError"), ErrorMessage: fixturePointer("The OAuth endpoint \"https://idp.example/token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.")}, rejectRedirectsOracleCase{Response: ResponseMetadata{Status: 308, Type: "basic"}, Threw: true, ErrorName: fixturePointer("SingleAuthError"), ErrorMessage: fixturePointer("The OAuth endpoint \"https://idp.example/token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.")}}}}, rejectRedirectsOracleTest{Title: "throws on an opaque redirect (spec-runtime manual redirect)", Observation: rejectRedirectsOracleObservation{Endpoint: "https://idp.example/token", Cases: []rejectRedirectsOracleCase{rejectRedirectsOracleCase{Response: ResponseMetadata{Type: "opaqueredirect"}, Threw: true, ErrorName: fixturePointer("SingleAuthError"), ErrorMessage: fixturePointer("The OAuth endpoint \"https://idp.example/token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.")}}}}}

var rejectRedirectRuntimeCases = []struct {
	ID          string                            "json:\"id\""
	File        string                            "json:\"file\""
	Suite       string                            "json:\"suite\""
	Title       string                            "json:\"title\""
	Observation rejectRedirectsRuntimeObservation "json:\"observation\""
}{struct {
	ID          string                            "json:\"id\""
	File        string                            "json:\"file\""
	Suite       string                            "json:\"suite\""
	Title       string                            "json:\"title\""
	Observation rejectRedirectsRuntimeObservation "json:\"observation\""
}{Suite: "server-side OAuth fetch refuses redirects via real betterFetch", Title: "rejects a 302 from the token endpoint and never follows it", Observation: rejectRedirectsRuntimeObservation{Rejected: true, ErrorName: "SingleAuthError", ErrorMessage: "The OAuth endpoint \"https://idp.example/token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.", FetchCallCount: 1, Redirect: "manual"}}}

var rejectRedirectServerCases = []struct {
	ID          string                     "json:\"id\""
	File        string                     "json:\"file\""
	Suite       string                     "json:\"suite\""
	Title       string                     "json:\"title\""
	Observation rejectRedirectsObservation "json:\"observation\""
}{struct {
	ID          string                     "json:\"id\""
	File        string                     "json:\"file\""
	Suite       string                     "json:\"suite\""
	Title       string                     "json:\"title\""
	Observation rejectRedirectsObservation "json:\"observation\""
}{Suite: "server-side OAuth fetches never follow a redirect to an internal host", Title: "clientCredentialsToken rejects the redirect and never connects to the internal host", Observation: rejectRedirectsObservation{Rejected: true, ErrorMessage: "The OAuth endpoint \"<baseUrl>/redirecting-token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL."}}, struct {
	ID          string                     "json:\"id\""
	File        string                     "json:\"file\""
	Suite       string                     "json:\"suite\""
	Title       string                     "json:\"title\""
	Observation rejectRedirectsObservation "json:\"observation\""
}{Suite: "server-side OAuth fetches never follow a redirect to an internal host", Title: "refreshAccessToken rejects the redirect and never connects to the internal host", Observation: rejectRedirectsObservation{Rejected: true, ErrorMessage: "The OAuth endpoint \"<baseUrl>/redirecting-token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL."}}, struct {
	ID          string                     "json:\"id\""
	File        string                     "json:\"file\""
	Suite       string                     "json:\"suite\""
	Title       string                     "json:\"title\""
	Observation rejectRedirectsObservation "json:\"observation\""
}{Suite: "server-side OAuth fetches never follow a redirect to an internal host", Title: "sanity: a client that follows redirects does reach the internal endpoint", Observation: rejectRedirectsObservation{ResponseStatus: 200, InternalHit: true}}, struct {
	ID          string                     "json:\"id\""
	File        string                     "json:\"file\""
	Suite       string                     "json:\"suite\""
	Title       string                     "json:\"title\""
	Observation rejectRedirectsObservation "json:\"observation\""
}{Suite: "server-side OAuth fetches never follow a redirect to an internal host", Title: "validateAuthorizationCode rejects the redirect and never connects to the internal host", Observation: rejectRedirectsObservation{Rejected: true, ErrorMessage: "The OAuth endpoint \"<baseUrl>/redirecting-token\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL."}}, struct {
	ID          string                     "json:\"id\""
	File        string                     "json:\"file\""
	Suite       string                     "json:\"suite\""
	Title       string                     "json:\"title\""
	Observation rejectRedirectsObservation "json:\"observation\""
}{Suite: "server-side OAuth fetches never follow a redirect to an internal host", Title: "validateToken (JWKS) rejects the redirect and never connects to the internal host", Observation: rejectRedirectsObservation{Rejected: true, ErrorMessage: "The OAuth endpoint \"<baseUrl>/redirecting-jwks\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL."}}}

var validateTokenCases = []struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "refuses a redirecting JWKS endpoint and fetches with redirects disabled", Observation: map[string]interface{}{"redirect": "manual", "rejected": true, "ssrfMessage": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should find correct key when multiple keys exist", Observation: map[string]interface{}{"sub": "user-123", "verified": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should reject token with mismatched audience", Observation: map[string]interface{}{"rejected": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should reject token with mismatched issuer", Observation: map[string]interface{}{"rejected": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should throw when JWKS fetch fails", Observation: map[string]interface{}{"rejected": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should throw when JWKS returns empty keys array", Observation: map[string]interface{}{"rejected": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should throw when kid doesn't match any key", Observation: map[string]interface{}{"rejected": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should verify EdDSA (Ed25519) signed token", Observation: map[string]interface{}{"sub": "user-123", "verified": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should verify ES256 signed token", Observation: map[string]interface{}{"sub": "user-123", "verified": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should verify RS256 signed token", Observation: map[string]interface{}{"email": "test@example.com", "sub": "user-123", "verified": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should verify token with both audience and issuer", Observation: map[string]interface{}{"aud": "test-client", "iss": "https://example.com", "verified": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should verify token with matching audience", Observation: map[string]interface{}{"aud": "test-client", "verified": true}}, struct {
	ID          string                 "json:\"id\""
	File        string                 "json:\"file\""
	Suite       string                 "json:\"suite\""
	Title       string                 "json:\"title\""
	Observation map[string]interface{} "json:\"observation\""
}{Suite: "validateToken", Title: "should verify token with matching issuer", Observation: map[string]interface{}{"iss": "https://example.com", "verified": true}}}
