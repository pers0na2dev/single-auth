package singleauth_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

var originCheckTransports = []string{"net/http", "fasthttp", "fiber"}

type originCheckVector struct {
	Suite      string
	Title      string
	Transports []string
}

type originCheckExchange func(
	method string,
	target string,
	headers http.Header,
	body []byte,
) (int, http.Header, []byte, error)

type originCheckLogger struct {
	mu       sync.Mutex
	warnings []string
}

func (capture *originCheckLogger) log(level logger.Level, message string, _ ...any) {
	if level != logger.Warn {
		return
	}
	capture.mu.Lock()
	capture.warnings = append(capture.warnings, message)
	capture.mu.Unlock()
}

func (capture *originCheckLogger) snapshot() []string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]string(nil), capture.warnings...)
}

func originCheckBool(value bool) *bool { return &value }

func originCheckOptions(baseURL string) singleauth.Options {
	return singleauth.Options{
		BaseURL: baseURL,
		Secret:  "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return password, nil },
				Verify: func(hash, password string) bool { return hash == password },
			},
		},
		RateLimit: singleauth.RateLimitOptions{Enabled: originCheckBool(false)},
		Logger:    logger.Options{Disabled: true},
		RunBackground: func(ctx context.Context, callback func(context.Context) error) error {
			return callback(ctx)
		},
	}
}

func newOriginCheckAuth(t *testing.T, options singleauth.Options, seed bool) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if seed {
		_, err = auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
			Name: "test user", Email: "test@test.com", Password: "test123456",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return auth
}

func newOriginCheckRuntime(
	t *testing.T,
	transportName string,
	options singleauth.Options,
	seed bool,
) (*singleauth.Auth, originCheckExchange) {
	t.Helper()
	auth := newOriginCheckAuth(t, options, seed)
	return auth, newOriginCheckExchange(t, transportName, auth)
}

func newOriginCheckExchange(
	t *testing.T,
	transportName string,
	auth *singleauth.Auth,
) originCheckExchange {
	t.Helper()
	switch transportName {
	case "net/http":
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			request := httptest.NewRequest(method, target, bytes.NewReader(body))
			request.Header = headers.Clone()
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			parsed, err := url.Parse(target)
			if err != nil {
				return 0, nil, nil, err
			}
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.SetRequestURI(parsed.RequestURI())
			request.Header.SetHost(parsed.Host)
			request.URI().SetScheme(parsed.Scheme)
			for name, values := range headers {
				for _, value := range values {
					request.Header.Add(name, value)
				}
			}
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(
				&request,
				&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43124},
				nil,
			)
			handler(&requestContext)
			responseHeaders := make(http.Header)
			requestContext.Response.Header.VisitAll(func(name, value []byte) {
				responseHeaders.Add(string(name), string(value))
			})
			return requestContext.Response.StatusCode(), responseHeaders,
				append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
		sourceTransport, ok := certificateSource.Client().Transport.(*http.Transport)
		if !ok || sourceTransport.TLSClientConfig == nil {
			certificateSource.Close()
			t.Fatal("httptest TLS client has no TLS configuration")
		}
		clientTransport := &http.Transport{
			TLSClientConfig: sourceTransport.TLSClientConfig.Clone(),
		}
		client := &http.Client{
			Transport: clientTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		serverTLS := &tls.Config{
			Certificates: append([]tls.Certificate(nil), certificateSource.TLS.Certificates...),
			MinVersion:   tls.VersionTLS12,
		}
		certificateSource.Close()

		plainListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tlsBaseListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			_ = plainListener.Close()
			t.Fatal(err)
		}
		tlsListener := tls.NewListener(tlsBaseListener, serverTLS)

		startApp := func(listener net.Listener) (*fiberframework.App, <-chan error) {
			app := fiberframework.New()
			app.Use(fibertransport.NewHandler(auth.Dispatcher()))
			result := make(chan error, 1)
			go func() {
				result <- app.Listener(listener, fiberframework.ListenConfig{DisableStartupMessage: true})
			}()
			return app, result
		}
		plainApp, plainResult := startApp(plainListener)
		tlsApp, tlsResult := startApp(tlsListener)
		t.Cleanup(func() {
			clientTransport.CloseIdleConnections()
			_ = plainApp.ShutdownWithTimeout(5 * time.Second)
			_ = tlsApp.ShutdownWithTimeout(5 * time.Second)
			for name, result := range map[string]<-chan error{
				"plain": plainResult,
				"TLS":   tlsResult,
			} {
				select {
				case <-result:
				case <-time.After(5 * time.Second):
					t.Errorf("Fiber %s listener did not stop", name)
				}
			}
		})

		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			parsed, err := url.Parse(target)
			if err != nil {
				return 0, nil, nil, err
			}
			var listener net.Listener
			switch parsed.Scheme {
			case "http":
				listener = plainListener
			case "https":
				listener = tlsListener
			default:
				return 0, nil, nil, fmt.Errorf("unsupported Fiber test target scheme %q", parsed.Scheme)
			}
			request, err := http.NewRequest(
				method,
				parsed.Scheme+"://"+listener.Addr().String()+parsed.RequestURI(),
				bytes.NewReader(body),
			)
			if err != nil {
				return 0, nil, nil, err
			}
			request.Host = parsed.Host
			request.Header = headers.Clone()
			response, err := client.Do(request)
			if err != nil {
				return 0, nil, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	default:
		t.Fatalf("unknown origin-check transport %q", transportName)
		return nil
	}
}

func originCheckEndpoint(name, path string) engine.Endpoint {
	return engine.Endpoint{
		Name: name, Path: path, Methods: []string{http.MethodPost},
		Handler: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(contract.StatusOK, map[string]any{"ok": true})
		},
	}
}

func originCheckHeaders(values ...string) http.Header {
	headers := make(http.Header)
	for index := 0; index+1 < len(values); index += 2 {
		headers.Add(values[index], values[index+1])
	}
	return headers
}

func originCheckJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func originCheckRequest(
	t *testing.T,
	exchange originCheckExchange,
	method, target string,
	headers http.Header,
	body any,
) (int, http.Header, []byte) {
	t.Helper()
	if headers == nil {
		headers = make(http.Header)
	}
	var encoded []byte
	if body != nil {
		encoded = originCheckJSON(body)
		headers = headers.Clone()
		headers.Set("Content-Type", "application/json")
	}
	status, responseHeaders, responseBody, err := exchange(
		method, target, headers, encoded,
	)
	if err != nil {
		t.Fatal(err)
	}
	return status, responseHeaders, responseBody
}

func requireOriginCheckStatus(t *testing.T, got, want int, body []byte) {
	t.Helper()
	if got != want {
		t.Fatalf("origin-check status=%d want=%d body=%s", got, want, body)
	}
}

func requireOriginCheckMessage(t *testing.T, body []byte, want string) {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode origin-check error body %s: %v", body, err)
	}
	if got, _ := value["message"].(string); got != want {
		t.Fatalf("origin-check message=%q want=%q body=%s", got, want, body)
	}
}

func originCheckSessionCookie(values []string) string {
	for _, value := range values {
		if strings.Contains(value, "session") {
			return strings.SplitN(value, ";", 2)[0]
		}
	}
	return ""
}

func TestOriginCheckHTTPBehavior(t *testing.T) {
	for _, vector := range originCheckCases() {
		vector := vector
		t.Run(vector.Suite+"/"+vector.Title, func(t *testing.T) {
			for _, transportName := range vector.Transports {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					runOriginCheckScenario(t, transportName, vector)
				})
			}
		})
	}
}

func TestOriginCheckScenarioDefinitions(t *testing.T) {
	cases := originCheckCases()
	if len(cases) != 38 {
		t.Fatalf("origin-check scenarios=%d, want 38", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, scenario := range cases {
		name := scenario.Suite + "::" + scenario.Title
		if scenario.Suite == "" || scenario.Title == "" || len(scenario.Transports) != len(originCheckTransports) {
			t.Fatalf("invalid origin-check scenario: %#v", scenario)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate origin-check scenario %q", name)
		}
		seen[name] = struct{}{}
	}
}

func runOriginCheckScenario(
	t *testing.T,
	transportName string,
	vector originCheckVector,
) {
	t.Helper()
	switch vector.Suite {
	case "Origin Check":
		runOriginCheckBasicScenario(t, transportName, vector.Title)
	case "Fetch Metadata CSRF Protection":
		runOriginCheckFetchMetadataScenario(t, transportName, vector.Title)
	case "origin check middleware":
		runOriginCheckMiddlewareScenario(t, transportName, vector.Title)
	case "trusted origins with baseURL inferred from request":
		runOriginCheckInferredBaseURLScenario(t, transportName, vector.Title)
	case "disableCSRFCheck and disableOriginCheck separation":
		runOriginCheckDisableFlagsScenario(t, transportName, vector.Title)
	case "request-scoped trusted origin isolation":
		runOriginCheckIsolationScenario(t, transportName, vector.Title)
	case "inferred baseURL is not persisted across requests":
		runOriginCheckBaseURLPersistenceScenario(t, transportName, vector.Title)
	default:
		t.Fatalf("unhandled origin-check suite %q", vector.Suite)
	}
}

func runOriginCheckBasicScenario(t *testing.T, transportName, title string) {
	t.Helper()
	options := originCheckOptions("http://localhost:3000")
	options.TrustedOrigins = []string{
		"http://localhost:5000", "https://trusted.com", "*.my-site.com",
	}
	options.EmailAndPassword.SendResetPassword = func(context.Context, singleauth.PasswordResetMessage) error {
		return nil
	}
	if title == "should filter out null values from trustedOrigins callback" {
		options.TrustedOrigins = nil
		options.ResolveTrustedOrigins = func(context.Context, contract.Request) ([]string, error) {
			return []string{"http://valid-origin.com", "", ""}, nil
		}
	}
	_, exchange := newOriginCheckRuntime(t, transportName, options, true)
	credentials := map[string]any{
		"email": "test@test.com", "password": "test123456",
	}

	switch title {
	case "should allow trusted origins":
		credentials["callbackURL"] = "http://localhost:3000/callback"
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("Origin", "http://localhost:3000"), credentials)
		requireOriginCheckStatus(t, status, http.StatusOK, body)
	case "should not allow untrusted origins":
		credentials["callbackURL"] = "http://malicious.com"
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email", nil, credentials)
		requireOriginCheckStatus(t, status, http.StatusForbidden, body)
		requireOriginCheckMessage(t, body, "Invalid callbackURL")
	case "should reject untrusted origin headers":
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("Origin", "malicious.com", "Cookie", "session=123"),
			credentials)
		requireOriginCheckStatus(t, status, http.StatusForbidden, body)
	case "should reject untrusted origin even without cookies":
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("Origin", "http://sub-domain.trusted.com"), credentials)
		requireOriginCheckStatus(t, status, http.StatusForbidden, body)
	case "should reject untrusted redirectTo":
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/request-password-reset", nil,
			map[string]any{"email": "test@test.com", "redirectTo": "http://malicious.com"})
		requireOriginCheckStatus(t, status, http.StatusForbidden, body)
		requireOriginCheckMessage(t, body, "Invalid redirectURL")
	case "should work with list of trusted origins":
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/request-password-reset",
			originCheckHeaders("Origin", "https://trusted.com"),
			map[string]any{
				"email": "test@test.com", "redirectTo": "http://localhost:5000/reset-password",
			})
		requireOriginCheckStatus(t, status, http.StatusOK, body)
		status, _, body = originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email?currentURL=http%3A%2F%2Flocalhost%3A5000",
			originCheckHeaders("Origin", "https://trusted.com"), credentials)
		requireOriginCheckStatus(t, status, http.StatusOK, body)
	case "should work with wildcard trusted origins":
		credentials["callbackURL"] = "https://sub-domain.my-site.com/callback"
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"https://sub-domain.my-site.com/api/auth/sign-in/email",
			originCheckHeaders("Origin", "https://sub-domain.my-site.com"), credentials)
		requireOriginCheckStatus(t, status, http.StatusOK, body)
	case "should work with GET requests":
		status, _, body := originCheckRequest(t, exchange, http.MethodGet,
			"https://sub-domain.my-site.com/api/auth/ok",
			originCheckHeaders("Origin", "https://google.com", "Cookie", "value"), nil)
		requireOriginCheckStatus(t, status, http.StatusOK, body)
		if !bytes.Contains(body, []byte(`"ok":true`)) {
			t.Fatalf("GET /ok body=%s", body)
		}
	case "should handle POST requests with proper origin validation":
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("Origin", "http://localhost:5000", "Cookie", "session=123"),
			credentials)
		requireOriginCheckStatus(t, status, http.StatusOK, body)
		status, _, body = originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("Origin", "http://untrusted-domain.com", "Cookie", "session=123"),
			credentials)
		requireOriginCheckStatus(t, status, http.StatusForbidden, body)
	case "should filter out null values from trustedOrigins callback":
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("Origin", "http://valid-origin.com"), credentials)
		requireOriginCheckStatus(t, status, http.StatusOK, body)
	default:
		t.Fatalf("unhandled Origin Check title %q", title)
	}
}

func runOriginCheckFetchMetadataScenario(t *testing.T, transportName, title string) {
	t.Helper()
	options := originCheckOptions("http://localhost:3000")
	options.TrustedOrigins = []string{"http://localhost:3000", "https://app.example.com"}
	auth, exchange := newOriginCheckRuntime(t, transportName, options, true)
	credentials := map[string]any{
		"email": "test@test.com", "password": "test123456",
	}
	endpoint := "/api/auth/sign-in/email"
	headers := originCheckHeaders("Origin", "http://localhost:3000")
	wantStatus := http.StatusOK
	wantMessage := ""

	switch title {
	case "should block cross-site navigation on first-login (no session cookie)":
		headers = originCheckHeaders(
			"Sec-Fetch-Site", "cross-site",
			"Sec-Fetch-Mode", "navigate",
			"Sec-Fetch-Dest", "document",
			"Origin", "https://evil.com",
		)
		credentials = map[string]any{
			"email": "attacker@evil.com", "password": "password123",
		}
		wantStatus = http.StatusForbidden
		wantMessage = "Cross-site navigation login blocked. This request appears to be a CSRF attack."
	case "should allow same-origin navigation on first-login (no session cookie)":
		headers = originCheckHeaders(
			"Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "navigate",
			"Sec-Fetch-Dest", "document", "Origin", "http://localhost:3000",
		)
	case "should allow same-site navigation on first-login (no session cookie)":
		headers = originCheckHeaders(
			"Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "navigate",
			"Sec-Fetch-Dest", "document", "Origin", "https://app.example.com",
		)
	case "should fallback to origin validation when Fetch Metadata is missing":
		headers = originCheckHeaders("Origin", "http://localhost:3000")
	case "should reject an untrusted origin on first-login when Fetch Metadata is missing":
		headers = originCheckHeaders("Origin", "https://evil.com")
		wantStatus = http.StatusForbidden
	case "should reject an untrusted Referer on first-login when Fetch Metadata is missing":
		headers = originCheckHeaders("Referer", "https://evil.com")
		wantStatus = http.StatusForbidden
	case "should allow a first-login request that sends no cookies, Fetch Metadata, or origin":
		headers = nil
	case "should use existing origin validation when session cookie exists":
		signIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
			Email: "test@test.com", Password: "test123456",
		})
		if err != nil {
			t.Fatal(err)
		}
		cookie := originCheckSessionCookie(signIn.Headers.Values("Set-Cookie"))
		if cookie == "" {
			t.Fatal("direct sign-in returned no session cookie")
		}
		headers = originCheckHeaders(
			"Cookie", cookie, "Sec-Fetch-Site", "cross-site",
			"Sec-Fetch-Mode", "navigate", "Origin", "http://localhost:3000",
		)
	case "should block cross-site navigation for sign-up endpoint":
		endpoint = "/api/auth/sign-up/email"
		headers = originCheckHeaders(
			"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate",
			"Sec-Fetch-Dest", "document", "Origin", "https://evil.com",
		)
		credentials = map[string]any{
			"email": "attacker@evil.com", "password": "password123", "name": "Attacker",
		}
		wantStatus = http.StatusForbidden
		wantMessage = "Cross-site navigation login blocked. This request appears to be a CSRF attack."
	case "should allow cors mode requests (fetch/XHR)":
		headers = originCheckHeaders(
			"Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "cors",
			"Sec-Fetch-Dest", "empty", "Origin", "http://localhost:3000",
		)
	case "should allow requests with expired session cookie (cookie presence check)":
		headers = originCheckHeaders(
			"Cookie", "single-auth.session_token=expired_or_invalid_token",
			"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate",
			"Origin", "http://localhost:3000",
		)
	default:
		t.Fatalf("unhandled Fetch Metadata title %q", title)
	}

	status, _, body := originCheckRequest(t, exchange, http.MethodPost,
		"http://localhost:3000"+endpoint, headers, credentials)
	requireOriginCheckStatus(t, status, wantStatus, body)
	if wantMessage != "" {
		requireOriginCheckMessage(t, body, wantMessage)
	}
}

func runOriginCheckMiddlewareScenario(t *testing.T, transportName, title string) {
	t.Helper()
	options := originCheckOptions("http://localhost:3000")
	options.TrustedOrigins = []string{"https://trusted-site.com"}

	switch title {
	case "should return invalid origin":
		_, exchange := newOriginCheckRuntime(t, transportName, options, false)
		checks := []struct {
			callback string
			status   int
		}{
			{"https://malicious-site.com", http.StatusForbidden},
			{"/dashboard", http.StatusFound},
			{"https://trusted-site.com/path", http.StatusFound},
			{"https://malicious-site.com", http.StatusForbidden},
		}
		for _, check := range checks {
			target := "http://localhost:3000/api/auth/verify-email?token=xyz&callbackURL=" +
				url.QueryEscape(check.callback)
			status, _, body := originCheckRequest(t, exchange, http.MethodGet, target, nil, nil)
			requireOriginCheckStatus(t, status, check.status, body)
		}
	case "should skip origin check for matched paths when skipOriginCheck is set to an array":
		options.Advanced.SkipOriginCheckPaths = []string{"/public/data"}
		options.Endpoints = []engine.Endpoint{
			originCheckEndpoint("originPublicData", "/public/data"),
			originCheckEndpoint("originProtectedData", "/protected/data"),
		}
		_, exchange := newOriginCheckRuntime(t, transportName, options, false)
		body := map[string]any{"callbackURL": "https://malicious.com"}
		status, _, response := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/public/data", nil, body)
		requireOriginCheckStatus(t, status, http.StatusOK, response)
		status, _, response = originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/protected/data", nil, body)
		requireOriginCheckStatus(t, status, http.StatusForbidden, response)
	case "should not skip origin check for a path that only shares a prefix with a skip path":
		options.Advanced.SkipOriginCheckPaths = []string{"/public/data"}
		options.Endpoints = []engine.Endpoint{
			originCheckEndpoint("originPublicDatabase", "/public/database"),
		}
		_, exchange := newOriginCheckRuntime(t, transportName, options, false)
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/public/database", nil,
			map[string]any{"callbackURL": "https://malicious.com"})
		requireOriginCheckStatus(t, status, http.StatusForbidden, body)
	case "should reject a non-string redirect parameter with 400, not 500":
		options.TrustedOrigins = []string{"http://localhost:3000"}
		_, exchange := newOriginCheckRuntime(t, transportName, options, false)
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("Origin", "http://localhost:3000"),
			map[string]any{
				"email": "test@test.com", "password": "password12345",
				"callbackURL": map[string]any{"object": true},
			})
		requireOriginCheckStatus(t, status, http.StatusBadRequest, body)
		status, _, body = originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email?callbackURL=/a&callbackURL=/b",
			originCheckHeaders("Origin", "http://localhost:3000"),
			map[string]any{"email": "test@test.com", "password": "password12345"})
		requireOriginCheckStatus(t, status, http.StatusBadRequest, body)
	default:
		t.Fatalf("unhandled origin check middleware title %q", title)
	}
}

func runOriginCheckInferredBaseURLScenario(t *testing.T, transportName, title string) {
	t.Helper()
	options := originCheckOptions("")
	credentials := map[string]any{
		"email": "test@test.com", "password": "test123456",
	}
	targetOrigin := "http://localhost:3000"
	wantStatus := http.StatusOK

	switch title {
	case "should respect trustedOrigins array when baseURL is NOT in config":
		options.TrustedOrigins = []string{"http://my-frontend.com"}
		targetOrigin = "http://my-frontend.com"
		credentials["callbackURL"] = "http://my-frontend.com/dashboard"
	case "should reject untrusted origins even when baseURL is inferred":
		options.TrustedOrigins = []string{"http://my-frontend.com"}
		targetOrigin = "http://evil-site.com"
		wantStatus = http.StatusForbidden
	case "should respect SINGLE_AUTH_TRUSTED_ORIGINS env when baseURL is NOT in config":
		t.Setenv("SINGLE_AUTH_TRUSTED_ORIGINS", "http://env-frontend.com")
		targetOrigin = "http://env-frontend.com"
		credentials["callbackURL"] = "http://env-frontend.com/dashboard"
	case "should allow requests from inferred baseURL origin":
		credentials["callbackURL"] = "http://localhost:3000/dashboard"
	case "should support both config array and env var together when baseURL is inferred":
		t.Setenv("SINGLE_AUTH_TRUSTED_ORIGINS", "http://env-origin.com")
		options.TrustedOrigins = []string{"http://config-origin.com"}
		_, exchange := newOriginCheckRuntime(t, transportName, options, true)
		for _, candidate := range []string{"http://config-origin.com", "http://env-origin.com"} {
			body := map[string]any{
				"email": "test@test.com", "password": "test123456",
				"callbackURL": candidate + "/dashboard",
			}
			status, _, response := originCheckRequest(t, exchange, http.MethodPost,
				"http://localhost:3000/api/auth/sign-in/email",
				originCheckHeaders("Origin", candidate, "Cookie", "session=test"), body)
			requireOriginCheckStatus(t, status, http.StatusOK, response)
		}
		return
	default:
		t.Fatalf("unhandled inferred baseURL title %q", title)
	}

	_, exchange := newOriginCheckRuntime(t, transportName, options, true)
	status, _, body := originCheckRequest(t, exchange, http.MethodPost,
		"http://localhost:3000/api/auth/sign-in/email",
		originCheckHeaders("Origin", targetOrigin, "Cookie", "session=test"), credentials)
	requireOriginCheckStatus(t, status, wantStatus, body)
}

func runOriginCheckDisableFlagsScenario(t *testing.T, transportName, title string) {
	t.Helper()
	options := originCheckOptions("http://localhost:3000")
	options.TrustedOrigins = []string{"http://localhost:3000"}
	headers := originCheckHeaders("Origin", "http://evil-site.com", "Cookie", "session=test")
	credentials := map[string]any{
		"email": "test@test.com", "password": "test123456",
	}
	wantStatus := http.StatusOK
	wantMessage := ""
	requestCount := 1
	var capture *originCheckLogger

	switch title {
	case "disableCSRFCheck should allow untrusted origins with cookies (CSRF bypass)":
		options.Advanced.DisableCSRFCheck = originCheckBool(true)
		options.Advanced.DisableOriginCheck = originCheckBool(false)
		credentials["callbackURL"] = "http://localhost:3000/dashboard"
	case "disableCSRFCheck should still validate callbackURL (origin check still active)":
		options.Advanced.DisableCSRFCheck = originCheckBool(true)
		options.Advanced.DisableOriginCheck = originCheckBool(false)
		credentials["callbackURL"] = "http://malicious-site.com/steal"
		wantStatus = http.StatusForbidden
		wantMessage = "Invalid callbackURL"
	case "disableOriginCheck should allow untrusted callbackURL":
		options.Advanced.DisableCSRFCheck = originCheckBool(false)
		options.Advanced.DisableOriginCheck = originCheckBool(true)
		headers = originCheckHeaders("Origin", "http://localhost:3000", "Cookie", "session=test")
		credentials["callbackURL"] = "http://any-site.com/redirect"
	case "disableOriginCheck also disables CSRF for backward compatibility":
		options.Advanced.DisableOriginCheck = originCheckBool(true)
		credentials["callbackURL"] = "http://any-site.com/redirect"
		capture = &originCheckLogger{}
		options.Logger = logger.Options{Level: logger.Warn, Log: capture.log}
		requestCount = 2
	case "disableCSRFCheck should bypass Fetch Metadata CSRF protection":
		options.Advanced.DisableCSRFCheck = originCheckBool(true)
		options.Advanced.DisableOriginCheck = originCheckBool(false)
		headers = originCheckHeaders(
			"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate",
			"Sec-Fetch-Dest", "document", "Origin", "https://evil.com",
		)
	case "both flags disabled should bypass all checks":
		options.Advanced.DisableCSRFCheck = originCheckBool(true)
		options.Advanced.DisableOriginCheck = originCheckBool(true)
		credentials["callbackURL"] = "http://malicious-site.com/steal"
	default:
		t.Fatalf("unhandled disable flags title %q", title)
	}

	_, exchange := newOriginCheckRuntime(t, transportName, options, true)
	for range requestCount {
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email", headers, credentials)
		requireOriginCheckStatus(t, status, wantStatus, body)
		if wantMessage != "" {
			requireOriginCheckMessage(t, body, wantMessage)
		}
	}
	if capture != nil {
		warnings := capture.snapshot()
		if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "[Deprecation] disableOriginCheck: true") {
			t.Fatalf("backward-compatible origin warnings=%q", warnings)
		}
	}
}

func runOriginCheckIsolationScenario(t *testing.T, transportName, title string) {
	t.Helper()
	if title != "does not let one request's trusted origins bleed into a concurrent request" {
		t.Fatalf("unhandled origin isolation title %q", title)
	}
	aReachedPause := make(chan struct{})
	releaseA := make(chan struct{})
	var signalOnce sync.Once
	options := originCheckOptions("http://localhost:3000")
	options.ResolveTrustedOrigins = func(ctx context.Context, request contract.Request) ([]string, error) {
		tenant, _ := request.Headers().Get("X-Tenant")
		if tenant == "a" {
			signalOnce.Do(func() { close(aReachedPause) })
			select {
			case <-releaseA:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []string{"https://" + tenant + ".example"}, nil
	}
	_, exchange := newOriginCheckRuntime(t, transportName, options, false)

	type result struct {
		status int
		body   []byte
		err    error
	}
	resultA := make(chan result, 1)
	go func() {
		status, _, body, err := exchange(
			http.MethodPost,
			"http://localhost:3000/api/auth/sign-in/email",
			originCheckHeaders("X-Tenant", "a", "Origin", "https://b.example", "Cookie", "x=1", "Content-Type", "application/json"),
			originCheckJSON(map[string]any{"email": "a@example.com", "password": "password1234"}),
		)
		resultA <- result{status: status, body: body, err: err}
	}()
	select {
	case <-aReachedPause:
	case <-time.After(5 * time.Second):
		t.Fatal("tenant A did not pause in trusted-origin resolution")
	}
	statusB, _, bodyB := originCheckRequest(t, exchange, http.MethodPost,
		"http://localhost:3000/api/auth/sign-in/email",
		originCheckHeaders("X-Tenant", "b", "Origin", "https://b.example", "Cookie", "x=1"),
		map[string]any{"email": "b@example.com", "password": "password1234"})
	if statusB == http.StatusForbidden {
		t.Fatalf("tenant B origin was unexpectedly rejected: %s", bodyB)
	}
	close(releaseA)
	select {
	case outcome := <-resultA:
		if outcome.err != nil {
			t.Fatal(outcome.err)
		}
		requireOriginCheckStatus(t, outcome.status, http.StatusForbidden, outcome.body)
	case <-time.After(5 * time.Second):
		t.Fatal("tenant A request did not resume")
	}
}

func runOriginCheckBaseURLPersistenceScenario(t *testing.T, transportName, title string) {
	t.Helper()
	if title != "does not reuse one request's host for a later request's token links" {
		t.Fatalf("unhandled baseURL persistence title %q", title)
	}
	var resetMutex sync.Mutex
	resetURLs := make([]string, 0, 2)
	options := originCheckOptions("")
	options.EmailAndPassword.SendResetPassword = func(_ context.Context, message singleauth.PasswordResetMessage) error {
		resetMutex.Lock()
		resetURLs = append(resetURLs, message.URL)
		resetMutex.Unlock()
		return nil
	}
	_, exchange := newOriginCheckRuntime(t, transportName, options, true)
	for _, host := range []string{"untrusted.example", "app.example"} {
		status, _, body := originCheckRequest(t, exchange, http.MethodPost,
			"https://"+host+"/api/auth/request-password-reset", nil,
			map[string]any{"email": "test@test.com", "redirectTo": "/"})
		requireOriginCheckStatus(t, status, http.StatusOK, body)
	}
	resetMutex.Lock()
	defer resetMutex.Unlock()
	if len(resetURLs) != 2 || !strings.Contains(resetURLs[1], "https://app.example") ||
		strings.Contains(resetURLs[1], "untrusted.example") {
		t.Fatalf("request-scoped reset URLs=%q", resetURLs)
	}
}

func TestFiberRealTLSPreservesOriginCheckScheme(t *testing.T) {
	var resetURL string
	options := originCheckOptions("")
	options.EmailAndPassword.SendResetPassword = func(_ context.Context, message singleauth.PasswordResetMessage) error {
		resetURL = message.URL
		return nil
	}
	auth := newOriginCheckAuth(t, options, true)
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(auth.Dispatcher()))

	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	client := certificateSource.Client()
	serverTLS := &tls.Config{
		Certificates: append([]tls.Certificate(nil), certificateSource.TLS.Certificates...),
		MinVersion:   tls.VersionTLS12,
	}
	certificateSource.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, serverTLS)
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- app.Listener(tlsListener, fiberframework.ListenConfig{DisableStartupMessage: true})
	}()
	t.Cleanup(func() {
		_ = app.ShutdownWithTimeout(5 * time.Second)
		select {
		case <-serveResult:
		case <-time.After(5 * time.Second):
			t.Error("Fiber TLS listener did not stop")
		}
	})

	body := originCheckJSON(map[string]any{"email": "test@test.com", "redirectTo": "/"})
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://"+listener.Addr().String()+"/api/auth/request-password-reset",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "app.example"
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	requireOriginCheckStatus(t, response.StatusCode, http.StatusOK, responseBody)
	if !strings.Contains(resetURL, "https://app.example") {
		t.Fatalf("real TLS Fiber reset URL=%q", resetURL)
	}
}

func TestOriginCheckFixtureHasNoUnhandledScenarios(t *testing.T) {
	for _, vector := range originCheckCases() {
		if !originCheckScenarioHandled(vector.Suite, vector.Title) {
			t.Errorf("unhandled origin-check scenario %q", vector.Suite+"::"+vector.Title)
		}
	}
}

func originCheckScenarioHandled(suite, title string) bool {
	for _, candidate := range originCheckScenarioInventory()[suite] {
		if candidate == title {
			return true
		}
	}
	return false
}

func originCheckScenarioInventory() map[string][]string {
	return map[string][]string{
		"Origin Check": {
			"should allow trusted origins",
			"should not allow untrusted origins",
			"should reject untrusted origin headers",
			"should reject untrusted origin even without cookies",
			"should reject untrusted redirectTo",
			"should work with list of trusted origins",
			"should work with wildcard trusted origins",
			"should work with GET requests",
			"should handle POST requests with proper origin validation",
			"should filter out null values from trustedOrigins callback",
		},
		"Fetch Metadata CSRF Protection": {
			"should block cross-site navigation on first-login (no session cookie)",
			"should allow same-origin navigation on first-login (no session cookie)",
			"should allow same-site navigation on first-login (no session cookie)",
			"should fallback to origin validation when Fetch Metadata is missing",
			"should reject an untrusted origin on first-login when Fetch Metadata is missing",
			"should reject an untrusted Referer on first-login when Fetch Metadata is missing",
			"should allow a first-login request that sends no cookies, Fetch Metadata, or origin",
			"should use existing origin validation when session cookie exists",
			"should block cross-site navigation for sign-up endpoint",
			"should allow cors mode requests (fetch/XHR)",
			"should allow requests with expired session cookie (cookie presence check)",
		},
		"origin check middleware": {
			"should return invalid origin",
			"should skip origin check for matched paths when skipOriginCheck is set to an array",
			"should not skip origin check for a path that only shares a prefix with a skip path",
			"should reject a non-string redirect parameter with 400, not 500",
		},
		"trusted origins with baseURL inferred from request": {
			"should respect trustedOrigins array when baseURL is NOT in config",
			"should reject untrusted origins even when baseURL is inferred",
			"should respect SINGLE_AUTH_TRUSTED_ORIGINS env when baseURL is NOT in config",
			"should allow requests from inferred baseURL origin",
			"should support both config array and env var together when baseURL is inferred",
		},
		"disableCSRFCheck and disableOriginCheck separation": {
			"disableCSRFCheck should allow untrusted origins with cookies (CSRF bypass)",
			"disableCSRFCheck should still validate callbackURL (origin check still active)",
			"disableOriginCheck should allow untrusted callbackURL",
			"disableOriginCheck also disables CSRF for backward compatibility",
			"disableCSRFCheck should bypass Fetch Metadata CSRF protection",
			"both flags disabled should bypass all checks",
		},
		"request-scoped trusted origin isolation": {
			"does not let one request's trusted origins bleed into a concurrent request",
		},
		"inferred baseURL is not persisted across requests": {
			"does not reuse one request's host for a later request's token links",
		},
	}
}

func originCheckCases() []originCheckVector {
	inventory := originCheckScenarioInventory()
	suiteOrder := []string{
		"Fetch Metadata CSRF Protection",
		"Origin Check",
		"disableCSRFCheck and disableOriginCheck separation",
		"inferred baseURL is not persisted across requests",
		"origin check middleware",
		"request-scoped trusted origin isolation",
		"trusted origins with baseURL inferred from request",
	}
	cases := make([]originCheckVector, 0, 38)
	for _, suite := range suiteOrder {
		for _, title := range inventory[suite] {
			cases = append(cases, originCheckVector{
				Suite: suite, Title: title, Transports: append([]string(nil), originCheckTransports...),
			})
		}
	}
	return cases
}
