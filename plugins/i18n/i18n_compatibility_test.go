package i18n

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const (
	i18nProbeError   = "i18nProbeError"
	i18nProbeSuccess = "i18nProbeSuccess"
)

type i18nObservation struct {
	Status        int            `json:"status,omitempty"`
	Body          map[string]any `json:"body,omitempty"`
	ThrownMessage string         `json:"thrownMessage,omitempty"`
}

type i18nScenario struct {
	name string
	mode string
	want i18nObservation
}

func localizedError(message string, includeOriginal bool) i18nObservation {
	body := map[string]any{
		"code":    "INVALID_EMAIL_OR_PASSWORD",
		"message": message,
	}
	if includeOriginal {
		body["originalMessage"] = "Invalid email or password"
	}
	return i18nObservation{Status: http.StatusUnauthorized, Body: body}
}

var i18nScenarios = []i18nScenario{
	{name: "callback works for direct calls", mode: "callback-direct", want: localizedError("Email ou mot de passe invalide", true)},
	{name: "callback strategy uses request headers", mode: "callback-header", want: localizedError("Email ou mot de passe invalide", true)},
	{name: "empty translations are rejected", mode: "empty-translations", want: i18nObservation{ThrownMessage: "i18n plugin: translations object is empty. At least one locale must be provided."}},
	{name: "implicit English locale is selected", mode: "implicit-en-present", want: localizedError("Invalid email or password", true)},
	{name: "missing implicit locale keeps the message", mode: "implicit-en-missing", want: localizedError("Invalid email or password", false)},
	{name: "explicit German default is selected", mode: "explicit-default-de", want: localizedError("Ungültige E-Mail oder Passwort", true)},
	{name: "missing translation falls back", mode: "fallback-upstream-case", want: localizedError("Ungültige E-Mail oder Passwort", true)},
	{name: "no locale input uses the default", mode: "fallback-default", want: localizedError("Invalid email or password", true)},
	{name: "regional locale resolves to its base", mode: "header-base-locale", want: localizedError("Email ou mot de passe invalide", true)},
	{name: "quality values are honored", mode: "header-quality", want: localizedError("Email ou mot de passe invalide", true)},
	{name: "French header translates errors", mode: "header-fr", want: localizedError("Email ou mot de passe invalide", true)},
	{name: "German header translates errors", mode: "header-de", want: localizedError("Ungültige E-Mail oder Passwort", true)},
	{name: "unknown header locale uses the default", mode: "header-unavailable", want: localizedError("Invalid email or password", true)},
	{name: "locale cookie has priority", mode: "cookie-priority", want: localizedError("Email ou mot de passe invalide", true)},
	{name: "successful responses are unchanged", mode: "success-unchanged", want: i18nObservation{Status: http.StatusOK, Body: map[string]any{
		"session": map[string]any{"id": "session-id"},
		"user":    map[string]any{"id": "user-id"},
	}}},
}

func TestI18nScenarios(t *testing.T) {
	for _, scenario := range i18nScenarios {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			actual := executeI18nMode(t, scenario.mode)
			if !reflect.DeepEqual(actual, scenario.want) {
				t.Fatalf("mode %s observation=%#v, want %#v", scenario.mode, actual, scenario.want)
			}

			switch scenario.mode {
			case "callback-header", "header-fr", "cookie-priority", "success-unchanged":
				for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
					options := optionsForI18nMode(t, scenario.mode)
					auth := newI18nProbeAuth(t, options)
					observation := executeI18nTransport(t, auth, scenario.mode, transport)
					if !reflect.DeepEqual(observation, scenario.want) {
						t.Fatalf("mode %s transport %s=%#v, want %#v", scenario.mode, transport, observation, scenario.want)
					}
				}
			}
		})
	}
}

func TestI18nSessionLocaleDetection(t *testing.T) {
	optional := storage.Bool(false)
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test", Secret: "i18n-session-secret-that-is-long-enough",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"locale": {Type: storage.FieldString, Required: optional},
			}},
		}},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Translations: i18nTranslations(), DefaultLocale: "en",
			Detection: []LocaleDetectionStrategy{DetectionSession},
		})},
		Endpoints: i18nProbeEndpoints(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fields := model.Fields{}
	fields.Set("locale", "fr")
	signedUp, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Locale User", Email: "locale@example.test", Password: "password123",
		AdditionalFields: fields,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", signedUp.Headers.Values("Set-Cookie"))
	result, err := auth.API().Call(t.Context(), i18nProbeError, singleauth.DirectCallInput{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
	})
	if err == nil {
		t.Fatal("session-localized probe unexpectedly succeeded")
	}
	observation := responseObservation(t, result.Response)
	if observation.Body["message"] != "Email ou mot de passe invalide" ||
		observation.Body["originalMessage"] != "Invalid email or password" {
		t.Fatalf("session locale response=%#v", observation)
	}
}

func TestI18nOptionsAreSnapshotted(t *testing.T) {
	translations := i18nTranslations()
	detection := []LocaleDetectionStrategy{DetectionHeader}
	plugin, err := New(Options{Translations: translations, Detection: detection})
	if err != nil {
		t.Fatal(err)
	}
	translations["fr"]["INVALID_EMAIL_OR_PASSWORD"] = "mutated"
	detection[0] = DetectionCookie

	dispatcher, err := engine.NewDispatcher(mustI18nRegistry(t, plugin), engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.NewRequest(http.MethodPost, "/i18n-probe-error", contract.RequestOptions{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Accept-Language", Value: "fr"}),
	})
	response, err := dispatcher.Dispatch(request)
	if err == nil {
		t.Fatal("probe unexpectedly succeeded")
	}
	if got := responseObservation(t, response).Body["message"]; got != "Email ou mot de passe invalide" {
		t.Fatalf("snapshotted translation=%#v", got)
	}
}

func executeI18nMode(t *testing.T, mode string) i18nObservation {
	t.Helper()
	if mode == "empty-translations" {
		_, err := New(Options{Translations: map[string]TranslationDictionary{}})
		if err == nil {
			t.Fatal("empty translations unexpectedly succeeded")
		}
		return i18nObservation{ThrownMessage: err.Error()}
	}
	options := optionsForI18nMode(t, mode)
	auth := newI18nProbeAuth(t, options)
	if mode == "callback-header" || mode == "success-unchanged" {
		return executeI18nTransport(t, auth, mode, "net/http")
	}
	endpoint := i18nProbeError
	input := singleauth.DirectCallInput{Headers: headersForI18nMode(mode)}
	result, err := auth.API().Call(t.Context(), endpoint, input)
	if err == nil {
		t.Fatalf("mode %s unexpectedly succeeded", mode)
	}
	return responseObservation(t, result.Response)
}

func optionsForI18nMode(t *testing.T, mode string) Options {
	t.Helper()
	standard := Options{
		Translations: i18nTranslations(), DefaultLocale: "en",
		Detection: []LocaleDetectionStrategy{DetectionHeader, DetectionCookie},
	}
	switch mode {
	case "callback-direct":
		standard.Detection = []LocaleDetectionStrategy{DetectionCallback}
		standard.GetLocale = func(ctx *engine.Context) (string, error) {
			if ctx == nil || !ctx.IsDirect() || ctx.Request().Headers().Len() != 0 {
				return "", errors.New("direct callback did not receive the headerless direct context")
			}
			return "fr", nil
		}
	case "callback-header":
		standard.Detection = []LocaleDetectionStrategy{DetectionCallback}
		standard.GetLocale = func(ctx *engine.Context) (string, error) {
			if ctx == nil || ctx.IsDirect() {
				return "", errors.New("callback did not receive an HTTP endpoint context")
			}
			locale, _ := ctx.Request().Headers().Get("X-Custom-Locale")
			return locale, nil
		}
	case "implicit-en-present":
		standard.DefaultLocale = ""
		standard.Detection = []LocaleDetectionStrategy{DetectionHeader}
		standard.Translations = map[string]TranslationDictionary{
			"de": {"INVALID_EMAIL_OR_PASSWORD": "Ungültige E-Mail oder Passwort"},
			"en": {"INVALID_EMAIL_OR_PASSWORD": "Invalid email or password"},
			"fr": {"INVALID_EMAIL_OR_PASSWORD": "Email ou mot de passe invalide"},
		}
	case "implicit-en-missing":
		standard.DefaultLocale = ""
		standard.Detection = []LocaleDetectionStrategy{DetectionHeader}
		standard.Translations = map[string]TranslationDictionary{
			"fr": {"INVALID_EMAIL_OR_PASSWORD": "Email ou mot de passe invalide"},
			"de": {"INVALID_EMAIL_OR_PASSWORD": "Ungültige E-Mail oder Passwort"},
		}
	case "explicit-default-de":
		standard.DefaultLocale = "de"
		standard.Detection = []LocaleDetectionStrategy{DetectionHeader}
		standard.Translations = map[string]TranslationDictionary{
			"fr": {"INVALID_EMAIL_OR_PASSWORD": "Email ou mot de passe invalide"},
			"de": {"INVALID_EMAIL_OR_PASSWORD": "Ungültige E-Mail oder Passwort"},
		}
	case "cookie-priority":
		standard.Detection = []LocaleDetectionStrategy{DetectionCookie, DetectionHeader}
		standard.LocaleCookie = "lang"
	case "fallback-upstream-case", "fallback-default", "header-base-locale", "header-quality", "header-fr", "header-de", "header-unavailable", "success-unchanged":
	default:
		t.Fatalf("unknown i18n scenario mode %q", mode)
	}
	return standard
}

func headersForI18nMode(mode string) contract.Headers {
	headers := contract.Headers{}
	switch mode {
	case "callback-header":
		headers.Set("X-Custom-Locale", "fr")
	case "fallback-upstream-case", "header-de":
		headers.Set("Accept-Language", "de")
	case "header-base-locale":
		headers.Set("Accept-Language", "fr-CA")
	case "header-quality":
		headers.Set("Accept-Language", "es;q=0.9, fr;q=0.8, en;q=0.7")
	case "header-fr", "success-unchanged":
		headers.Set("Accept-Language", "fr")
	case "header-unavailable":
		headers.Set("Accept-Language", "es")
	case "cookie-priority":
		headers.Set("Cookie", "lang=fr")
		headers.Set("Accept-Language", "de")
	}
	return headers
}

func i18nTranslations() map[string]TranslationDictionary {
	return map[string]TranslationDictionary{
		"en": {
			"USER_NOT_FOUND": "User not found", "INVALID_EMAIL_OR_PASSWORD": "Invalid email or password",
			"INVALID_PASSWORD": "Invalid password",
		},
		"fr": {
			"USER_NOT_FOUND": "Utilisateur non trouvé", "INVALID_EMAIL_OR_PASSWORD": "Email ou mot de passe invalide",
			"INVALID_PASSWORD": "Mot de passe invalide",
		},
		"de": {
			"USER_NOT_FOUND": "Benutzer nicht gefunden", "INVALID_EMAIL_OR_PASSWORD": "Ungültige E-Mail oder Passwort",
		},
	}
}

func newI18nProbeAuth(t *testing.T, options Options) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "i18n-probe-secret-that-is-long-enough",
		PluginFactories: []singleauth.PluginFactory{NewFactory(options)},
		Endpoints:       i18nProbeEndpoints(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func i18nProbeEndpoints() []engine.Endpoint {
	return []engine.Endpoint{
		{
			Name: i18nProbeError, Path: "/i18n-probe-error", Methods: []string{http.MethodPost},
			Handler: func(*engine.Context) (contract.Response, error) {
				err := contract.NewAPIError(
					contract.StatusUnauthorized, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password",
				)
				return contract.ResponseFromError(err), err
			},
		},
		{
			Name: i18nProbeSuccess, Path: "/i18n-probe-success", Methods: []string{http.MethodGet},
			Handler: func(*engine.Context) (contract.Response, error) {
				return contract.JSONResponse(contract.StatusOK, map[string]any{
					"session": map[string]any{"id": "session-id"},
					"user":    map[string]any{"id": "user-id"},
				})
			},
		},
	}
}

func mustI18nRegistry(t *testing.T, plugin engine.Plugin) *engine.Registry {
	t.Helper()
	registry, err := engine.NewRegistry(i18nProbeEndpoints(), plugin)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func executeI18nTransport(t *testing.T, auth *singleauth.Auth, mode, transport string) i18nObservation {
	t.Helper()
	success := mode == "success-unchanged"
	method, path := http.MethodPost, "/api/auth/i18n-probe-error"
	if success {
		method, path = http.MethodGet, "/api/auth/i18n-probe-success"
	}
	headers := headersForI18nMode(mode)
	if method == http.MethodPost {
		// single-auth's client supplies the same-origin request context. The
		// explicit transport matrix reconstructs that context at the wire layer.
		headers.Set("Origin", "http://localhost:3000")
	}
	var response contract.Response
	switch transport {
	case "net/http":
		request := httptest.NewRequest(method, "http://localhost:3000"+path, nil)
		for _, field := range headers.Fields() {
			request.Header.Add(field.Name, field.Value)
		}
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		responseHeaders := contract.Headers{}
		for name, values := range recorder.Header() {
			for _, value := range values {
				responseHeaders.Add(name, value)
			}
		}
		response = contract.NewResponse(recorder.Code, responseHeaders, recorder.Body.Bytes())
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.Header.SetHost("localhost:3000")
		request.SetRequestURI(path)
		for _, field := range headers.Fields() {
			request.Header.Add(field.Name, field.Value)
		}
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, nil, nil)
		handler(&requestContext)
		response = contract.NewResponse(requestContext.Response.StatusCode(), contract.Headers{}, requestContext.Response.Body())
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(method, "http://localhost:3000"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range headers.Fields() {
			request.Header.Add(field.Name, field.Value)
		}
		result, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Body.Close()
		body, err := io.ReadAll(result.Body)
		if err != nil {
			t.Fatal(err)
		}
		response = contract.NewResponse(result.StatusCode, contract.Headers{}, body)
	default:
		t.Fatalf("unknown transport %q", transport)
	}
	return responseObservation(t, response)
}

func responseObservation(t *testing.T, response contract.Response) i18nObservation {
	t.Helper()
	observation := i18nObservation{Status: response.Status()}
	if len(response.Body()) == 0 {
		return observation
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Body()))
	decoder.UseNumber()
	if err := decoder.Decode(&observation.Body); err != nil {
		t.Fatalf("decode response body %q: %v", response.Body(), err)
	}
	return observation
}
