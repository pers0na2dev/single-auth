package singleauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type signOutCase struct {
	Suite       string
	Title       string
	Observation signOutObservation
}

type signOutObservation struct {
	Data struct {
		Success bool `json:"success"`
	} `json:"data"`
	Error               any `json:"error"`
	AfterSessionDeleted int `json:"afterSessionDeleted"`
}

type signOutExchange func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error)

func TestSignOutHTTPBehavior(t *testing.T) {
	for _, vector := range signOutCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				var afterDelete atomic.Int64
				auth, err := singleauth.New(singleauth.Options{
					BaseURL: "http://localhost:3000",
					Secret:  "0123456789abcdef0123456789abcdef",
					EmailAndPassword: singleauth.EmailAndPasswordOptions{
						Enabled: true,
						Password: singleauth.PasswordOptions{
							Hash:   func(password string) (string, error) { return password, nil },
							Verify: func(hash, password string) bool { return hash == password },
						},
					},
					DatabaseHooks: singleauth.DatabaseHooks{
						"session": {Delete: singleauth.DatabaseOperationHooks{
							After: func(any, singleauth.DatabaseHookContext) error {
								afterDelete.Add(1)
								return nil
							},
						}},
					},
				})
				if err != nil {
					t.Fatalf("%s: New: %v", transportName, err)
				}
				exchange := newSignOutExchange(t, transportName, auth)
				email := "sign-out-" + transportName + "@example.test"
				signUpBody, _ := json.Marshal(map[string]any{
					"name": "Sign Out", "email": email, "password": "password123",
				})
				headers := http.Header{"Content-Type": {"application/json"}, "Origin": {"http://localhost:3000"}}
				status, responseHeaders, body, err := exchange(http.MethodPost, "/api/auth/sign-up/email", headers, signUpBody)
				if err != nil || status != http.StatusOK {
					t.Fatalf("%s: sign-up status=%d body=%s err=%v", transportName, status, body, err)
				}
				cookieHeader := cookies.ApplySetCookies("", responseHeaders.Values("Set-Cookie"))
				if cookieHeader == "" {
					t.Fatalf("%s: sign-up returned no session cookie", transportName)
				}
				headers.Set("Cookie", cookieHeader)
				status, _, body, err = exchange(http.MethodPost, "/api/auth/sign-out", headers, nil)
				if err != nil || status != http.StatusOK {
					t.Fatalf("%s: sign-out status=%d body=%s err=%v", transportName, status, body, err)
				}
				var response struct {
					Success bool `json:"success"`
				}
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatalf("%s: decode sign-out: %v", transportName, err)
				}
				actual := signOutObservation{Error: nil, AfterSessionDeleted: int(afterDelete.Load())}
				actual.Data.Success = response.Success
				if !reflect.DeepEqual(actual, vector.Observation) {
					t.Fatalf("%s: sign-out observation = %#v, want %#v", transportName, actual, vector.Observation)
				}
			}
		})
	}
}

func newSignOutExchange(t *testing.T, transportName string, auth *singleauth.Auth) signOutExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
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
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.SetRequestURI(target)
			request.Header.SetHost("localhost:3000")
			for name, values := range headers {
				for _, value := range values {
					request.Header.Add(name, value)
				}
			}
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(&request, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123}, nil)
			handler(&requestContext)
			responseHeaders := make(http.Header)
			requestContext.Response.Header.VisitAll(func(name, value []byte) {
				responseHeaders.Add(string(name), string(value))
			})
			return requestContext.Response.StatusCode(), responseHeaders, append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			if err != nil {
				return 0, nil, nil, err
			}
			request.Header = headers.Clone()
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return 0, nil, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	default:
		t.Fatalf("unknown sign-out transport %q", transportName)
		return nil
	}
}

func TestSignOutScenarioDefinitions(t *testing.T) {
	cases := signOutCases()
	if len(cases) != 1 || cases[0].Suite == "" || cases[0].Title == "" {
		t.Fatalf("invalid sign-out scenarios: %#v", cases)
	}
}

func signOutCases() []signOutCase {
	want := signOutObservation{Error: nil, AfterSessionDeleted: 1}
	want.Data.Success = true
	return []signOutCase{{Suite: "sign-out", Title: "should sign out", Observation: want}}
}
