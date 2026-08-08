package customsession

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestGetSessionProjectsSerializedCoreResponse(t *testing.T) {
	var callbackPath string
	var callbackMethod string
	_, dispatcher := newTestPlugin(t, func(options *Options) {
		options.Enrich = func(data SessionData, ctx *engine.Context) (any, error) {
			callbackPath = ctx.Path()
			callbackMethod = ctx.Request().Method()
			if data.User["role"] != "admin" || data.Session["custom"] != "serialized-session-field" {
				t.Fatalf("serialized input = %#v", data)
			}
			data.User["role"] = "mutated"
			return map[string]any{
				"profile": map[string]any{"firstName": "Ada", "role": "admin"},
				"custom":  map[string]any{"message": "Hello, World!"},
			}, nil
		}
	})

	response, err := dispatchGetSession(t, dispatcher)
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	result := responseMap(t, response)
	if _, exists := result["user"]; exists {
		t.Fatalf("custom response leaked default user: %#v", result)
	}
	if result["custom"].(map[string]any)["message"] != "Hello, World!" ||
		callbackPath != "/get-session" || callbackMethod != http.MethodGet {
		t.Fatalf("custom response=%#v path=%q method=%q", result, callbackPath, callbackMethod)
	}
}

func TestGetSessionForwardsDistinctCookieAndCacheHeaders(t *testing.T) {
	innerHeaders := contract.NewHeaders(
		contract.HeaderField{Name: "Set-Cookie", Value: "single-auth.session_token=abc%2525def; Max-Age=86400; Path=/; HttpOnly; SameSite=Lax"},
		contract.HeaderField{Name: "Set-Cookie", Value: "single-auth.session_data=cache%2525value; Max-Age=300; Path=/; HttpOnly; Secure; SameSite=None; Partitioned"},
		contract.HeaderField{Name: "Cache-Control", Value: "no-store"},
		contract.HeaderField{Name: "Pragma", Value: "no-cache"},
	)
	_, dispatcher := newTestPlugin(t, func(options *Options) {
		options.Runtime.GetSession = func(*engine.Context) (contract.Response, error) {
			return testSessionResponse("user-1", "token-1", innerHeaders), nil
		}
	})

	response, err := dispatchGetSession(t, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	setCookies := response.Headers().Values("Set-Cookie")
	if len(setCookies) != 2 {
		t.Fatalf("Set-Cookie = %#v", setCookies)
	}
	if strings.Contains(setCookies[0], "%252525") || strings.Contains(setCookies[1], "%252525") {
		t.Fatalf("cookies were double encoded: %#v", setCookies)
	}
	parsedToken := cookies.ParseSetCookieHeader(setCookies[0])
	parsedData := cookies.ParseSetCookieHeader(setCookies[1])
	if len(parsedToken) != 1 || len(parsedData) != 1 ||
		parsedToken[0].Attributes.MaxAge == nil || *parsedToken[0].Attributes.MaxAge != 86400 ||
		parsedData[0].Attributes.MaxAge == nil || *parsedData[0].Attributes.MaxAge != 300 ||
		parsedToken[0].Attributes.Value != "abc%25def" || parsedData[0].Attributes.Value != "cache%25value" ||
		!parsedData[0].Attributes.Partitioned || parsedData[0].Attributes.SameSite != "none" {
		t.Fatalf("parsed cookies = %#v %#v", parsedToken, parsedData)
	}
	cacheControl, _ := response.Headers().Get("Cache-Control")
	pragma, _ := response.Headers().Get("Pragma")
	if cacheControl != "no-store" || pragma != "no-cache" {
		t.Fatalf("cache headers = %q %q", cacheControl, pragma)
	}
}

func TestGetSessionNullAndInnerFailuresAreNull(t *testing.T) {
	for _, test := range []struct {
		name string
		get  GetSessionFunc
	}{
		{
			name: "null response",
			get: func(*engine.Context) (contract.Response, error) {
				return contract.JSONResponse(http.StatusOK, nil)
			},
		},
		{
			name: "thrown error",
			get: func(*engine.Context) (contract.Response, error) {
				return contract.Response{}, errors.New("adapter failed")
			},
		},
		{
			name: "non-200 response",
			get: func(*engine.Context) (contract.Response, error) {
				return contract.JSONResponse(http.StatusInternalServerError, map[string]any{"error": true})
			},
		},
		{
			name: "malformed response",
			get: func(*engine.Context) (contract.Response, error) {
				return contract.NewResponse(http.StatusOK, contract.Headers{}, []byte("not-json")), nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var callbacks atomic.Int64
			_, dispatcher := newTestPlugin(t, func(options *Options) {
				options.Runtime.GetSession = test.get
				options.Enrich = func(SessionData, *engine.Context) (any, error) {
					callbacks.Add(1)
					return map[string]any{"unexpected": true}, nil
				}
			})
			response, err := dispatchGetSession(t, dispatcher)
			if err != nil || response.Status() != http.StatusOK || string(response.Body()) != "null" || callbacks.Load() != 0 {
				t.Fatalf("status=%d body=%s callbacks=%d err=%v", response.Status(), response.Body(), callbacks.Load(), err)
			}
			if response.Headers().Len() != 1 { // JSON content type only.
				t.Fatalf("failed inner headers leaked: %#v", response.Headers().Fields())
			}
		})
	}
}

func TestGetSessionCallbackErrorPropagatesBeforeHeaders(t *testing.T) {
	sentinel := errors.New("custom projection failed")
	_, dispatcher := newTestPlugin(t, func(options *Options) {
		options.Runtime.GetSession = func(*engine.Context) (contract.Response, error) {
			return testSessionResponse("user-1", "token-1", contract.NewHeaders(
				contract.HeaderField{Name: "Set-Cookie", Value: "single-auth.session_token=secret; Path=/"},
			)), nil
		}
		options.Enrich = func(SessionData, *engine.Context) (any, error) { return nil, sentinel }
	})
	response, err := dispatchGetSession(t, dispatcher)
	if !errors.Is(err, sentinel) || response.Status() != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	if values := response.Headers().Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("callback failure forwarded cookies: %#v", values)
	}
}

func TestDirectGetSessionUsesSameProjection(t *testing.T) {
	_, dispatcher := newTestPlugin(t, nil)
	request := contract.NewRequest(http.MethodGet, "/:direct", contract.RequestOptions{})
	response, err := dispatcher.Invoke("getSession", engine.DirectInput{Request: request})
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("direct status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	if got := responseMap(t, response); !reflect.DeepEqual(got, map[string]any{
		"subject": "user-1", "role": "admin", "token": "token-1",
	}) {
		t.Fatalf("direct result = %#v", got)
	}
}

func TestConfigurationValidationAndSnapshot(t *testing.T) {
	_, err := New(Options{})
	if err == nil || err.Error() != "customsession: Enrich is required" {
		t.Fatalf("missing enrich error = %v", err)
	}
	_, err = New(Options{Enrich: func(SessionData, *engine.Context) (any, error) { return nil, nil }})
	if err == nil || err.Error() != "customsession: Runtime.GetSession is required" {
		t.Fatalf("missing runtime error = %v", err)
	}
}
