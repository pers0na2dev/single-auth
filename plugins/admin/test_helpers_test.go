package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type testIdentity struct {
	ID     string
	Email  string
	Cookie string
}

func newRootAuth(t *testing.T, options Options, additional ...singleauth.PluginFactory) *singleauth.Auth {
	return newRootAuthConfigured(t, options, nil, additional...)
}

func newRootAuthConfigured(
	t *testing.T,
	options Options,
	configure func(*singleauth.Options),
	additional ...singleauth.PluginFactory,
) *singleauth.Auth {
	t.Helper()
	factories := []singleauth.PluginFactory{NewFactory(options)}
	factories = append(factories, additional...)
	rootOptions := singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  testSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
				Verify: func(hash, value string) bool { return hash == "hashed:"+value },
			},
		},
		PluginFactories: factories,
		DatabaseHooks: singleauth.DatabaseHooks{"user": {
			Create: singleauth.DatabaseOperationHooks{Before: func(data storage.Record, _ singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
				if name, _ := data["name"].(string); name == "Admin" || name == "Second Admin" {
					return singleauth.DatabaseHookResult{Data: storage.Record{"role": "admin", "emailVerified": true}}, nil
				}
				return singleauth.DatabaseHookResult{}, nil
			}},
		}},
	}
	if configure != nil {
		configure(&rootOptions)
	}
	auth, err := singleauth.New(rootOptions)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func signUpIdentity(t *testing.T, auth *singleauth.Auth, name, email, password string) testIdentity {
	t.Helper()
	status, headers, body := exchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": name, "email": email, "password": password,
	})
	if status != http.StatusOK {
		t.Fatalf("sign-up %s status=%d body=%#v", email, status, body)
	}
	user := objectField(t, body, "user")
	id, _ := user["id"].(string)
	return testIdentity{ID: id, Email: email, Cookie: cookies.ApplySetCookies("", headers.Values("Set-Cookie"))}
}

func signInIdentity(t *testing.T, auth *singleauth.Auth, email, password string) testIdentity {
	t.Helper()
	status, headers, body := exchange(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": email, "password": password,
	})
	if status != http.StatusOK {
		t.Fatalf("sign-in %s status=%d body=%#v", email, status, body)
	}
	user := objectField(t, body, "user")
	id, _ := user["id"].(string)
	return testIdentity{ID: id, Email: email, Cookie: cookies.ApplySetCookies("", headers.Values("Set-Cookie"))}
}

func exchange(
	t *testing.T,
	auth *singleauth.Auth,
	method, path, cookie string,
	body any,
) (int, contract.Headers, map[string]any) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "http://auth.example.test/api/auth"+path, bytes.NewReader(encoded))
	request.Header.Set("Origin", "http://auth.example.test")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	result := map[string]any{}
	if recorder.Body.Len() != 0 {
		decoder := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes()))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			t.Fatalf("decode %s %s status=%d body=%q: %v", method, path, recorder.Code, recorder.Body.String(), err)
		}
	}
	headers := contract.Headers{}
	for name, values := range recorder.Header() {
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	return recorder.Code, headers, result
}

func invoke(
	t *testing.T,
	auth *singleauth.Auth,
	name, method, cookie string,
	body any,
	query map[string][]string,
) (int, contract.Headers, any, error) {
	t.Helper()
	headers := contract.Headers{}
	if cookie != "" {
		headers.Set("Cookie", cookie)
	}
	result, err := auth.API().Call(context.Background(), name, singleauth.DirectCallInput{
		Method: method, Scheme: "http", Host: "auth.example.test", Headers: headers,
		Body: body, Query: query,
	})
	return result.Response.Status(), result.Response.Headers(), result.Value, err
}

func objectField(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	object, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("%s in %#v is not an object", key, value)
	}
	return object
}

func assertError(t *testing.T, status int, body map[string]any, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || body["code"] != code {
		t.Fatalf("status=%d body=%#v, want status=%d code=%s", status, body, wantStatus, code)
	}
}

func createDirectUser(t *testing.T, auth *singleauth.Auth, body map[string]any) map[string]any {
	t.Helper()
	status, _, value, err := invoke(t, auth, "createUser", http.MethodPost, "", body, nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("direct create status=%d value=%#v err=%v", status, value, err)
	}
	return value.(map[string]any)["user"].(map[string]any)
}
