package customplugin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
)

func TestFactoryEndpointUsesRootSession(t *testing.T) {
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "https://auth.example.com",
		Secret:  strings.Repeat("s", 48),
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
		},
		PluginFactories: []singleauth.PluginFactory{NewFactory()},
	})
	if err != nil {
		t.Fatal(err)
	}

	signUp := httptest.NewRequest(
		http.MethodPost,
		"https://auth.example.com/api/auth/sign-up/email",
		strings.NewReader(`{"name":"Ada","email":"ada@example.com","password":"correct-horse-battery-staple"}`),
	)
	signUp.Header.Set("Content-Type", "application/json")
	signUpResponse := httptest.NewRecorder()
	auth.ServeHTTP(signUpResponse, signUp)
	if signUpResponse.Code != http.StatusOK {
		t.Fatalf("sign up status = %d, body = %s", signUpResponse.Code, signUpResponse.Body.String())
	}

	whoAmI := httptest.NewRequest(
		http.MethodGet,
		"https://auth.example.com/api/auth/who-am-i",
		nil,
	)
	for _, cookie := range signUpResponse.Result().Cookies() {
		whoAmI.AddCookie(cookie)
	}
	whoAmIResponse := httptest.NewRecorder()
	auth.ServeHTTP(whoAmIResponse, whoAmI)
	if whoAmIResponse.Code != http.StatusOK {
		t.Fatalf("who-am-I status = %d, body = %s", whoAmIResponse.Code, whoAmIResponse.Body.String())
	}
	if body := whoAmIResponse.Body.String(); !strings.Contains(body, `"email":"ada@example.com"`) {
		t.Fatalf("who-am-I body = %s", body)
	}
}
