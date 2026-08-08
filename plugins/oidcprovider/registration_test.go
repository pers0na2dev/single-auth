package oidcprovider

import (
	"encoding/json"
	"net/http"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestRegisterAndGetOAuthClient(t *testing.T) {
	harness := newHarness(t, func(options *Options) {
		options.GenerateClientID = func() string { return "registered-client" }
		options.GenerateClientSecret = func() string { return "registered-secret" }
	})
	_, headers := harness.signUp(t, 1)
	result, err := harness.call(t, "registerOAuthApplication", http.MethodPost, headers, map[string]any{
		"client_name": "test", "redirect_uris": []string{"https://client.example/callback"},
		"logo_uri": "", "metadata": map[string]any{"tenant": "acme"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	created := responseObject(t, result)
	if result.Response.Status() != 201 || created["client_id"] != "registered-client" ||
		created["client_secret"] != "registered-secret" || created["client_name"] != "test" ||
		created["token_endpoint_auth_method"] != "client_secret_basic" ||
		created["client_secret_expires_at"] != json.Number("0") {
		t.Fatalf("created=%#v status=%d", created, result.Response.Status())
	}
	if headerValue(result.Response.Headers(), "Cache-Control") != "no-store" ||
		headerValue(result.Response.Headers(), "Pragma") != "no-cache" {
		t.Fatalf("headers=%#v", result.Response.Headers())
	}
	record, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "oauthApplication", Where: []storage.Where{{Field: "clientId", Value: "registered-client"}},
	})
	if err != nil || record == nil || record["clientSecret"] != "registered-secret" ||
		record["redirectUrls"] != "https://client.example/callback" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	clientResult, err := harness.auth.API().Call(t.Context(), "getOAuthClient", contractCallInput(
		http.MethodGet, headers, nil, map[string]string{"id": "registered-client"},
	))
	if err != nil {
		t.Fatal(err)
	}
	client := responseObject(t, clientResult)
	if client["clientId"] != "registered-client" || client["name"] != "test" || client["icon"] != nil {
		t.Fatalf("client=%#v", client)
	}
}

func TestRegistrationAuthenticationAndDynamicRegistration(t *testing.T) {
	restricted := newHarness(t, nil)
	result, err := restricted.call(t, "registerOAuthApplication", http.MethodPost, contract.Headers{}, map[string]any{
		"client_name": "anonymous", "redirect_uris": []string{"https://client.example/callback"},
	}, nil)
	oauthErrorObject(t, result, err, http.StatusUnauthorized, "invalid_token")

	dynamic := newHarness(t, func(options *Options) {
		options.AllowDynamicClientRegistration = true
	})
	result, err = dynamic.call(t, "registerOAuthApplication", http.MethodPost, contract.Headers{}, map[string]any{
		"client_name": "anonymous", "redirect_uris": []string{"https://client.example/callback"},
	}, nil)
	if err != nil || result.Response.Status() != 201 || responseObject(t, result)["client_id"] == "" {
		t.Fatalf("dynamic status=%d err=%v body=%s", result.Response.Status(), err, result.Response.Body())
	}
}

func TestRegistrationRejectsDangerousRedirectSchemes(t *testing.T) {
	harness := newHarness(t, nil)
	_, headers := harness.signUp(t, 2)
	for _, uri := range []string{
		"javascript:fetch('/api/auth/get-session')//",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
	} {
		t.Run(uri[:4], func(t *testing.T) {
			result, err := harness.call(t, "registerOAuthApplication", http.MethodPost, headers, map[string]any{
				"client_name": "Evil App", "redirect_uris": []string{uri},
			}, nil)
			if err == nil || result.Response.Status() != http.StatusBadRequest {
				t.Fatalf("uri=%q status=%d err=%v", uri, result.Response.Status(), err)
			}
		})
	}
}

func TestRegistrationAcceptsHTTPSAndLoopbackHTTP(t *testing.T) {
	harness := newHarness(t, nil)
	_, headers := harness.signUp(t, 3)
	result, err := harness.call(t, "registerOAuthApplication", http.MethodPost, headers, map[string]any{
		"client_name": "Good App",
		"redirect_uris": []string{
			"https://client.example.com/callback", "http://localhost:3000/callback",
		},
	}, nil)
	if err != nil || result.Response.Status() != 201 || responseObject(t, result)["client_id"] == "" {
		t.Fatalf("status=%d err=%v body=%s", result.Response.Status(), err, result.Response.Body())
	}
}

func contractCallInput(method string, headers contract.Headers, body any, params map[string]string) singleauth.DirectCallInput {
	return singleauth.DirectCallInput{
		Method: method, Scheme: "http", Host: "localhost:3000",
		Headers: headers, Body: body, Params: params,
	}
}
