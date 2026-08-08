package oauthprovider

import (
	"context"
	"net/http"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestOAuthProviderConsentFactoryBindsRootSessionAndServerAPI(t *testing.T) {
	now := time.Date(2028, time.January, 2, 3, 4, 5, 987000000, time.UTC)
	factory := NewConsentFactory(ConsentOptions{})
	auth, err := singleauth.New(singleauth.Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Clock:            func() time.Time { return now },
		PluginFactories:  []singleauth.PluginFactory{factory},
	})
	if err != nil {
		t.Fatal(err)
	}
	signedUp, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Consent Root User", Email: "consent-root@test.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "oauthClient",
		Data: storage.Record{
			"clientId": "root-consent-client", "clientSecret": "secret",
			"redirectUris": []string{"http://localhost:5000/callback"},
			"userId":       signedUp.User.ID,
		},
	}); err != nil {
		t.Fatal(err)
	}
	created, err := factory.CreateConsent(context.Background(), CreateConsentInput{
		ClientID: "root-consent-client", UserID: signedUp.User.ID, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", signedUp.Headers.Values("Set-Cookie"))
	result, err := auth.API().Call(t.Context(), "getOAuthConsent", singleauth.DirectCallInput{
		Method:  http.MethodGet,
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
		Query:   map[string][]string{"id": {consentRecordString(created, "id")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	object, ok := result.Value.(map[string]any)
	if result.Response.Status() != http.StatusOK || !ok || object["clientId"] != "root-consent-client" {
		t.Fatalf("root consent response = status %d value %#v", result.Response.Status(), result.Value)
	}
}
