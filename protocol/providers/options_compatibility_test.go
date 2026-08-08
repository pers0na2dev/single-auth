package providers

import (
	"errors"
	"strings"
	"testing"
)

func TestProviderConfigurationErrors(t *testing.T) {
	if _, err := Cognito(Options{}); !errors.Is(err, ErrDomainAndRegionRequired) {
		t.Fatalf("Cognito constructor error = %v", err)
	}
	credentialProviders := []string{"apple", "atlassian", "facebook", "figma", "google", "paybin", "paypal", "salesforce"}
	for _, id := range credentialProviders {
		provider, err := New(id, Options{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.CreateAuthorizationURL(AuthorizationInput{CodeVerifier: "verifier"})
		if !errors.Is(err, ErrClientIDAndSecretRequired) {
			t.Errorf("%s credentials error = %v", id, err)
		}
	}
	microsoft, _ := Microsoft(Options{})
	if _, err := microsoft.CreateAuthorizationURL(AuthorizationInput{}); !errors.Is(err, ErrClientIDAndSecretRequired) {
		t.Fatalf("Microsoft client id error = %v", err)
	}
	cognito, _ := Cognito(Options{Domain: "domain", Region: "region", UserPoolID: "pool", RequireClientSecret: true, ClientID: "client"})
	if _, err := cognito.CreateAuthorizationURL(AuthorizationInput{}); !errors.Is(err, ErrClientSecretRequired) {
		t.Fatalf("Cognito client secret error = %v", err)
	}
}

func TestRequiredPKCEErrorsMatchProviderMessages(t *testing.T) {
	for _, id := range []string{"atlassian", "figma", "google", "paybin", "salesforce", "vercel"} {
		provider, err := New(id, Options{ClientID: "client", ClientSecret: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.CreateAuthorizationURL(AuthorizationInput{})
		if err == nil || !strings.Contains(err.Error(), "codeVerifier is required for "+provider.Name) {
			t.Errorf("%s PKCE error = %v", id, err)
		}
	}
}

func TestOptionOverridesAndEmptyScopeSemantics(t *testing.T) {
	provider, _ := Google(Options{ClientID: []string{"primary", "secondary"}, ClientSecret: "secret", RedirectURI: "https://configured.example/callback", AuthorizationEndpoint: "https://issuer.example/authorize", DisableDefaultScope: true})
	url, err := provider.CreateAuthorizationURL(AuthorizationInput{State: "state", CodeVerifier: "verifier", RedirectURI: "https://ignored.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if url.Host != "issuer.example" || url.Query().Get("client_id") != "primary" || url.Query().Get("redirect_uri") != "https://configured.example/callback" {
		t.Fatalf("option overrides not applied: %s", url)
	}
	if !strings.Contains(url.RawQuery, "scope=") {
		t.Fatalf("disabled defaults must retain the reference implementation's empty scope parameter: %s", url)
	}

	vercel, _ := Vercel(Options{ClientID: "client"})
	url, err = vercel.CreateAuthorizationURL(AuthorizationInput{State: "state", CodeVerifier: "verifier", RedirectURI: "https://app.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(url.RawQuery, "scope=") {
		t.Fatalf("Vercel must omit scope when neither scope source is defined: %s", url)
	}
}

func TestDynamicEndpointOptions(t *testing.T) {
	tests := []struct {
		name, id string
		options  Options
		authHost string
		tokenURL string
	}{
		{name: "GitLab issuer", id: "gitlab", options: Options{ClientID: "c", Issuer: "https://gitlab.example///"}, authHost: "gitlab.example", tokenURL: "https://gitlab.example/oauth/token"},
		{name: "Paybin issuer", id: "paybin", options: Options{ClientID: "c", ClientSecret: "s", Issuer: "https://paybin.example"}, authHost: "paybin.example", tokenURL: "https://paybin.example/oauth2/token"},
		{name: "Salesforce sandbox", id: "salesforce", options: Options{ClientID: "c", ClientSecret: "s", Environment: "sandbox"}, authHost: "test.salesforce.com", tokenURL: "https://test.salesforce.com/services/oauth2/token"},
		{name: "PayPal live", id: "paypal", options: Options{ClientID: "c", ClientSecret: "s", Environment: "live"}, authHost: "www.paypal.com", tokenURL: "https://api-m.paypal.com/v1/oauth2/token"},
		{name: "Microsoft authority", id: "microsoft", options: Options{ClientID: "c", TenantID: "tenant", Authority: "https://login.example///"}, authHost: "login.example", tokenURL: "https://login.example/tenant/oauth2/v2.0/token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, err := New(test.id, test.options)
			if err != nil {
				t.Fatal(err)
			}
			url, err := provider.CreateAuthorizationURL(AuthorizationInput{CodeVerifier: "verifier", RedirectURI: "https://app.example/callback"})
			if err != nil {
				t.Fatal(err)
			}
			if url.Host != test.authHost || provider.Metadata.TokenEndpoint != test.tokenURL {
				t.Fatalf("got auth=%s token=%s", url, provider.Metadata.TokenEndpoint)
			}
		})
	}
}
