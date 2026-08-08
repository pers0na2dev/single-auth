package genericoauth

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	authlogger "github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

func TestProviderHelpersMatchFrozenGenericOAuthConfigurations(t *testing.T) {
	base := BaseOAuthProviderOptions{ClientID: "client", ClientSecret: "secret"}
	tests := []struct {
		name          string
		config        Config
		providerID    string
		discoveryURL  string
		authorizeURL  string
		tokenURL      string
		userInfoURL   string
		hasUserInfo   bool
		integrationID string
	}{
		{
			name: "okta", config: Okta(OktaOptions{BaseOAuthProviderOptions: base, Issuer: "https://dev.okta.test/oauth2/default"}),
			providerID: "okta", discoveryURL: "https://dev.okta.test/oauth2/default/.well-known/openid-configuration",
			integrationID: "okta",
		},
		{
			name: "auth0", config: Auth0(Auth0Options{BaseOAuthProviderOptions: base, Domain: "dev.eu.auth0.test"}),
			providerID: "auth0", discoveryURL: "https://dev.eu.auth0.test/.well-known/openid-configuration",
			integrationID: "auth0",
		},
		{
			name: "microsoft entra", config: MicrosoftEntraID(MicrosoftEntraIDOptions{BaseOAuthProviderOptions: base, TenantID: "common"}),
			providerID:   "microsoft-entra-id",
			authorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			tokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			userInfoURL:  "https://graph.microsoft.com/oidc/userinfo", hasUserInfo: true,
			integrationID: "microsoft-entra-id",
		},
		{
			name: "slack", config: Slack(SlackOptions{BaseOAuthProviderOptions: base}),
			providerID: "slack", authorizeURL: "https://slack.com/openid/connect/authorize",
			tokenURL:    "https://slack.com/api/openid.connect.token",
			userInfoURL: "https://slack.com/api/openid.connect.userInfo", hasUserInfo: true,
			integrationID: "slack",
		},
		{
			name: "keycloak", config: Keycloak(KeycloakOptions{BaseOAuthProviderOptions: base, Issuer: "https://keycloak.test/realms/example"}),
			providerID: "keycloak", discoveryURL: "https://keycloak.test/realms/example/.well-known/openid-configuration",
			integrationID: "keycloak",
		},
	}
	wantScopes := []string{"openid", "profile", "email"}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := test.config
			if config.ProviderID != test.providerID || config.DiscoveryURL != test.discoveryURL ||
				config.AuthorizationURL != test.authorizeURL || config.TokenURL != test.tokenURL ||
				config.UserInfoURL != test.userInfoURL || config.ClientID != "client" ||
				config.ClientSecret != "secret" || !reflect.DeepEqual(config.Scopes, wantScopes) ||
				(config.GetUserInfo != nil) != test.hasUserInfo {
				t.Fatalf("helper config diverged: %#v", config)
			}
			if _, err := singleauth.New(singleauth.Options{
				BaseURL: genericBaseURL, Secret: genericSecret,
				PluginFactories: []singleauth.PluginFactory{NewFactory(Options{Config: []Config{config}})},
			}); err != nil {
				t.Fatalf("helper integration failed: %v", err)
			}
		})
	}
}

func TestAdditionalProviderHelpersConfigurationAndProfileMapping(t *testing.T) {
	client := &http.Client{Transport: genericRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{}`
		switch {
		case strings.Contains(request.URL.Host, "gumroad"):
			body = `{"success":true,"user":{"user_id":101,"name":"Gumroad User","email":"gumroad@test.com","profile_url":"https://example.test/gumroad"}}`
		case strings.Contains(request.URL.Host, "hubapi"):
			body = `{"user_id":202,"user":"hubspot@test.com"}`
		case strings.Contains(request.URL.Host, "line.me"):
			body = `{"sub":"line-user","name":"LINE User","email":"line@test.com","picture":"https://example.test/line"}`
		case strings.Contains(request.URL.Host, "patreon"):
			body = `{"data":{"id":"patreon-user","attributes":{"full_name":"Patreon User","email":"patreon@test.com","image_url":"https://example.test/patreon","is_email_verified":true}}}`
		case strings.Contains(request.URL.Host, "yandex"):
			body = `{"id":"yandex-user","login":"fallback-login","display_name":"Yandex User","emails":["yandex@test.com"],"default_avatar_id":"avatar-id","is_avatar_empty":false}`
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}
	base := BaseOAuthProviderOptions{ClientID: "client", ClientSecret: "secret", HTTPClient: client}
	tests := []struct {
		name       string
		config     Config
		providerID string
		wantID     string
		wantEmail  string
		wantImage  string
		verified   bool
	}{
		{name: "gumroad", config: Gumroad(GumroadOptions{BaseOAuthProviderOptions: base}), providerID: "gumroad", wantID: "101", wantEmail: "gumroad@test.com", wantImage: "https://example.test/gumroad"},
		{name: "hubspot", config: HubSpot(HubSpotOptions{BaseOAuthProviderOptions: base}), providerID: "hubspot", wantID: "202", wantEmail: "hubspot@test.com"},
		{name: "line", config: Line(LineOptions{BaseOAuthProviderOptions: base, ProviderID: "line-jp"}), providerID: "line-jp", wantID: "line-user", wantEmail: "line@test.com", wantImage: "https://example.test/line"},
		{name: "patreon", config: Patreon(PatreonOptions{BaseOAuthProviderOptions: base}), providerID: "patreon", wantID: "patreon-user", wantEmail: "patreon@test.com", wantImage: "https://example.test/patreon", verified: true},
		{name: "yandex", config: Yandex(YandexOptions{BaseOAuthProviderOptions: base}), providerID: "yandex", wantID: "yandex-user", wantEmail: "yandex@test.com", wantImage: "https://avatars.yandex.net/get-yapic/avatar-id/islands-200"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.config.ProviderID != test.providerID || test.config.GetUserInfo == nil || len(test.config.Scopes) == 0 {
				t.Fatalf("helper configuration=%#v", test.config)
			}
			profile, err := test.config.GetUserInfo(t.Context(), oauth2.Tokens{AccessToken: "access"})
			if err != nil || profile == nil || stringValue(profile["id"]) != test.wantID ||
				stringValue(profile["email"]) != test.wantEmail || stringValue(profile["image"]) != test.wantImage ||
				boolValue(profile["emailVerified"]) != test.verified {
				t.Fatalf("mapped profile=%#v err=%v", profile, err)
			}
		})
	}
}

type genericRoundTripFunc func(*http.Request) (*http.Response, error)

func (function genericRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestProviderHelpersNormalizeInputAndForwardOverrides(t *testing.T) {
	customScopes := []string{"openid", "profile"}
	base := BaseOAuthProviderOptions{
		ClientID: "client", ClientSecret: "secret", Scopes: customScopes,
		PKCE: true, DisableImplicitSignUp: true,
	}
	configs := []Config{
		Okta(OktaOptions{BaseOAuthProviderOptions: base, Issuer: "https://okta.test/oauth2/default/"}),
		Auth0(Auth0Options{BaseOAuthProviderOptions: base, Domain: "https://auth0.test"}),
		MicrosoftEntraID(MicrosoftEntraIDOptions{BaseOAuthProviderOptions: base, TenantID: "12345678-1234-1234-1234-123456789012"}),
		Slack(SlackOptions{BaseOAuthProviderOptions: base}),
		Keycloak(KeycloakOptions{BaseOAuthProviderOptions: base, Issuer: "https://keycloak.test/realms/test/"}),
	}
	customScopes[0] = "mutated"
	for _, config := range configs {
		if !reflect.DeepEqual(config.Scopes, []string{"openid", "profile"}) || !config.PKCE || !config.DisableImplicitSignUp {
			t.Fatalf("overrides were not preserved/snapshotted: %#v", config)
		}
	}
	if configs[0].DiscoveryURL != "https://okta.test/oauth2/default/.well-known/openid-configuration" {
		t.Fatalf("Okta trailing slash = %q", configs[0].DiscoveryURL)
	}
	if configs[1].DiscoveryURL != "https://auth0.test/.well-known/openid-configuration" {
		t.Fatalf("Auth0 protocol handling = %q", configs[1].DiscoveryURL)
	}
	if !strings.Contains(configs[2].AuthorizationURL, "12345678-1234-1234-1234-123456789012") {
		t.Fatalf("Entra GUID URL = %q", configs[2].AuthorizationURL)
	}
	if configs[4].DiscoveryURL != "https://keycloak.test/realms/test/.well-known/openid-configuration" {
		t.Fatalf("Keycloak trailing slash = %q", configs[4].DiscoveryURL)
	}
}

func TestDuplicateProviderIDWarningsAreUniqueOrderedAndSilentForUniqueIDs(t *testing.T) {
	tests := []struct {
		name    string
		ids     []string
		warning string
	}{
		{name: "one", ids: []string{"single-provider"}},
		{name: "unique", ids: []string{"unique-1", "unique-2"}},
		{name: "duplicate", ids: []string{"duplicate-id", "duplicate-id"}, warning: "Duplicate provider IDs found: duplicate-id"},
		{name: "multiple", ids: []string{"dup-1", "dup-1", "dup-2", "dup-2"}, warning: "Duplicate provider IDs found: dup-1, dup-2"},
		{name: "triple", ids: []string{"triple-dup", "triple-dup", "triple-dup"}, warning: "Duplicate provider IDs found: triple-dup"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var lock sync.Mutex
			var warnings []string
			configs := make([]Config, len(test.ids))
			for index, id := range test.ids {
				configs[index] = Config{
					ProviderID: id, AuthorizationURL: "https://provider.test/authorize",
					TokenURL: "https://provider.test/token", ClientID: "client", ClientSecret: "secret",
				}
			}
			_, err := singleauth.New(singleauth.Options{
				BaseURL: genericBaseURL, Secret: genericSecret,
				Logger: authlogger.Options{Log: func(level authlogger.Level, message string, _ ...any) {
					if level == authlogger.Warn && strings.HasPrefix(message, "Duplicate provider IDs found:") {
						lock.Lock()
						warnings = append(warnings, message)
						lock.Unlock()
					}
				}},
				PluginFactories: []singleauth.PluginFactory{NewFactory(Options{Config: configs})},
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.warning == "" && len(warnings) != 0 {
				t.Fatalf("unexpected warnings: %#v", warnings)
			}
			if test.warning != "" && !reflect.DeepEqual(warnings, []string{test.warning}) {
				t.Fatalf("warnings = %#v, want %q", warnings, test.warning)
			}
		})
	}
}
