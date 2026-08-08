package singleauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	organizationplugin "github.com/pers0na2dev/single-auth/plugins/organization"
	ssoplugin "github.com/pers0na2dev/single-auth/plugins/sso"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

type ssoSocialCallbackRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn ssoSocialCallbackRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestSSOSocialCallbackAssignsOrganizationByDomainAcrossTransports(t *testing.T) {
	tests := []struct {
		name                    string
		domainVerification      bool
		providerDomainVerified  bool
		socialEmailVerified     bool
		wantOrganizationMembers int
	}{
		{
			name:                    "verified SSO domain assigns an unverified social email",
			domainVerification:      true,
			providerDomainVerified:  true,
			socialEmailVerified:     false,
			wantOrganizationMembers: 1,
		},
		{
			name:                    "unverified SSO domain is ignored when verification is enabled",
			domainVerification:      true,
			providerDomainVerified:  false,
			socialEmailVerified:     true,
			wantOrganizationMembers: 0,
		},
		{
			name:                    "unverified SSO domain assigns when verification is disabled",
			domainVerification:      false,
			providerDomainVerified:  false,
			socialEmailVerified:     true,
			wantOrganizationMembers: 1,
		},
	}
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			for _, test := range tests {
				test := test
				t.Run(test.name, func(t *testing.T) {
					auth, adapter, roleInputs := newSSOSocialCallbackAssignmentAuth(
						t, test.domainVerification, test.providerDomainVerified,
						test.socialEmailVerified,
					)
					cookies := make(map[string]string)
					invokeSSOSocialCallback(t, auth, transport, cookies, "first-code")

					users := oidcRecords(t, adapter, "user")
					var socialUser storage.Record
					for _, user := range users {
						if user["email"] == "alice@corp.example" {
							socialUser = user
							break
						}
					}
					if socialUser == nil {
						t.Fatalf("social user not persisted: %#v", users)
					}
					members, err := adapter.FindMany(t.Context(), storage.FindManyParams{
						Model: "member", Where: []storage.Where{{Field: "userId", Value: socialUser["id"]}},
					})
					if err != nil {
						t.Fatal(err)
					}
					if len(members) != test.wantOrganizationMembers {
						t.Fatalf("members=%#v, want count %d", members, test.wantOrganizationMembers)
					}
					if test.wantOrganizationMembers == 0 {
						if len(*roleInputs) != 0 {
							t.Fatalf("role resolver called for rejected domain: %#v", *roleInputs)
						}
						return
					}
					if members[0]["organizationId"] != "org-domain" || members[0]["role"] != "auditor" {
						t.Fatalf("member=%#v", members[0])
					}
					if len(*roleInputs) != 1 {
						t.Fatalf("role inputs=%#v", *roleInputs)
					}
					roleInput := (*roleInputs)[0]
					if roleInput.User.Email != "alice@corp.example" ||
						roleInput.User.Fields["emailVerified"] != test.socialEmailVerified ||
						len(roleInput.UserInfo) != 0 || roleInput.Token != nil ||
						roleInput.Provider["providerId"] != "enterprise-domain" {
						t.Fatalf("role input=%#v", roleInput)
					}

					invokeSSOSocialCallback(t, auth, transport, cookies, "second-code")
					members, err = adapter.FindMany(t.Context(), storage.FindManyParams{
						Model: "member", Where: []storage.Where{{Field: "userId", Value: socialUser["id"]}},
					})
					if err != nil || len(members) != 1 || len(*roleInputs) != 1 {
						t.Fatalf("repeat callback members=%#v roleInputs=%#v err=%v", members, *roleInputs, err)
					}
				})
			}
		})
	}
}

func newSSOSocialCallbackAssignmentAuth(
	t *testing.T,
	domainVerification bool,
	providerDomainVerified bool,
	socialEmailVerified bool,
) (*singleauth.Auth, storage.Adapter, *[]ssoplugin.OrganizationRoleInput) {
	t.Helper()
	email := "alice@corp.example"
	provider, err := providers.Google(providers.Options{
		ClientID: "social-client", ClientSecret: "social-secret",
		HTTPClient: &http.Client{Transport: ssoSocialCallbackRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPost || request.URL.String() != "https://oauth2.googleapis.com/token" {
				t.Fatalf("unexpected social OAuth request %s %s", request.Method, request.URL)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"social-access","token_type":"Bearer"}`)),
				Request:    request,
			}, nil
		})},
		GetUserInfo: func(_ context.Context, tokens oauth2.Tokens) (*providers.UserInfoResult, error) {
			if tokens.AccessToken != "social-access" {
				t.Fatalf("social access token=%q", tokens.AccessToken)
			}
			return &providers.UserInfoResult{User: oauth2.UserInfo{
				ID: "social-user", Name: "Social User", Email: &email,
				EmailVerified: socialEmailVerified,
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	roleInputs := make([]ssoplugin.OrganizationRoleInput, 0, 1)
	ssoFactory := ssoplugin.NewFactory(ssoplugin.Options{
		DomainVerification: ssoplugin.DomainVerificationOptions{Enabled: domainVerification},
		OrganizationProvisioning: ssoplugin.OrganizationProvisioningOptions{
			GetRole: func(_ context.Context, input ssoplugin.OrganizationRoleInput) (string, error) {
				roleInputs = append(roleInputs, input)
				return "auditor", nil
			},
		},
	})
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: oidcAuthBaseURL, Secret: "sso-social-callback-secret-at-least-32-bytes",
		Clock:           func() time.Time { return time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC) },
		SocialProviders: map[string]*providers.Provider{"google": provider},
		PluginFactories: []singleauth.PluginFactory{
			organizationplugin.NewFactory(organizationplugin.Options{}), ssoFactory,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := auth.Adapter()
	owner, err := auth.InternalAdapter().CreateUser(t.Context(), storage.Record{
		"name": "Domain Owner", "email": "owner@example.test", "emailVerified": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "organization", Data: storage.Record{
			"id": "org-domain", "name": "Domain Org", "slug": "domain-org",
			"createdAt": time.Date(2026, time.August, 10, 11, 0, 0, 0, time.UTC),
		}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	providerData := storage.Record{
		"issuer": "https://idp.example.test", "domain": "corp.example",
		"userId": owner["id"], "providerId": "enterprise-domain",
		"organizationId": "org-domain",
	}
	if domainVerification {
		providerData["domainVerified"] = providerDomainVerified
	}
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "ssoProvider", Data: providerData,
	}); err != nil {
		t.Fatal(err)
	}
	return auth, adapter, &roleInputs
}

func invokeSSOSocialCallback(
	t *testing.T,
	auth *singleauth.Auth,
	transport string,
	cookies map[string]string,
	code string,
) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider": "google", "callbackURL": "/social-complete",
	})
	if err != nil {
		t.Fatal(err)
	}
	started := ssoOIDCExchange(t, auth, transport, http.MethodPost, "/sign-in/social", body, cookies)
	if started.status != http.StatusOK {
		t.Fatalf("start social OAuth status=%d body=%s", started.status, started.body)
	}
	var startBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(started.body, &startBody); err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := url.Parse(startBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := authorizationURL.Query().Get("state")
	if state == "" {
		t.Fatalf("social authorization URL has no state: %s", authorizationURL)
	}
	callback := ssoOIDCExchange(t, auth, transport, http.MethodGet,
		"/callback/google?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, cookies)
	if callback.status != http.StatusFound || callback.header.Get("Location") != "/social-complete" {
		t.Fatalf("social callback status=%d location=%q body=%s",
			callback.status, callback.header.Get("Location"), callback.body)
	}
}
