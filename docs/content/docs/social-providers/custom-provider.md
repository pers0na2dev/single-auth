---
title: "Custom provider"
---

Implement a server-side OAuth provider while retaining single-auth account and session behavior.

Use `providers.NewCustomProvider` when no built-in provider or Generic OAuth configuration represents the remote service correctly. The custom provider plugs into the same social sign-in, callback, account-linking, token, hook, and session lifecycle as a built-in.

## Required callbacks

`ID`, `CreateAuthorizationURL`, `ValidateAuthorizationCode`, and `GetUserInfo` are required. `Name` defaults to the ID. Refresh and ID-token verification callbacks are optional.

~~~go
const maxUserInfoBytes int64 = 1 << 20

clientID := os.Getenv("ACME_CLIENT_ID")
clientSecret := os.Getenv("ACME_CLIENT_SECRET")
providerHTTPClient := &http.Client{
    Timeout: 10 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse
    },
}

custom, err := providers.NewCustomProvider(providers.CustomProvider{
    ID:   "acme",
    Name: "Acme Identity",
    Options: providers.Options{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        HTTPClient:   providerHTTPClient,
    },
    Metadata: providers.Metadata{
        AuthorizationEndpoint: "https://identity.acme.example/oauth/authorize",
        TokenEndpoint:         "https://identity.acme.example/oauth/token",
        UserInfoEndpoint:      "https://identity.acme.example/oauth/userinfo",
        DefaultScopes:         []string{"openid", "profile", "email"},
        TokenAuthentication:   oauth2.AuthenticationBasic,
    },
    CreateAuthorizationURL: func(input providers.AuthorizationInput) (*url.URL, error) {
        return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
            AuthorizationEndpoint: "https://identity.acme.example/oauth/authorize",
            Options: oauth2.ProviderOptions{
                ClientID: clientID,
            },
            RedirectURI:           input.RedirectURI,
            State:                 input.State,
            Scopes:                append([]string{"openid", "profile", "email"}, input.Scopes...),
            CodeVerifier:          input.CodeVerifier,
        })
    },
    ValidateAuthorizationCode: func(ctx context.Context, input providers.CodeInput) (*oauth2.Tokens, error) {
        request := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{
            Code:         input.Code,
            RedirectURI:  input.RedirectURI,
            CodeVerifier: input.CodeVerifier,
            Options: oauth2.ProviderOptions{
                ClientID:     clientID,
                ClientSecret: clientSecret,
            },
            Authentication: oauth2.AuthenticationBasic,
        })
        data, err := oauth2.DoForm(ctx, providerHTTPClient,
            "https://identity.acme.example/oauth/token", request)
        if err != nil {
            return nil, err
        }
        tokens := oauth2.NormalizeTokens(data, time.Now())
        return &tokens, nil
    },
    GetUserInfo: func(ctx context.Context, tokens oauth2.Tokens, _ *providers.AuthorizationUser) (*providers.UserInfoResult, error) {
        if tokens.AccessToken == "" {
            return nil, errors.New("acme user info: access token is empty")
        }
        request, err := http.NewRequestWithContext(ctx, http.MethodGet,
            "https://identity.acme.example/oauth/userinfo", nil)
        if err != nil {
            return nil, err
        }
        request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
        request.Header.Set("Accept", "application/json")

        response, err := providerHTTPClient.Do(request)
        if err != nil {
            return nil, err
        }
        defer response.Body.Close()
        if response.StatusCode < 200 || response.StatusCode >= 300 {
            return nil, fmt.Errorf("acme user info: unexpected status %d", response.StatusCode)
        }
        mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
        if err != nil || mediaType != "application/json" {
            return nil, fmt.Errorf("acme user info: expected application/json")
        }

        payload, err := io.ReadAll(io.LimitReader(response.Body, maxUserInfoBytes+1))
        if err != nil {
            return nil, err
        }
        if int64(len(payload)) > maxUserInfoBytes {
            return nil, errors.New("acme user info: response exceeds 1 MiB")
        }
        var data map[string]any
        if err := json.Unmarshal(payload, &data); err != nil {
            return nil, fmt.Errorf("acme user info: decode data: %w", err)
        }
        subject, _ := data["sub"].(string)
        if subject == "" {
            return nil, errors.New("acme user info: sub is required")
        }
        name, _ := data["name"].(string)
        picture, _ := data["picture"].(string)
        emailVerified, _ := data["email_verified"].(bool)
        var email *string
        if value, ok := data["email"].(string); ok && value != "" {
            email = &value
        }
        return &providers.UserInfoResult{
            User: oauth2.UserInfo{
                ID:            subject,
                Name:          name,
                Email:         email,
                Image:         picture,
                EmailVerified: emailVerified,
                Extra:         map[string]any{},
            },
            Data: data,
        }, nil
    },
})
if err != nil {
    return err
}
~~~

The example uses a fixed HTTPS endpoint, a finite timeout, a redirect-refusing client, status/content-type checks, a 1 MiB response ceiling, and a required subject. Adjust the claim schema and email-verification rule to the remote provider's documented contract.

`NewCustomProvider` derives `Metadata.SupportsRefresh` from the presence of `RefreshAccessToken`. It does not derive `Metadata.SupportsIDToken` from `VerifyIDToken`; set that metadata flag explicitly when the direct ID-token sign-in/link path should be available. The normal authorization-code callback still does not invoke the ID-token verifier automatically.

## Register it

~~~go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        custom.ID: custom,
    },
})
~~~

The callback becomes `https://auth.example.com/api/auth/callback/acme`. Provider IDs must be unique; plugin-factory registration also rejects collisions.

## Security contract

- Generate and validate cryptographically random state through the normal single-auth route lifecycle.
- Use PKCE for authorization-code flows whenever the remote provider supports it.
- Reject unexpected redirects, issuers, audiences, algorithms, content types, and oversized responses.
- Normalize a stable, provider-scoped subject into `UserInfo.ID`.
- Set `EmailVerified` only from a cryptographically trustworthy claim or verified provider API response.
- Return remote claims in `Data` and application-specific normalized values in `User.Extra` without copying secrets.

If the service is a standard configurable OAuth/OIDC provider, prefer the [Generic OAuth plugin](../plugins/generic-oauth.md), which supplies discovery and route behavior without writing callback code.
