# Generic OAuth

`genericoauth` ports single-auth 1.6.26's `generic-oauth` server plugin to
single-auth. It implements authorization-code sign-in, PKCE, discovery,
database or encrypted-cookie state, account linking, token refresh, RFC 9207
issuer validation, custom token/user-info/profile callbacks, static or
request-scoped endpoint parameters, and all ten upstream provider helpers.

```go
auth := singleauth.MustNew(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
    PluginFactories: []singleauth.PluginFactory{
        genericoauth.NewFactory(genericoauth.Options{Config: []genericoauth.Config{
            {
                ProviderID:      "company-idp",
                DiscoveryURL:   "https://idp.example.com/.well-known/openid-configuration",
                ClientID:       os.Getenv("IDP_CLIENT_ID"),
                ClientSecret:   os.Getenv("IDP_CLIENT_SECRET"),
                Scopes:         []string{"openid", "profile", "email"},
                PKCE:           true,
                Issuer:         "https://idp.example.com",
                RequireIssuerValidation: true,
            },
        }}),
    },
})
```

The factory integrates with the root user, session, account-cookie,
token-encryption, verification, and refresh lifecycle. The same dispatcher is
available through direct API calls, `net/http`, native `fasthttp`, and Fiber v3.

Provider helpers are `Auth0`, `Okta`, `Keycloak`, `MicrosoftEntraID`, `Slack`,
`Gumroad`, `HubSpot`, `Line`, `Patreon`, and `Yandex`.

For database-backed OAuth state, the optional root setting below hashes state
identifiers at rest while retaining single-auth's legacy plain-key read and
consume fallback:

```go
Verification: singleauth.VerificationOptions{
    StoreIdentifier: singleauth.VerificationIdentifierStorage{
        Strategy: singleauth.VerificationIdentifierHashed,
    },
},
```

Frozen compatibility provenance lives in
`testdata/reference-1.6.26-oracle.json` and
`testdata/reference-1.6.26-stateless-account-oracle.json`. Both files are
reviewed manually against the read-only upstream snapshot and consumed as data
by native Go tests.

```sh
go test ./plugins/genericoauth
go test -race ./plugins/genericoauth
```
