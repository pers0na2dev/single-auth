---
title: "Compile-checked examples"
description: "Runnable Go examples for transports, direct calls, SQLite, social providers, enterprise features, and custom plugins."
---

Runnable Go examples for transports, the direct API, SQLite, social sign-in, and plugin factories.

The repository contains small Go packages that compile and execute during documentation validation. Each linked package uses canonical public imports and production constructors.

| Example | What it verifies | Source |
| --- | --- | --- |
| HTTP servers | `net/http`, direct `fasthttp`, and Fiber v3 handlers plus protected-route session middleware | [docs/examples/servers](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/servers) |
| Direct API | `SignUpEmail`, `Set-Cookie` propagation with `cookies.ApplySetCookies`, and `GetSession` without an HTTP transport | [docs/examples/directapi](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/directapi) |
| SQLite | Raw `database/sql` initialization, complete schema composition, and additive migrations | [docs/examples/sqlite](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/sqlite) |
| Social sign-in | Google provider construction and root registration | [docs/examples/social](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/social) |
| Plugins | Organization, API keys, two-factor authentication, and Passkey factories in one runtime | [docs/examples/plugins](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/plugins) |
| Custom plugin | Two-phase `PluginFactory`, authoritative root session resolution, public serialization, and a real cookie-authenticated endpoint | [docs/examples/customplugin](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/customplugin) |
| Enterprise protocols | Detailed API-key policy, static OIDC SSO, and JWT-before-OAuth-Provider ordering | [docs/examples/enterprise](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/enterprise) |

Run every example check from the repository root:

```bash
go test ./docs/examples/...
```

## Transport constructors

```go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  secret,
    EmailAndPassword: singleauth.EmailAndPasswordOptions{
        Enabled: true,
    },
    TrustedOrigins: []string{"https://app.example.com"},
})
if err != nil {
    return err
}

standardHandler := nethttptransport.NewHandler(
    auth.Dispatcher(),
    nethttptransport.WithMaxBodyBytes(1<<20),
)

fastHandler := fasthttptransport.NewHandler(
    auth.Dispatcher(),
    fasthttptransport.WithMaxBodyBytes(1<<20),
)

fiberApp := fiber.New()
fiberApp.Use("/api/auth", fibertransport.NewHandler(
    auth.Dispatcher(),
    fibertransport.WithMaxBodyBytes(1<<20),
))
```

Use one adapter for each incoming request. The adapters share the immutable dispatcher but a request must not pass through more than one of them.

## Full SQLite initialization

```go
database, err := sql.Open("sqlite", "file:auth.db")
if err != nil {
    return err
}

auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  secret,
    PluginFactories: []singleauth.PluginFactory{
        organization.NewFactory(organization.Options{}),
    },
}, database)
if err != nil {
    return err
}
if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

`NewWithSQLiteDatabase` composes core, rate-limit, additional schema, and every plugin-factory schema before creating the adapter. Explicitly constructed adapters cannot be retroactively reconfigured; merge their complete schema before construction.

## Social provider

```go
google, err := providers.Google(providers.Options{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        google.ID: google,
    },
})
```

Register `https://auth.example.com/api/auth/callback/google` in the Google application. See [Google](../social-providers/google.md) for scopes, ID-token verification, PKCE, hosted-domain policy, and direct provider methods.

## Plugin factories

```go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  secret,
    PluginFactories: []singleauth.PluginFactory{
        organization.NewFactory(organization.Options{}),
        apikey.NewFactory(apikey.Options{}),
        twofactor.NewFactory(twofactor.Options{}),
        passkey.NewFactory(passkey.Options{
            RPID:   "example.com",
            RPName: "Example",
            Origin: "https://app.example.com",
        }),
    },
})
```

Factories are evaluated in order, contribute schema before adapter initialization, and bind runtime services after the auth core exists. Use the order documented for dependencies such as Organization before organization-aware API keys/SCIM and JWT before OAuth Provider.

To implement your own factory with endpoints, schema, errors, hooks, and the
required security/test matrix, follow [Write a server plugin](../guides/write-a-server-plugin.md).
