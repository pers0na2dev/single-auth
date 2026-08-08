---
title: "Direct API"
---

Invoke authentication endpoints from trusted Go code without HTTP serialization.

`auth.API()` returns a typed façade over the same endpoint registry used by HTTP. It is useful for server-rendered applications, background workflows, administrative services, and tests.

```go
package accountbootstrap

import (
    "context"

    singleauth "github.com/pers0na2dev/single-auth"
)

func CreateOwner(ctx context.Context, auth *singleauth.Auth) (string, error) {
    result, err := auth.API().SignUpEmail(ctx, singleauth.SignUpEmailInput{
        Name:     "Application Owner",
        Email:    "owner@example.com",
        Password: "correct-horse-battery-staple",
    })
    if err != nil {
        return "", err
    }
    return result.User.ID, nil
}
```

## What still runs

- endpoint middleware;
- global before and after hooks;
- the endpoint handler;
- database and verification logic;
- plugin endpoint logic installed during runtime construction;
- response serialization into typed result values and `contract.Headers`.

## What does not run

Direct calls bypass the outer HTTP request path. They do not execute disabled-path routing, HTTP rate limiting, security or other path middleware, plugin `OnRequest`/`OnResponse`, transport conversion, or request/response observers that belong to an HTTP adapter. Do not expose an unbounded direct call behind an HTTP endpoint without independently applying the required host, origin/CSRF, authorization, abuse, and body-size controls.

## Sessions and cookies

Session-issuing results expose response headers. If later direct calls should act as that browser session, copy the emitted `Set-Cookie` values into a `Cookie` request header yourself. Direct calls do not maintain a cookie jar.

```go
cookieHeader := cookies.ApplySetCookies(
    "",
    result.Headers.Values("Set-Cookie"),
)
headers := contract.NewHeaders(contract.HeaderField{
    Name:  "Cookie",
    Value: cookieHeader,
})

session, err := auth.API().GetSession(ctx, singleauth.GetSessionInput{
    Headers: headers,
})
```

Required imports for the session snippet:

```go
import (
    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/contract"
    "github.com/pers0na2dev/single-auth/security/cookies"
)
```

## Dynamic base URLs

Typed direct API inputs do not carry a request host or scheme. When `DynamicBaseURL` is enabled, configure `DynamicBaseURL.Fallback` for direct calls that need absolute URLs. The lower-level `DirectAPI.Call` escape hatch can supply `Scheme`, `Host`, headers, body, query, parameters, and per-call values explicitly.

## Generic endpoint call

Use `Call` for a plugin or custom endpoint without a dedicated typed method:

```go
result, err := auth.API().Call(ctx, "pluginEndpointName", singleauth.DirectCallInput{
    Method: "POST",
    Scheme: "https",
    Host:   "app.example.com",
    Body: map[string]any{
        "value": "example",
    },
})
if err != nil {
    return err
}
_ = result.Value
```

The endpoint name is the registry's direct API name, not its HTTP path.
