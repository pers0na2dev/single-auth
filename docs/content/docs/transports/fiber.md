---
title: "Fiber v3"
---

Mount the direct fasthttp bridge as native Fiber middleware.

The Fiber adapter wraps the direct fasthttp adapter; it never converts the request through `net/http`.

```go
package main

import (
    "log"
    "os"

    fiberframework "github.com/gofiber/fiber/v3"

    singleauth "github.com/pers0na2dev/single-auth"
    fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func main() {
    auth := singleauth.MustNew(singleauth.Options{
        BaseURL: "https://app.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{
            Enabled: true,
        },
        TrustedOrigins: []string{"https://app.example.com"},
    })

    app := fiberframework.New()
    app.Use("/api/auth", fibertransport.NewHandler(auth.Dispatcher()))

    log.Fatal(app.Listen(":8080"))
}
```

Fiber's user context is passed to the direct fasthttp adapter as the authoritative Go context. The original request URI remains available to the dispatcher, so mounting by prefix does not change auth route matching.

## Protect application routes

The Fiber adapter serves the authentication endpoints. Protect your own
application routes by resolving the incoming session cookie with the same
`Auth` runtime. Do not treat the presence of a cookie as proof of
authentication: `GetSession` applies the configured
[session and cookie-cache policy](../core/sessions.md) and resolves the logical
session and user. An unauthenticated request returns a nil session without an
error.

```go
package main

import (
    fiberframework "github.com/gofiber/fiber/v3"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/contract"
)

type fiberSessionKey struct{}

func requireSession(auth *singleauth.Auth) fiberframework.Handler {
    api := auth.API()

    return func(ctx fiberframework.Ctx) error {
        headers := contract.Headers{}
        ctx.Request().Header.VisitAllInOrder(func(name, value []byte) {
            headers.Add(string(name), string(value))
        })
        if headers.Len() == 0 {
            ctx.Request().Header.VisitAll(func(name, value []byte) {
                headers.Add(string(name), string(value))
            })
        }

        current, err := api.GetSession(ctx.Context(), singleauth.GetSessionInput{
            Headers: headers,
        })
        if err != nil {
            // Report or log the underlying error through the application's
            // error policy. A storage failure is not an authentication miss.
            return fiberframework.NewError(
                fiberframework.StatusInternalServerError,
                "failed to resolve session",
            )
        }
        if current == nil {
            return ctx.Status(fiberframework.StatusUnauthorized).JSON(fiberframework.Map{
                "code":    "UNAUTHORIZED",
                "message": "Authentication required",
            })
        }

        fiberframework.Locals(ctx, fiberSessionKey{}, current)
        nextErr := ctx.Next()

        // Append after the application handler so a response reset cannot
        // erase refresh cookies. Set-Cookie values cannot be comma-joined.
        for _, cookie := range current.Headers.Values("Set-Cookie") {
            ctx.Response().Header.Add("Set-Cookie", cookie)
        }
        return nextErr
    }
}

func currentSession(ctx fiberframework.Ctx) *singleauth.SessionResult {
    return fiberframework.Locals[*singleauth.SessionResult](ctx, fiberSessionKey{})
}
```

Mount the auth handler separately, then apply the middleware only to the routes
that require a user:

```go
app.Use("/api/auth", fibertransport.NewHandler(auth.Dispatcher()))

protected := app.Group("/api/private", requireSession(auth))
protected.Get("/me", func(ctx fiberframework.Ctx) error {
    current := currentSession(ctx)

    return ctx.JSON(fiberframework.Map{
        "id":    current.User.ID,
        "email": current.User.Email,
    })
})
```

The complete version is compile-checked in
[`docs/examples/servers`](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/servers).

When a browser frontend uses a different origin, send requests with credentials
enabled and configure CORS with an explicit allowed origin and credential
support. Otherwise Fiber will not receive the session cookie.

This middleware establishes identity only. Add application authorization and,
for unsafe cookie-authenticated requests, an origin or CSRF policy. The
`single-auth` security middleware mounted at `/api/auth` does not wrap your
application routes.

Successful lookups expose refresh cookies through `SessionResult.Headers`,
which the example forwards. On a nil lookup, the typed API does not expose
response headers, so this wrapper cannot forward immediate cookie-expiration
headers for an already invalid cookie. Authentication still fails closed.

## Adapter options

```go
handler := fibertransport.NewHandler(
    auth.Dispatcher(),
    fibertransport.WithMaxBodyBytes(1<<20),
    fibertransport.WithErrorHandler(func(ctx context.Context, err error) {
        slog.ErrorContext(ctx, "authentication request failed", "error", err)
    }),
)

app.Use("/api/auth", handler)
```

`WithMaxBodyBytes` returns `413 PAYLOAD_TOO_LARGE` for an oversized buffered body. A non-positive value leaves enforcement to Fiber's `BodyLimit` configuration.

`WithErrorHandler` observes errors after the response is selected and must be safe for concurrent requests.

## Middleware ordering

Place middleware that establishes request IDs, tracing, proxy metadata, or the Fiber user context before the auth handler. Place fallback routing after it. Do not rewrite or strip the `/api/auth` path before the request reaches `single-auth`.
