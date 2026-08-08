---
title: "fasthttp"
---

Serve authentication directly through valyala/fasthttp without net/http conversion.

```go
package main

import (
    "log"
    "os"

    fasthttpserver "github.com/valyala/fasthttp"

    singleauth "github.com/pers0na2dev/single-auth"
    fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
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

    handler := fasthttptransport.NewHandler(auth.Dispatcher())
    log.Fatal(fasthttpserver.ListenAndServe(":8080", handler))
}
```

The adapter reads `RequestCtx.PostBody`, the original escaped path, the raw query, URI scheme/host, peer address, and headers in wire order when fasthttp exposes it. Responses are written directly to `fasthttp.Response`.

## Protect application routes

The auth adapter serves the authentication endpoints. Protect your own
handlers by resolving the incoming session cookie with the same `Auth` runtime.
`GetSession` applies the configured
[session and cookie-cache policy](../core/sessions.md); an unauthenticated
request returns a nil session without an error.

```go
package main

import (
    fasthttpserver "github.com/valyala/fasthttp"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/contract"
)

type sessionKey struct{}

func requireSession(
    auth *singleauth.Auth,
    next fasthttpserver.RequestHandler,
) fasthttpserver.RequestHandler {
    api := auth.API()

    return func(request *fasthttpserver.RequestCtx) {
        headers := contract.Headers{}
        request.Request.Header.VisitAllInOrder(func(name, value []byte) {
            headers.Add(string(name), string(value))
        })
        if headers.Len() == 0 {
            request.Request.Header.VisitAll(func(name, value []byte) {
                headers.Add(string(name), string(value))
            })
        }

        current, err := api.GetSession(request, singleauth.GetSessionInput{
            Headers: headers,
        })
        if err != nil {
            // Report the underlying storage/runtime error through the
            // application's error policy. It is not an authentication miss.
            request.Error(
                fasthttpserver.StatusMessage(fasthttpserver.StatusInternalServerError),
                fasthttpserver.StatusInternalServerError,
            )
            return
        }
        if current == nil {
            request.Error(
                fasthttpserver.StatusMessage(fasthttpserver.StatusUnauthorized),
                fasthttpserver.StatusUnauthorized,
            )
            return
        }

        request.SetUserValue(sessionKey{}, current)
        next(request)

        // Append after the application handler so a response reset cannot
        // erase refresh cookies. Set-Cookie values cannot be comma-joined.
        for _, cookie := range current.Headers.Values("Set-Cookie") {
            request.Response.Header.Add("Set-Cookie", cookie)
        }
    }
}

func currentSession(request *fasthttpserver.RequestCtx) *singleauth.SessionResult {
    current, _ := request.UserValue(sessionKey{}).(*singleauth.SessionResult)
    return current
}
```

Wrap the application handler, then route requests to the auth or protected
handler without rewriting their paths:

```go
authHandler := fasthttptransport.NewHandler(auth.Dispatcher())
privateHandler := requireSession(auth, func(request *fasthttpserver.RequestCtx) {
    current := currentSession(request)
    request.Response.Header.Set("X-User-ID", current.User.ID)
    request.SetStatusCode(fasthttpserver.StatusNoContent)
})

applicationHandler := func(request *fasthttpserver.RequestCtx) {
    path := request.Path()
    switch {
    case bytes.Equal(path, []byte("/api/auth")),
        bytes.HasPrefix(path, []byte("/api/auth/")):
        authHandler(request)
    case request.IsGet() && bytes.Equal(path, []byte("/api/private/me")):
        privateHandler(request)
    default:
        request.SetStatusCode(fasthttpserver.StatusNotFound)
    }
}
```

The routing snippet also needs `bytes` and the existing `fasthttptransport`
import. The complete version with JSON responses is compile-checked in
[`docs/examples/servers`](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/servers).

Values stored with `SetUserValue` are request-scoped. Read the session during
the handler and do not retain `RequestCtx` or its values after the request
returns.

When a browser frontend uses a different origin, send requests with credentials
enabled and configure CORS with an explicit allowed origin and credential
support. Otherwise fasthttp will not receive the session cookie.

This middleware establishes identity only. Add application authorization and,
for unsafe cookie-authenticated requests, an origin or CSRF policy. The
`single-auth` security middleware mounted at `/api/auth` does not wrap your
application handlers.

Successful lookups expose refresh cookies through `SessionResult.Headers`,
which the example forwards. On a nil lookup, the typed API does not expose
response headers, so this wrapper cannot forward immediate cookie-expiration
headers for an already invalid cookie. Authentication still fails closed.

## Options

```go
adapter := fasthttptransport.New(
    auth.Dispatcher(),
    fasthttptransport.WithMaxBodyBytes(1<<20),
    fasthttptransport.WithContextProvider(func(request *fasthttp.RequestCtx) context.Context {
        return serverContext
    }),
    fasthttptransport.WithErrorHandler(func(ctx context.Context, err error) {
        slog.ErrorContext(ctx, "authentication request failed", "error", err)
    }),
)
```

`WithMaxBodyBytes` checks the already-buffered body and returns `413 PAYLOAD_TOO_LARGE` when exceeded. A non-positive value leaves enforcement to `fasthttp.Server.MaxRequestBodySize`.

`WithContextProvider` should return a stable context owned by the host. It is useful when shutdown cancellation or request deadlines must outlive mutable fasthttp internals. If omitted, the request context supplied by fasthttp is used.

`WithErrorHandler` is a concurrency-safe observer and cannot replace the response.

## Routing with a larger application

Route only the configured auth base path to the adapter. Preserve the complete original path because the dispatcher matches endpoints below `Options.BasePath`.

```go
func applicationHandler(ctx *fasthttp.RequestCtx) {
    if bytes.HasPrefix(ctx.Path(), []byte("/api/auth/")) {
        authHandler(ctx)
        return
    }
    ctx.SetStatusCode(fasthttp.StatusNotFound)
}
```
