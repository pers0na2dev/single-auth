---
title: "net/http"
---

Mount single-auth on the Go standard library or a compatible router.

`*singleauth.Auth` implements `http.Handler`, so the root runtime is enough for the common case.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
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

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", auth)
    mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) {
        writer.WriteHeader(http.StatusNoContent)
    })

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Protect application routes

Mounting `single-auth` serves the authentication endpoints. Protect your own
handlers by resolving the incoming session cookie with the same `Auth` runtime.
`GetSession` applies the configured
[session and cookie-cache policy](../core/sessions.md); an unauthenticated
request returns a nil session without an error.

```go
package main

import (
    "context"
    "net/http"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/contract"
)

type sessionKey struct{}

func requireSession(auth *singleauth.Auth, next http.Handler) http.Handler {
    api := auth.API()

    return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
        headers := contract.Headers{}
        for name, values := range request.Header {
            for _, value := range values {
                headers.Add(name, value)
            }
        }

        current, err := api.GetSession(request.Context(), singleauth.GetSessionInput{
            Headers: headers,
        })
        if err != nil {
            // Report the underlying storage/runtime error through the
            // application's error policy. It is not an authentication miss.
            http.Error(
                writer,
                http.StatusText(http.StatusInternalServerError),
                http.StatusInternalServerError,
            )
            return
        }
        if current == nil {
            http.Error(
                writer,
                http.StatusText(http.StatusUnauthorized),
                http.StatusUnauthorized,
            )
            return
        }

        // Forward each Set-Cookie line separately so rolling refresh and the
        // cookie cache keep working.
        for _, cookie := range current.Headers.Values("Set-Cookie") {
            writer.Header().Add("Set-Cookie", cookie)
        }

        ctx := context.WithValue(request.Context(), sessionKey{}, current)
        next.ServeHTTP(writer, request.WithContext(ctx))
    })
}

func currentSession(request *http.Request) *singleauth.SessionResult {
    current, _ := request.Context().Value(sessionKey{}).(*singleauth.SessionResult)
    return current
}
```

Wrap individual handlers or a complete subtree:

```go
private := http.NewServeMux()
private.HandleFunc("GET /api/private/me", func(writer http.ResponseWriter, request *http.Request) {
    current := currentSession(request)
    writer.Header().Set("X-User-ID", current.User.ID)
    writer.WriteHeader(http.StatusNoContent)
})

mux.Handle("/api/private/", requireSession(auth, private))
```

The complete version with JSON responses is compile-checked in
[`docs/examples/servers`](https://github.com/pers0na2dev/single-auth/tree/main/docs/examples/servers).

When a browser frontend uses a different origin, send requests with credentials
enabled and configure CORS with an explicit allowed origin and credential
support. Otherwise `net/http` will not receive the session cookie.

This middleware establishes identity only. Add application authorization and,
for unsafe cookie-authenticated requests, an origin or CSRF policy. The
`single-auth` security middleware mounted at `/api/auth` does not wrap your
application handlers.

Successful lookups expose refresh cookies through `SessionResult.Headers`,
which the example forwards. On a nil lookup, the typed API does not expose
response headers, so this wrapper cannot forward immediate cookie-expiration
headers for an already invalid cookie. Authentication still fails closed.
The middleware must append refresh cookies before the downstream handler writes
its headers; downstream code should also append its own `Set-Cookie` values
instead of replacing the existing header.

## Dedicated adapter

Use `transport/nethttp` when you need body-size enforcement or error observation:

```go
handler := nethttptransport.NewHandler(
    auth.Dispatcher(),
    nethttptransport.WithMaxBodyBytes(1<<20),
    nethttptransport.WithErrorHandler(func(ctx context.Context, err error) {
        slog.ErrorContext(ctx, "authentication request failed", "error", err)
    }),
)

mux.Handle("/api/auth/", handler)
```

Required imports for the adapter snippet:

```go
import (
    "context"
    "log/slog"

    nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)
```

### `WithMaxBodyBytes`

The adapter wraps the body with `http.MaxBytesReader`. A body larger than the configured positive limit receives status `413` and code `PAYLOAD_TOO_LARGE`. A non-positive value delegates body limits to the hosting server.

### `WithErrorHandler`

The callback observes body-read, dispatch, and response-write errors. It must be concurrency safe. It cannot modify the already-selected response.

## Proxy headers

The adapter derives the request scheme from `request.URL.Scheme`, then TLS, then HTTP. It forwards `request.Host`, `RemoteAddr`, and all header values. Whether `X-Forwarded-*` values are trusted is controlled by auth configuration, not by the adapter.

Set `Advanced.TrustedProxyHeaders` and `Advanced.IPAddress.TrustedProxies` only when requests actually arrive through controlled proxies. Never trust forwarded headers from arbitrary clients.
