---
title: "Quickstart"
description: "Run the first credential flow, then replace process-local storage with a durable SQLite deployment."
---

Run email and password authentication with the standard library.

This example intentionally uses the built-in memory adapter. It is complete enough to exercise the HTTP contract, but process restarts discard users and sessions. Switch to durable storage before deployment.

## Create the server

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
    secret := os.Getenv("SINGLE_AUTH_SECRET")
    if secret == "" {
        log.Fatal("SINGLE_AUTH_SECRET is required")
    }

    auth, err := singleauth.New(singleauth.Options{
        AppName:  "Example App",
        BaseURL:  "http://localhost:8080",
        BasePath: "/api/auth",
        Secret:   secret,
        EmailAndPassword: singleauth.EmailAndPasswordOptions{
            Enabled: true,
        },
        TrustedOrigins: []string{"http://localhost:3000"},
    })
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", auth)

    server := &http.Server{
        Addr:    ":8080",
        Handler: mux,
    }
    log.Fatal(server.ListenAndServe())
}
```

Generate a secret and start the program:

```bash
export SINGLE_AUTH_SECRET="$(openssl rand -base64 48)"
go run .
```

## Create a user

Use a cookie jar so the session cookie survives between requests:

```bash
curl --fail-with-body \
  --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --request POST \
  --data '{"name":"Ada Lovelace","email":"ada@example.com","password":"correct-horse-battery-staple"}' \
  http://localhost:8080/api/auth/sign-up/email
```

The successful response contains the public user and, because auto sign-in is
enabled by default, a session token:

```json
{
  "token": "<session-token>",
  "user": {
    "id": "<user-id>",
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "emailVerified": false
  }
}
```

The exact IDs and timestamps vary. The cookie jar receives the signed session
cookie; applications should authenticate subsequent browser requests with the
cookie instead of copying `token` into arbitrary client storage.

## Read the session

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  http://localhost:8080/api/auth/get-session
```

An absent, invalid, or expired session returns JSON `null` with status 200.
A valid session returns `{session,user}` and always uses no-cache response
headers. See [Sessions](../core/sessions.md) for refresh and cache behavior.

## Sign out

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  http://localhost:8080/api/auth/sign-out
```

Mutating cookie-authenticated requests are origin checked. Add every browser application origin to `TrustedOrigins`; do not disable CSRF or origin checks to make an incorrect deployment work.

Sign-out is idempotent. It deletes the stored session when present and expires
the session cookies. Reusing the old cookie jar with `GET /get-session` then
returns `null`.

## Move to durable SQLite storage

The memory adapter is useful only for the first request. A deployable service
needs a durable adapter and an explicit migration step. Add the pure-Go SQLite
driver:

```bash
go get modernc.org/sqlite
```

Replace the server with this complete startup and shutdown path:

```go
package main

import (
    "context"
    "database/sql"
    "errors"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    _ "modernc.org/sqlite"

    singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
    secret := os.Getenv("SINGLE_AUTH_SECRET")
    if len(secret) < 32 {
        log.Fatal("SINGLE_AUTH_SECRET must contain at least 32 characters")
    }

    database, err := sql.Open(
        "sqlite",
        "file:auth.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)",
    )
    if err != nil {
        log.Fatal(err)
    }
    defer database.Close()

    startup, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancelStartup()
    if err := database.PingContext(startup); err != nil {
        log.Fatal(err)
    }

    auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
        AppName:  "Example App",
        BaseURL:  "http://localhost:8080",
        BasePath: "/api/auth",
        Secret:   secret,
        EmailAndPassword: singleauth.EmailAndPasswordOptions{
            Enabled: true,
        },
        TrustedOrigins: []string{"http://localhost:3000"},
    }, database)
    if err != nil {
        log.Fatal(err)
    }
    if err := auth.RunMigrationsContext(startup); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", auth)

    server := &http.Server{
        Addr:              ":8080",
        Handler:           mux,
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       15 * time.Second,
        WriteTimeout:      30 * time.Second,
        IdleTimeout:       60 * time.Second,
    }

    shutdownSignal, stop := signal.NotifyContext(
        context.Background(),
        os.Interrupt,
        syscall.SIGTERM,
    )
    defer stop()

    serverErrors := make(chan error, 1)
    go func() {
        serverErrors <- server.ListenAndServe()
    }()

    select {
    case err := <-serverErrors:
        if !errors.Is(err, http.ErrServerClosed) {
            log.Fatal(err)
        }
    case <-shutdownSignal.Done():
        shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
        defer cancel()
        if err := server.Shutdown(shutdown); err != nil {
            log.Printf("graceful shutdown: %v", err)
        }
    }
}
```

`NewWithSQLiteDatabase` composes the complete core/plugin schema before it
constructs the adapter. `RunMigrationsContext` then performs additive schema
setup; construction alone never changes the database. Run migrations as a
controlled startup or deployment step before accepting requests.

To prove persistence, create a user, stop the process, start it again with the
same `auth.db` and secret, then sign in with `POST /sign-in/email`. An existing
browser session also remains valid until its stored expiry. Changing the secret
invalidates signed session cookies even though the database row remains.

## Inspect failures

Normal endpoint errors use a stable JSON body:

```json
{
  "code": "INVALID_EMAIL_OR_PASSWORD",
  "message": "Invalid email or password"
}
```

Missing fields, malformed JSON, unsupported methods, disabled endpoints, and
untrusted origins are different failures. Preserve both the HTTP status and
`code` in logs and tests; do not branch only on the human-readable message.

Useful first checks:

```bash
curl --fail-with-body http://localhost:8080/api/auth/ok
curl --include --cookie cookies.txt http://localhost:8080/api/auth/get-session
```

`/ok` verifies the mount and dispatcher, not the database or an external OAuth
provider. For the complete wire contract, read [HTTP routes](../reference/http-routes.md)
and [Errors and logging](../core/errors-and-logging.md).

## Next steps

- [Use SQLite](../storage/sqlite.md)
- [Mount Fiber](../transports/fiber.md)
- [Configure social sign-in](../social-providers/index.md)
- [Deploy behind a proxy](../transports/net-http.md#proxy-headers)
- [Review production security](./production-checklist.md)
