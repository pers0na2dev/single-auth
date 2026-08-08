---
title: "Storage testing"
---

Run unit contracts and real-service Testcontainers tests for primary and secondary adapters.

Storage correctness depends on real driver behavior: locking, transaction rollback, affected-row counts, scalar conversion, indexes, foreign keys, and context cancellation. Use unit tests for deterministic logic and Testcontainers for every external backend.

## Repository test layout

The root Go module contains storage unit and contract tests:

```sh
go test ./storage/... -count=1
```

The `e2e` directory is a separate Go module. This keeps Testcontainers and concrete database drivers out of the production module's dependency graph.

```sh
cd e2e
go test ./sqlite ./redis ./postgres ./mysql ./mongodb ./mssql -count=1
```

The external-service matrix is:

| Package | Service | Main contract focus |
| --- | --- | --- |
| `e2e/redis` | Redis 7.4.2 | TTL, scan, clear, atomic get-delete, fixed-window increment |
| `e2e/postgres` | PostgreSQL 17.4 | Complete adapter, transactions, schema reconciliation |
| `e2e/mysql` | MySQL 8.4.4 | Complete adapter, guarded returning mutations, schema reconciliation |
| `e2e/mongodb` | MongoDB 7.0.16 replica set | Complete adapter, BSON IDs, transactions, indexes |
| `e2e/mssql` | SQL Server 2022 | Complete adapter, `OUTPUT`, transactions, schema reconciliation |
| `e2e/sqlite` | modernc SQLite | Relational migration and adapter setup without Docker |

Container images in the repository are pinned, including their digest. Review a version or digest change as an intentional storage-matrix change.

## Required Docker mode

Local tests can skip an external profile when Docker is unavailable. Set `SINGLE_AUTH_E2E_REQUIRED=1` in CI so container startup failure fails the job:

```sh
cd e2e
SINGLE_AUTH_E2E_REQUIRED=1 \
  go test ./redis ./postgres ./mysql ./mongodb ./mssql \
  -count=1 -timeout=15m -v
```

Run each backend as a separate CI matrix job when possible. That keeps logs focused and prevents one slow image from hiding failures in other services.

## Reusable adapter contract

Package `github.com/pers0na2dev/single-auth/storage/adaptertest` exposes the same behavioral contract for built-in and custom primary adapters:

```go
type Factory func(
    *testing.T,
    storage.Schema,
) (storage.Adapter, error)

func Run(t *testing.T, factory Factory)
```

The factory must return a fresh adapter configured with the supplied schema. Do not reuse rows between contract subtests.

The suite verifies:

- create, read, selection, and copy isolation;
- every predicate operator and comparison mode;
- null versus missing semantics;
- sort, limit, offset, and count;
- guarded update and delete behavior;
- update-many and delete-many counts;
- aliases and plural models;
- one-to-one and one-to-many joins;
- unique constraints;
- atomic single-use consumption under contention;
- positive and negative atomic increments with guards;
- transactions, rollback, and cancellation;
- deterministic public ID and scalar behavior.

## Complete PostgreSQL Testcontainers example

This example starts PostgreSQL, creates a fresh namespace for every adapter contract subtest, runs native schema setup, and executes the reusable suite:

```go
package postgres_test

import (
    "database/sql"
    "fmt"
    "net"
    "net/url"
    "sync/atomic"
    "testing"
    "time"

    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/wait"

    "github.com/pers0na2dev/single-auth/storage"
    "github.com/pers0na2dev/single-auth/storage/adaptertest"
    postgresstore "github.com/pers0na2dev/single-auth/storage/postgres"
)

const postgresImage = "postgres:17.4-alpine@sha256:7062a2109c4b51f3c792c7ea01e83ed12ef9a980886e3b3d380a7d2e5f6ce3f5"

func TestPostgreSQLAdapter(t *testing.T) {
    ctx := t.Context()

    container, err := testcontainers.Run(
        ctx,
        postgresImage,
        testcontainers.WithEnv(map[string]string{
            "POSTGRES_DB":       "single_auth",
            "POSTGRES_USER":     "single_auth",
            "POSTGRES_PASSWORD": "single_auth_e2e",
        }),
        testcontainers.WithExposedPorts("5432/tcp"),
        testcontainers.WithWaitStrategy(
            wait.ForLog("database system is ready to accept connections").
                WithOccurrence(2).
                WithStartupTimeout(60*time.Second),
        ),
    )
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() {
        if err := testcontainers.TerminateContainer(container); err != nil {
            t.Errorf("terminate PostgreSQL container: %v", err)
        }
    })

    host, err := container.Host(ctx)
    if err != nil {
        t.Fatal(err)
    }
    port, err := container.MappedPort(ctx, "5432/tcp")
    if err != nil {
        t.Fatal(err)
    }

    connectionURL := &url.URL{
        Scheme: "postgres",
        User:   url.UserPassword("single_auth", "single_auth_e2e"),
        Host:   net.JoinHostPort(host, port.Port()),
        Path:   "/single_auth",
    }
    query := connectionURL.Query()
    query.Set("sslmode", "disable")
    connectionURL.RawQuery = query.Encode()

    database, err := sql.Open("pgx", connectionURL.String())
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() {
        if err := database.Close(); err != nil {
            t.Errorf("close PostgreSQL database: %v", err)
        }
    })
    if err := database.PingContext(ctx); err != nil {
        t.Fatal(err)
    }

    var sequence atomic.Uint64
    adaptertest.Run(t, func(
        t *testing.T,
        schema storage.Schema,
    ) (storage.Adapter, error) {
        namespace := fmt.Sprintf("contract_%d", sequence.Add(1))
        if _, err := database.ExecContext(
            t.Context(),
            `CREATE SCHEMA "`+namespace+`"`,
        ); err != nil {
            return nil, err
        }

        adapter, err := postgresstore.New(
            database,
            postgresstore.Options{
                Schema:         schema,
                DatabaseSchema: namespace,
                IDType:         postgresstore.TextID,
            },
        )
        if err != nil {
            return nil, err
        }
        if err := adapter.EnsureSchema(t.Context()); err != nil {
            return nil, err
        }
        return adapter, nil
    })
}
```

## Testcontainers patterns by backend

### PostgreSQL

- Start a pinned PostgreSQL image.
- Wait for the ready log twice because PostgreSQL performs an initial restart during image setup.
- Create a fresh schema per adapter contract subtest.
- Configure `DatabaseSchema` to that namespace.
- Run `EnsureSchema` before returning the adapter.

### MySQL

- Start a pinned MySQL image with a root password and initial database.
- Wait for the server-ready log.
- Create a fresh database per contract subtest.
- Open a new `*sql.DB` configured with `ParseTime`, UTC, and native passwords.
- Run `EnsureSchema`; retain the handle until the subtest ends.

### SQL Server

- Use the Testcontainers SQL Server module.
- Accept the EULA and configure a strong password.
- Connect to `master`, create one isolated database per subtest, then open a database-specific connection.
- Disable encryption only for an isolated local container, never as production guidance.
- Run `EnsureSchema` before the adapter contract.

### MongoDB

- Use the Testcontainers MongoDB module with `WithReplicaSet`.
- Wait for the client to ping successfully.
- Use a fresh database name per contract subtest.
- Run `EnsureSchema` to create collections and indexes.
- Keep transactions enabled so the contract exercises driver sessions.

### Redis

- Start a pinned Redis image and wait for the ready log.
- Give each test an isolated prefix.
- Adapt the chosen client to `redisstore.Commander`.
- Assert TTL is positive and bounded after `Set`.
- Race many callers through `GetAndDelete` and require exactly one non-empty result.
- Race increments and verify the counter is complete without extending the original TTL.
- Test `ListKeys` and `Clear` only within the isolated prefix.

## Migration contract

Storage tests should exercise at least four states:

1. an empty database creates the complete schema;
2. a partial database receives missing fields, indexes, and foreign keys;
3. a second run produces no work;
4. an injected DDL failure follows the backend's documented rollback policy.

For MySQL, verify that retrying after partial DDL re-inspects and completes only the missing suffix. For SQLite, explicitly test the existing-column foreign-key limitation. For PostgreSQL, test both the current namespace and an explicit `DatabaseSchema`.

## Transaction tests

Every transactional adapter should prove:

- successful callbacks commit;
- callback errors roll back;
- context cancellation before commit rolls back;
- nested `RunWithTransaction` calls reuse the active transaction;
- operations inside the callback use the supplied transaction adapter;
- concurrent unique conflicts do not silently commit duplicates.

MongoDB tests must use a replica set. A standalone container cannot validate the production transaction contract.

## Race and static checks

Run storage tests under the race detector:

```sh
go test -race ./storage/... -count=1
```

Run static checks:

```sh
go vet ./storage/...
```

External-service tests can also run with `-race`, but allow a longer timeout and sufficient container resources.

## Failure diagnostics

On container-backed failures:

- attach service logs to the test output;
- do not print credentials or full production-style connection strings;
- include the backend, image, operation, and generated schema namespace;
- retain the original wrapped driver error;
- terminate containers in `t.Cleanup`, including when setup fails after startup.

Do not make container startup errors successful skips in required CI mode.
