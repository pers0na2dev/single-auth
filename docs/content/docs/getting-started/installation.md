---
title: "Installation"
description: "Install the pre-release Go module, pin an exact revision, and verify the server and documentation toolchains."
---

Add the current local Go module safely and verify the toolchain.

## Requirements

- Go `1.25` or newer, matching the repository's `go.mod`.
- A server supported by `net/http`, `fasthttp`, or Fiber v3.
- A random authentication secret of at least 32 characters for development and substantially higher entropy for production.
- The Go toolchain is sufficient for the library, tests, examples, documentation generators, and documentation checks.

## Choose and pin a revision

The repository declares the canonical public module path:

```go
module github.com/pers0na2dev/single-auth
```

The project does not have a tagged release yet. For an evaluation, resolve the
current `main` branch once:

```bash
go get github.com/pers0na2dev/single-auth@main
go list -m -json github.com/pers0na2dev/single-auth
```

The second command prints the resolved pseudo-version and commit. Commit the
resulting `go.mod` and `go.sum`; do not leave an automated deployment tracking
`main`. To reproduce a previously evaluated build, request its exact commit:

```bash
go get github.com/pers0na2dev/single-auth@<full-commit-sha>
```

Until the first release, every update is a pre-1.0 source review. Read the
[project status](./project-status.md), compare the selected commit, and rerun
your integration suite before updating the pinned version.

## Use a neighboring checkout

For a neighboring development checkout, use the same canonical requirement
with a local replacement:

```bash
go mod edit -require=github.com/pers0na2dev/single-auth@v0.0.0
go mod edit -replace=github.com/pers0na2dev/single-auth=../single-auth
go mod tidy
```

Imports always use the canonical package paths:

```go
import (
    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/storage/sqlite"
    nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)
```

## Verify the checkout

From the library repository:

```bash
go test ./...
go vet ./...
```

External-database E2E tests live in the nested `e2e` module and require Docker:

```bash
cd e2e
go test ./...
```

The ordinary unit suite does not execute the preserved `better-auth-main` source tree and does not require a JavaScript runtime.
