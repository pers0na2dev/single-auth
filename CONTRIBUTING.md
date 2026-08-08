# Contributing to single-auth

Thank you for helping build `single-auth`. The project is a work-in-progress
native Go port of the applicable Better Auth 1.6.26 server behavior. Changes
should preserve Go-native design rather than reproduce JavaScript-specific
implementation details.

## Before opening a change

For a bug or feature, open an issue first when the behavior, compatibility
target, public API, or security impact is not obvious. Search existing issues
and the capability map before proposing a duplicate implementation.

Read these project contracts:

- [architecture](docs/project/architecture.md) for package ownership and dependencies;
- [`AGENTS.md`](AGENTS.md) for mandatory port constraints;
- [`conformance/capability-map.json`](conformance/capability-map.json) for the
  machine-readable implementation status;
- [remaining work](docs/project/remaining-work.md) for
  unfinished work;
- [upstream provenance](docs/project/upstream.md) for the frozen reference and
  attribution rules.

## Scope

Current contributions may cover the Go server, transport-neutral contracts,
`net/http`, direct `fasthttp`, Fiber, native storage adapters, protocol
primitives, server plugins, the browser/React/Next.js/Vue/Solid package, tests,
and documentation.

Do not add a native Go HTTP client, the Better Auth CLI, unsupported JavaScript
framework clients, billing integrations, Cloudflare/Bun/Deno runtime behavior,
or fake Drizzle, Prisma, or Kysely adapters. Applicable database behavior
belongs in the native Go storage contract and adapters.

`better-auth-main/` is preserved read-only evidence. Do not modify, generate
into, or depend on it at runtime; read it only during implementation review or
the explicit conformance source audit.

## Development setup

Use the Go version declared in `go.mod`. The root module contains library and
unit tests. Cross-package black-box tests live in `integrationtest/` and use
the external `singleauth_test` package. Real-service integration tests live in
the nested `e2e` module and require Docker.

Useful checks for a focused Go change:

```sh
go test ./path/to/package -count=1
go test -race ./path/to/package -count=1
go vet ./path/to/package
gofmt -w path/to/changed.go path/to/changed_test.go
git diff --check
```

Before requesting review for a cross-cutting change:

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go run ./internal/conformance/cmd/capability-report
```

Run the explicit read-only upstream evidence audit only when you changed
conformance references:

```sh
go run ./internal/conformance/cmd/capability-report -upstream-root .
```

The normal test suite and default capability report must work without reading
`better-auth-main/`.

## Real-service E2E

The E2E suite uses Testcontainers from the nested module. Docker must be
available. Run only the backends relevant to your change, or run the full
server-backed matrix:

```sh
cd e2e
SINGLE_AUTH_E2E_REQUIRED=1 go test ./redis ./postgres ./mysql ./mongodb ./mssql -count=1
go vet ./...
```

Required mode turns an unavailable container runtime into a failure rather than
a skip. SQLite tests do not require a container.

## Documentation changes

`docs/` is a self-contained Fumadocs/Next.js application. It is the only place
outside the preserved upstream snapshot where authored JavaScript,
TypeScript, MDX, a package manifest, and a Bun lockfile are allowed. The Go
library and Go tests must not import, execute, or require those artifacts.

After changing provider metadata, errors, or the supported public server API,
run the applicable source-derived generators from the repository root:

```sh
go run ./docs/scripts/social-providers
go run ./docs/scripts/error-codes
go run ./docs/scripts/go-api-reference
go run ./docs/scripts/check-links
go test ./docs/... -count=1
```

Then validate the documentation application with Bun from its own directory:

```sh
cd docs
bun install --frozen-lockfile
bun run lint
bun run typecheck
bun run build
```

Do not run the documentation development server as part of repository
validation. Keep `node_modules`, `.next`, generated caches, and other build
output untracked and contained under `docs/`. Do not add JavaScript or
TypeScript tooling elsewhere in the Go project.

## Implementing a compatibility capability

1. Identify one unique observable behavior in the frozen Better Auth snapshot.
2. Decide whether it applies to a native Go server, protocol, or adapter. Do
   not port runtime-specific mechanics that have no Go equivalent.
3. Implement the behavior in production Go code through the shared dispatcher
   or storage contract.
4. Cover applicable success, malformed-input, authorization, rollback,
   replay/concurrency, and failure cases.
5. Exercise all affected transports and real storage backends.
6. Update conformance evidence only after the implementation and required tests
   pass.

Frozen JSON fixtures are allowed as data-only evidence. Go code and ordinary
tests must not execute Bun, Node.js, TypeScript, or JavaScript oracle scripts.

## Package and API changes

- Follow the dependency rules in the [architecture](docs/project/architecture.md).
- Keep the root `singleauth` package as a thin application-facing facade; put
  implementation and reusable type identities in the package families defined
  by the architecture.
- Do not expose `internal` types in public signatures.
- Avoid adding a public package unless third-party code needs its API.
- Keep plugins and concrete adapters opt-in.
- Document exported identifiers and provide an example for non-obvious public
  behavior.
- Call out any intentional breaking change in the pull request. Compatibility
  breaks require explicit maintainer approval.

## Tests and naming

Name Go tests after Go behavior, not upstream filenames, TypeScript test paths,
or implementation-language compatibility labels. Upstream provenance belongs in the
conformance manifest or a fixture comment, while test names should describe the
observable contract.

Tests should be deterministic. Inject clocks, random sources, ID generators,
and outbound clients where the behavior needs control. Never depend on test
order, global mutable registration, a developer's environment, or a local copy
of the upstream source.

## Pull requests

Keep a pull request focused on one capability or architectural slice. Complete
the pull request template, list the exact commands you ran, describe public API
impact, and link any capability-map changes to executable evidence. Do not mark
an item complete when the corresponding check was skipped.

By participating, you agree to follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
