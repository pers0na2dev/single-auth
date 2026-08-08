# single-auth

Work-in-progress native Go port of the Better Auth 1.6.26 server for `net/http`,
`fasthttp`, and Fiber. The implementation is not yet a drop-in replacement:
only independently audited observable behavior counts as complete.

Current scope is the native Go server/library plus an isolated browser-client
package for React, Next.js, Vue, and Solid. The preserved
`better-auth-main/` tree is the read-only reference used during the port; Go
production code and tests do not execute it. The JavaScript clients live under
`clients/`, call the Go HTTP API, and never become a Go runtime dependency. A
CLI, billing integrations, other JavaScript frameworks, and compatibility
layers for JavaScript-only ORMs remain outside scope. A native Go HTTP client is
intentionally not shipped; Go applications use the direct API or ordinary HTTP
routes. Applicable database behavior is implemented through native Go storage
adapters.

The active JavaScript/TypeScript toolchains outside the preserved snapshot are
the isolated Fumadocs application under `docs/` and client package under
`clients/`. Each has its own Bun lockfile and dependencies; the Go library and
Go test suite do not import, execute, or require either workspace.

Current reproducible Go capability snapshot: **38 passing, 0 partial, 0
missing out of 38 (100%)**. Partial capabilities would not increase readiness.
The schema-v2 source is `conformance/capability-map.json`: all 38 groups carry
structured observable contracts (76 assertion strings) and explicit preserved
upstream evidence (83 references, 267 exact case substrings). Validate and
print the self-contained Go report with
`go run ./internal/conformance/cmd/capability-report`;
add `-upstream-root better-auth-main` only for an explicit read-only source audit.

The separate JavaScript package exports browser, React, Next.js, Vue, and Solid
entrypoints. Its reproducible gate is **28 passing tests**, an ESM/declaration
build, packed-export smoke, and a live sign-up/session/sign-out lifecycle
against the native Go HTTP server. Run it from `clients/` with
`bun run check`.

## Repository layout

- `singleauth` at the repository root is the thin public facade.
- `core/` owns the server implementation plus transport-neutral contracts,
  dispatch, and models.
- `security/`, `protocol/`, and `observability/` group reusable supporting
  packages by responsibility.
- `storage/`, `transport/`, and `plugins/` contain the opt-in integration
  surfaces; social providers live under `protocol/providers/`.
- `conformance/` stores checked-in capability evidence; `e2e/` is the nested
  real-service test module.
- `clients/` contains the isolated Bun package for browser and framework clients.
- `docs/` contains the isolated documentation application and project notes.
- `better-auth-main/` remains the preserved read-only upstream reference.

## Project documents

- [Architecture](docs/project/architecture.md)
- [Implementation plan](docs/project/implementation-plan.md)
- [Remaining work](docs/project/remaining-work.md)
- [Upstream provenance](docs/project/upstream.md)
- [Historical porting plan](docs/project/archive/porting-plan.md)
- [English Fumadocs handbook](docs/README.md)
- [Documentation content](docs/content/docs/index.md)
- [Mandatory repository port rules](AGENTS.md)
- [Go capability map](conformance/capability-map.json)
