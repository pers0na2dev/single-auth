# single-auth architecture

This document defines the vNext package boundaries for `single-auth`. The root
package is a small application-facing facade; implementation and reusable
primitives live in named package families. During the reorganization, any
remaining legacy top-level package path is transitional rather than a stable
part of this layout. Current capability status remains defined by the
[`conformance/capability-map.json`](../../conformance/capability-map.json).

## Design goals

- Keep the public entry point small and predictable for Go applications.
- Run identical authentication behavior behind `net/http`, direct `fasthttp`,
  and Fiber adapters.
- Make plugins and storage adapters optional: importing the root package must
  not pull every integration into an application.
- Keep production code and ordinary tests independent of JavaScript runtimes
  and the preserved Better Auth source tree.
- Isolate the Fumadocs JavaScript/TypeScript/Bun toolchain under `docs/` so it
  never enters the Go production or test dependency graph.
- Make dependency direction visible in the directory structure and enforceable
  with normal Go package rules.

## Repository layout

```text
single-auth/
├── *.go                         # thin package singleauth facade
├── core/                        # server composition and auth implementation
│   ├── contract/                # transport-neutral wire contracts
│   ├── engine/                  # registry, matching and dispatch
│   └── model/                   # shared auth data models
├── security/                    # reusable security policy and primitives
│   ├── authorization/
│   ├── cookies/
│   ├── crypto/
│   └── ratelimit/
├── protocol/                    # reusable protocol implementations
│   ├── oauth2/
│   ├── providers/               # social-provider definitions
│   ├── saml/
│   └── webauthn/
├── observability/               # logging, metrics and diagnostics
│   ├── instrumentation/
│   └── logger/
├── storage/                     # adapter contract, migrations and native adapters
│   ├── adaptertest/             # reusable adapter conformance suite
│   ├── memory/
│   ├── sqlite/
│   ├── postgres/
│   ├── mysql/
│   ├── mssql/
│   ├── mongodb/
│   └── secondary/               # optional cache/session storage
│       └── redis/
├── transport/                   # protocol adapters only
│   ├── internal/testsuite/      # shared private transport contract tests
│   ├── nethttp/
│   ├── fasthttp/
│   └── fiber/
├── plugins/<plugin>/            # optional public server extensions
├── internal/                    # repository-private services and test support
│   └── conformance/             # private capability/report commands and packages
├── integrationtest/             # cross-package external Go tests
├── conformance/                 # checked-in JSON manifests, schemas and evidence
├── e2e/                         # nested Testcontainers integration module
├── clients/                     # isolated Bun browser/framework client package
├── docs/                        # isolated Fumadocs/Next.js app built with Bun
└── better-auth-main/            # preserved read-only upstream reference
```

### Root package: composition and public identity

The root `singleauth` package is the application-facing boundary. It exposes
`Auth`, `Options`, plugin extension contracts, errors, and constructors while
delegating implementation to `core`. It does not own route algorithms,
persistence mechanics, protocol implementations, or observability services.

The root is a composition facade, not a catch-all implementation directory.
The vNext package-family migration intentionally changes legacy leaf import
paths and type identities; the final paths documented here become the stable
surface after the migration is complete.

The root package must not import optional plugin packages or concrete storage
adapters. Applications select those packages explicitly, which prevents import
cycles and keeps dependencies opt-in.

### Public extension packages

Public packages exist when application or extension authors need to name and
use their types directly:

- `core/contract` owns transport-neutral request, response, header, endpoint, and
  middleware contracts.
- `core/engine` owns deterministic route registration, matching, endpoint conflict
  detection, and dispatch mechanics.
- `core/model` owns storage- and transport-independent auth models.
- `security/authorization` owns reusable role, statement, and permission evaluation; it
  does not register authentication routes.
- `storage` owns the adapter, query, schema, migration, and transaction
  contracts. Each concrete backend lives in its own child package.
- `protocol/oauth2`, `protocol/saml`, and `protocol/webauthn` expose reusable
  protocol primitives without depending on a server transport.
- `protocol/providers` owns the built-in and custom social-provider registry
  built on the OAuth2 primitives.
- `security/cookies`, `security/crypto`, and `security/ratelimit` expose shared
  security primitives and policy.
- `observability/instrumentation` and `observability/logger` keep operational
  concerns out of the auth core.

Do not create a public package solely to shorten a root file. A package becomes
public only when external users need its API; otherwise it belongs under
`internal`.

### Plugins

Each `plugins/<name>` package implements one optional server capability. A
plugin may depend on the root extension contracts and lower-level public leaf
packages, but the root package must never import it. Plugins must not depend on
each other unless the relationship is part of an explicit public integration
contract; shared mechanics belong in a lower-level package.

Plugin packages own their routes, options, schema contributions, migrations,
rate-limit rules, errors, and public HTTP or direct-API surface where
applicable. They must not bypass the common dispatcher, origin/CSRF policy,
storage contract, or transaction boundary.

### Storage

The parent `storage` package contains backend-neutral contracts. Native backend
packages implement those contracts directly; JavaScript ORM compatibility
packages are intentionally out of scope.

Backend-independent behavior belongs in the shared contract or migration
packages and is verified by `storage/adaptertest`. Backend-specific SQL,
serialization, transaction behavior, and capability limits stay in the
corresponding adapter package. Real PostgreSQL, MySQL, MSSQL, MongoDB, and Redis
behavior is exercised in the nested `e2e` module with Testcontainers.

`storage/secondary` contains the secondary-storage contract, and
`storage/secondary/redis` implements it. Secondary storage is deliberately
nested under storage without pretending Redis is a primary database adapter.
Applications opt into it when they need Redis-backed session, cache, or
rate-limit behavior.

### Transports

`transport/nethttp`, `transport/fasthttp`, and `transport/fiber` translate
framework requests into `core/contract.Request`, invoke the same dispatcher,
and translate `core/contract.Response` back. They contain no authentication
business logic and never fork route behavior.

The transport-neutral layers do not import `net/http`, `fasthttp`, or Fiber.
Transport adapters may depend on the root-facing handler contract and lower
level contracts, but the core pipeline must not depend on a concrete transport.
Raw bodies, repeated headers, `Set-Cookie`, cancellation, and peer-address
semantics must survive translation without accidental normalization.

The common adapter behavior suite lives at `transport/internal/testsuite`.
Only packages below `transport/` may import it; it is test support, not public
library API.

### Internal packages

`internal` contains cohesive business services and repository-only helpers
that third-party packages must not import. Internal services depend downward on
public leaf contracts; they do not import the root package, optional plugins,
concrete transports, or concrete storage adapters. The root package composes
them and converts between root-owned public types and internal implementation
types where needed.

Test-only helpers belong under `internal` or beside the package they test. They
must not become production APIs just to make a test convenient.

`internal/conformance` contains the private capability validator, Go test event
reporter, and their commands. The public `conformance/` directory contains
data-only manifests, schemas, candidate evidence, and explanatory material;
it is not an importable Go package.

### JavaScript workspace boundaries

`docs/` is a self-contained Fumadocs/Next.js application built with Bun. Its
TypeScript, JavaScript, MDX, package manifest, lockfile, installed dependencies,
and build output must remain below `docs/`. They may be used to build, lint, or
type-check documentation, but they are never imported or executed by Go
production packages or ordinary Go tests.

`clients/` is a separate Bun package for the browser, React, Next.js, Vue, and
Solid integrations. It calls the public Go HTTP surface and has its own lockfile,
dependencies, tests, declarations, and build output. Go production packages and
ordinary Go tests never import or execute it.

No other active package may introduce a JavaScript runtime or package manager.
`better-auth-main/` is a separate preserved read-only source snapshot, not a
build dependency for either the Go module or the documentation application.

## Dependency rules

The intended dependency direction is:

```text
application
    │
    ├── singleauth (public identity + composition)
    ├── plugins/* (optional)
    ├── storage/* (chosen adapter)
    └── transport/* (chosen server adapter)

singleauth ──> core ──> core/contract + core/engine + core/model
core ──> security + protocol + observability + storage contracts
plugins/* ──> singleauth extension API + public package families
storage adapters ──> storage contract + backend driver
transport/* ──> core/engine + core/contract
clients/ ──> public Go HTTP routes
```

Mandatory constraints:

1. `better-auth-main/` is never imported or read by production code or ordinary
   tests.
2. `internal` packages never become part of a public function or type
   signature.
3. Foundation packages under `core`, `security`, `protocol`, `observability`,
   and `storage` do not import the root package.
4. The root package does not import optional plugins or concrete adapters.
5. Transport-neutral packages do not import a concrete HTTP framework.
6. Concrete transports contain translation only; business behavior is tested
   once through the shared pipeline and then across the transport matrix.
7. Concrete storage packages do not leak driver-specific types into the
   backend-neutral adapter interface.
8. The Go module does not expose a native remote-client SDK; Go callers use the
   direct API or public HTTP routes, while `clients/` stays isolated.
9. Package initialization must not register global routes, adapters, or
   plugins. Composition is explicit and deterministic.
10. Cross-package helpers move to the lowest coherent package, not to a generic
    dumping-ground utility package.

## Request pipeline

All server entry points converge on one ordered pipeline:

```text
transport translation
→ URL and trusted-origin resolution
→ disabled-path and rate-limit checks
→ request/plugin middleware
→ route match, decode and validation
→ before hooks
→ endpoint service
→ after hooks
→ response/plugin middleware
→ transport translation
```

Direct API calls use the same dispatcher and skip only explicitly HTTP-only
stages. Server-only endpoints remain absent from public HTTP routing and
generated HTTP schemas.

## Test boundaries

- Package tests prove local contracts with the Go toolchain only.
- Cross-package public API tests use external test packages when practical.
- Repository-wide black-box tests that need the public root package live in
  `integrationtest/`, not among root implementation files.
- Transport-visible behavior is exercised through `net/http`, direct
  `fasthttp`, and Fiber.
- Adapter behavior is shared through `storage/adaptertest`; real-service
  behavior runs in `e2e` with required-mode Testcontainers.
- Frozen JSON fixtures may record upstream observations, but tests do not run
  Bun, Node.js, TypeScript, documentation tooling, or the upstream source tree.
- Capability status changes only after executable evidence is recorded in the
  conformance map and all applicable gates pass.

## Evolution rules

Architecture moves should be small enough to review and should preserve
behavior before changing it. A structural change is complete only when import
cycles are absent, public API checks pass, focused tests pass, generators and
documentation point at the new package identities, and no compatibility shim
silently restores a retired import path. See the [remaining work](remaining-work.md)
for unfinished capabilities and release gates.
