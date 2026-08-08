# single-auth port rules

These rules are mandatory for every change in this repository.

## Product goal

- Port the applicable server, protocol, and storage capabilities of
  the preserved Better Auth 1.6.26 snapshot to the native Go module
  `single-auth` (`package singleauth`).
- Support the same transport-neutral behavior through `net/http`, direct
  `fasthttp`, and Fiber.
- Ship the browser client and the React, Next.js, Vue, and Solid integrations
  as an isolated Bun package that targets the native Go HTTP surface.
- Measure completeness by unique observable Go capabilities in
  `conformance/capability-map.json`, not by duplicated Vitest leaf counts.

## Preserved upstream reference

- `better-auth-main/` is the read-only source reference for the port and must
  remain in the repository until the port is complete.
- Never delete, rewrite, or use `better-auth-main/` as a production or test
  runtime dependency.
- Reading the snapshot while implementing or running the explicit read-only
  conformance audit is allowed. Ordinary `go test ./...` must not read it.

## Go-only runtime and tests

- Production code and ordinary tests must work with only the Go toolchain.
- Do not execute Bun, Node.js, npm, Vitest, Playwright, TypeScript, or any
  JavaScript oracle from Go code or Go tests.
- `docs/` and `clients/` are the only authored-code exceptions. Each is an
  isolated Bun workspace and may contain JavaScript/TypeScript, `package.json`,
  and its own Bun lockfile. Dependencies and build output must remain local to
  the owning workspace and ignored by Git.
- Run Bun commands only from `docs/` for documentation work or from `clients/`
  for JavaScript-client work. Go production packages and Go tests must not
  import, execute, or require either workspace's JavaScript/TypeScript/Bun
  artifacts.
- Do not add `node_modules`, JavaScript/TypeScript source, package manifests,
  Bun locks, or JS compatibility shims anywhere else outside `docs/`,
  `clients/`, and the preserved upstream tree.
- Frozen JSON/golden fixtures are allowed when they contain data only and do
  not require a JavaScript runtime.

## Scope exclusions

- Do not port the Better Auth CLI.
- Do not port Stripe, Polar, or other billing/payment integrations.
- Do not port anonymous product telemetry or its publisher. Tracing
  instrumentation and application logging remain in scope.
- Do not port Cloudflare Workers, Bun, Deno, Vite, esbuild, browser-framework,
  or TypeScript compile/runtime behavior into the Go milestone.
- Do not create Drizzle, Prisma, or Kysely Go adapters or compatibility tests.
  Extract applicable database behavior into the shared native Go adapter and
  migration contracts instead.
- React, Next.js, Vue, and Solid clients are in scope only under `clients/` and
  must call the native Go HTTP API. Other JavaScript framework integrations
  remain deferred.
- Do not ship a native typed or raw Go HTTP client. Go applications can use the
  transport-neutral direct API or call the documented HTTP routes.

## Definition of done for a capability

1. Identify the unique observable behavior in the upstream snapshot.
2. Implement it in production Go code without a test-only shim.
3. Cover success, validation, authorization, rollback, replay/concurrency, and
   malformed-input cases that apply to Go.
4. Exercise every applicable transport and real storage backend.
5. Pass normal tests, race tests, vet, and Testcontainers E2E where relevant.
6. Update the capability manifest and plans only after the evidence passes.

Keep unrelated dirty-worktree changes intact. Do not stage, commit, push, or
remove files unless the user explicitly requests that action.
