## Summary

<!-- What observable behavior or structural boundary does this change? -->

## Scope

- Related issue:
- Affected packages:
- Affected capability IDs:

## Compatibility and architecture

- [ ] Public API is unchanged, or the breaking change is called out below.
- [ ] Package dependencies follow the architecture in `docs/project/architecture.md`.
- [ ] Production code and ordinary tests remain Go-only.
- [ ] `better-auth-main/` remains an optional, read-only reference.
- [ ] No excluded JS runtime, CLI, billing, or JavaScript ORM compatibility was added.

Public API or architecture notes:

<!-- Describe exported symbols, wire/storage changes, migrations, or "None". -->

## Verification

<!-- Replace examples with the exact commands you ran. Do not check skipped gates. -->

- [ ] Focused `go test` passed.
- [ ] Applicable focused `go test -race` passed.
- [ ] Applicable `go vet` passed.
- [ ] `gofmt` and `git diff --check` passed.
- [ ] Affected `net/http`, direct `fasthttp`, and Fiber behavior was tested.
- [ ] Affected native storage adapters were tested.
- [ ] Required Testcontainers E2E passed.
- [ ] Default capability report passed.
- [ ] Documentation was updated where needed.

Commands and results:

```text

```

## Conformance evidence

<!-- Link tests/fixtures for capability changes. State "No status change" otherwise. -->

## Security and operational impact

<!-- Cover cookies, tokens, authorization, replay/concurrency, migrations, and rollback where applicable. -->
