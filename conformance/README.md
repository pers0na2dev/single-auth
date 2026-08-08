# Conformance baseline

This directory preserves the Better Auth `1.6.26` source inventory and tracks
the active Go port. The checked-in JSON files are deterministic: they contain
no timestamps, absolute paths, host names, or random identifiers.

`better-auth-main/` is a read-only reference. Conformance extraction is a
manual review step; the Go build and test suite never imports or executes the
upstream source tree.

## Artifacts

- `source-lock.json` fixes provenance, license, public Go naming, and the source
  tree digest.
- `inventory.json` inventories all 20 workspace packages, their 102 export
  subpaths, 35 social providers, built-in and standalone plugins, CLI commands,
  documentation features, test configurations, and all 257 test/spec files.
  Every test file has a category and an owner phase.
- `test-manifest.json` contains the historical upstream test cases collected
  from the frozen source tree. It is provenance, not an executable Go-suite
  requirement.
- `compatibility-map.json` is a one-to-one ledger keyed by upstream stable test ID.
- `capability-map.json` is the Go-readiness source of truth. Every capability
  has structured observable assertions, native Go evidence, execution
  dimensions, and explicit read-only upstream paths/case substrings.
- `schemas/` contains the machine-readable artifact contracts.

## Pure-Go validation

Run from the repository root:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Go tests are hermetic with respect to the upstream snapshot and JavaScript
runtimes. They compile native Go packages and may load checked-in JSON fixtures
as immutable test data; they do not read source files or dependency trees from
`better-auth-main/` or `compat/`.

## Manual extraction

When an applicable upstream behavior is ported, inspect the read-only snapshot,
encode the behavior in a native Go test, and review any required frozen JSON
fixture as ordinary source data. Historical inventory and compatibility entries are
updated explicitly in the same review. No generator or runtime collector is
part of the Go test path.

## Optional Go evidence report

The Go event reporter converts `go test -json` output into deterministic leaf
evidence and can compare it with every accepted `implementation.kind=go-test`
entry. Tests under migration use `internal/conformancetest.Log` after their
assertions to emit the upstream ID and one record per applicable
transport/backend:

```sh
set -o pipefail
go test -json ./... | go run ./internal/conformance/cmd/go-test-report \
  -compatibility-map conformance/compatibility-map.json \
  -output /tmp/single-auth-go-test-report.json
```

Add `-require-passing-map` only after all accepted Go tests have migrated from
legacy `exact ID:` logs to structured evidence. The gate rejects missing,
failed, duplicate, or unexpected execution dimensions. Pending IDs may appear
in the report but do not become accepted compatibility.

Before accepting a pending fragment, include it explicitly in the same proof:

```sh
go test -json ./plugins/apikey | go run ./internal/conformance/cmd/go-test-report \
  -compatibility-map conformance/compatibility-map.json \
  -candidate-fragment conformance/compatibility-updates/apikey-verify-update-get-list-36.json \
  -candidate-only \
  -require-passing-map
```

`candidate-only` makes a focused package run ignore unrelated accepted IDs;
the fragment still has to reference known, currently unaccepted compatibility-map
entries. `candidateGoIDs` and the dimension counters include the fragment
without changing `compatibility-map.json`. Multiple `-candidate-fragment` flags are
allowed.

Review frozen-artifact diffs like source code; never normalize away security
headers, cookie attributes, error fields, or other observable behavior.

## Go capability contract

The default report validates schema, status rules, observable contracts,
dimensions, native Go evidence paths, and scope decisions without reading the
preserved source tree:

```sh
go run ./internal/conformance/cmd/capability-report
```

The schema-v2 snapshot contains 38 capability groups, 38 observable contracts,
76 assertion strings, 83 upstream file references, and 267 exact upstream case
substrings. Readiness is 38 passing, 0 partial, and 0 missing: all 38 applicable
Go capability groups are passing.

During an explicit source-audit step, verify that every recorded upstream path
exists and contains every recorded case substring:

```sh
go run ./internal/conformance/cmd/capability-report -upstream-root better-auth-main
```

This opt-in audit only reads `better-auth-main`; it never imports or executes
JavaScript/TypeScript. Ordinary `go test`, `go vet`, and the default report
remain valid when the preserved source tree is absent.
