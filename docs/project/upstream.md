# Frozen Better Auth upstream

`single-auth` is a clean-room Go port targeting behavioral and wire-level
compatibility with the source snapshot in `better-auth-main/`.

`better-auth-main/` is a read-only reference. The Go build and test suite do
not import it, modify it, or execute any tooling from it.

## Baseline

| Field | Locked value |
|---|---|
| Project | Better Auth |
| Upstream repository | `https://github.com/better-auth/better-auth.git` |
| Package version | `1.6.26` |
| Git commit | unavailable in the supplied source archive |
| Snapshot path | `better-auth-main/` |
| Tree SHA-256 | `01f179b28c2de406e22388ec175234c6ae437bf437a8e8c34a8b3bfb51330521` |
| Hashed files | 1,907 |
| License | MIT |
| License SHA-256 | `7a07f7d9085cb3157e4377d944988c9712933141b0f7201955ceccfac92abde4` |

The archive has no `.git` metadata, so no commit SHA is inferred or invented.
Version `1.6.26` is read from every workspace package manifest. The repository
URL comes from the upstream root manifest.

## Recalculate the tree hash

The digest hashes the standard `shasum` output for every regular file in
bytewise path order. `.git` content and macOS `.DS_Store` files are excluded.
Run this from `better-auth-main/`:

```sh
find . -type f ! -path './.git/*' ! -name '.DS_Store' -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 shasum -a 256 \
  | shasum -a 256
```

Expected output:

```text
01f179b28c2de406e22388ec175234c6ae437bf437a8e8c34a8b3bfb51330521  -
```

The hash command above is a manual provenance check. Runtime behavior is
validated by the hermetic Go suite from the repository root:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Applicable behavior is extracted manually from the read-only snapshot into
native Go code, Go tests, and, when a fixed vector is useful, reviewed JSON
fixtures. Updating the snapshot or its provenance never happens as a side
effect of `go test`.

## License and attribution

The upstream snapshot is distributed under the MIT License:

> Copyright (c) 2024 - present, Bereket Engida

The complete upstream license text remains in `better-auth-main/LICENSE.md` and
must accompany copied or derived portions. Ported behavior must retain a source
reference through the test manifest/compatibility map; ported code derived from a
specific upstream file must preserve its provenance and MIT notice in repository
history and release attribution.

## Port naming

- Distribution and repository name: `single-auth`.
- Canonical Go module path: `github.com/pers0na2dev/single-auth`.
- Root Go package identifier: `singleauth` (Go identifiers cannot contain `-`).

Changing the upstream version or tree is a new compatibility cycle. Do not refresh this
lock while fixing a regression against the current baseline.
