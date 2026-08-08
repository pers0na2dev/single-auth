# single-auth documentation

The English documentation site for the native Go `single-auth` server library
and its browser, React, Next.js, Vue, and Solid clients.
The site uses Next.js, Fumadocs, Fumadocs MDX, and Bun. Its JavaScript/TypeScript
toolchain is isolated under `docs/`; the library runtime and ordinary Go tests
do not depend on it.

Install the site dependencies from this directory:

```bash
bun install --frozen-lockfile
```

Run the non-development site checks:

```bash
bun run check
```

Do not start the development server in CI, generators, or automated validation.

Validate the compile-checked Go examples, generators, and documentation links
from the repository root:

```bash
go test ./docs/...
go vet ./docs/...
go run ./docs/scripts/check-links
go run ./docs/scripts/capabilities -check
go run ./docs/scripts/error-codes -check
go run ./docs/scripts/go-api-reference -check
go run ./docs/scripts/social-providers -check
```

Regenerate source-derived pages after changing provider metadata, the core
error map, or a supported public server API:

```bash
go run ./docs/scripts/social-providers
go run ./docs/scripts/error-codes
go run ./docs/scripts/capabilities
go run ./docs/scripts/go-api-reference
go run ./docs/scripts/check-links
```

The documentation layout is:

- `app/`, `components/`, and `lib/` contain the isolated Fumadocs application;
- `content/docs/` contains the handbook, task-oriented guides, capability
  matrix, and generated API reference;
- `examples/` contains server, direct API, storage, and plugin Go examples
  compiled by the Go test suite;
- `project/` contains architecture, implementation, provenance, and historical
  project notes kept out of the repository root;
- `scripts/` contains Go generators and the internal-link checker.

`docs/lib/source.ts` defines the Fumadocs source. Navigation is controlled by
the `meta.json` files in the content tree. Every page must have valid frontmatter
with at least a `title`. Generated pages and navigation metadata are committed
so the site build is deterministic from a clean checkout.

Set `NEXT_PUBLIC_SITE_URL` to the public site origin (without a path) for
production builds so canonical and Open Graph URLs use the deployed domain.
Local builds fall back to `http://localhost:3000`.

Set `NEXT_PUBLIC_BASE_PATH` when the site is hosted below the domain root. The
GitHub Pages workflow receives both values from `actions/configure-pages`, so
forks, project sites, user sites, and custom domains use the correct URLs.

Every push to `main` publishes the static export through
`.github/workflows/docs-pages.yml`. The workflow installs dependencies with
Bun, runs `next build`, uploads `docs/out`, and deploys it to the `github-pages`
environment. In the repository settings, GitHub Pages must use **GitHub
Actions** as its source.

The static site exposes client-side full-text search, `/llms.txt`,
`/llms-full.txt`, per-page processed Markdown, and generated Open Graph images
through pre-rendered routes under `app/`.

Do not document unsupported JavaScript frameworks or billing integrations as
stable features. The public handbook covers the Go server, native adapters,
transports, protocols, social providers, server-side plugins, and the isolated
browser/React/Next.js/Vue/Solid package. The native Go capability report covers
38 server-side groups; JavaScript client behavior is validated separately from
`clients/` with Bun.
