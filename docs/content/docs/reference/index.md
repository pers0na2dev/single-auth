---
title: "Reference"
description: "Generated capability status, exact core HTTP routes, error contracts, and public server-side Go declarations."
---

Exact HTTP routes, error contracts, and generated public Go declarations.

Use the narrative sections to choose and configure a feature. Use this section when you need an exact route, symbol, signature, error code, or package import.

- [**Capabilities**](./capabilities.md) — Generated status and observable contracts for all 38 native Go server capability groups.
- [**HTTP routes**](./http-routes.md) — Core methods, paths, authentication requirements, inputs, and results. Plugin routes are documented on their plugin pages.
- [**Errors**](./error-codes.md) — Typed API errors, wire shapes, redaction, and every core error code.
- [**Go packages**](./packages/index.md) — Generated declarations for every exported server-side symbol.

## Source of truth

The package reference is generated from the checked-in Go source with:

```bash
go run ./docs/scripts/go-api-reference
```

The capability matrix, social-provider reference, and error catalog are likewise generated from their checked-in sources. Regenerate all four after changing their public contracts:

```bash
go run ./docs/scripts/capabilities
go run ./docs/scripts/social-providers
go run ./docs/scripts/error-codes
go run ./docs/scripts/go-api-reference
```

The server package generator excludes internal packages, conformance machinery,
commands, testdata, and E2E harnesses. Browser and framework behavior is
documented separately in [JavaScript clients](../javascript-client/index.md).
