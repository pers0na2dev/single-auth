---
title: "Getting started"
description: "Install the pre-release module, create one immutable auth runtime, choose a transport and storage backend, and validate a production path."
---

Install single-auth, create a server, and understand the runtime model.

The smallest `single-auth` server needs a public base URL, a random secret, and one enabled authentication method. It uses an in-memory primary adapter when no database is configured, which is useful for local evaluation but not durable production use.

1. **Add the module.** Follow [Installation](./installation.md) and import `github.com/pers0na2dev/single-auth`.
2. **Construct one immutable runtime.** Call `singleauth.New` during application startup. Configuration is copied and validated; the returned `*singleauth.Auth` is safe for concurrent use.
3. **Mount one transport.** `*singleauth.Auth` implements `http.Handler`. Dedicated adapters expose the same dispatcher to direct `fasthttp` and Fiber v3.
4. **Configure durable storage.** Use SQLite for an embedded deployment or a native PostgreSQL, MySQL, MSSQL, or MongoDB adapter. Redis is secondary storage, not a primary adapter.
5. **Add plugins before migrations.** Plugin factories contribute schema at runtime construction. When you build an adapter manually, merge plugin schemas before creating that adapter. The SQLite raw-database initializer is the exception because it receives the final merged schema automatically.

- [Five-minute quickstart](./quickstart.md)
- [Runtime architecture](./architecture.md)
- [All configuration fields](./configuration.md)

## Evaluation path

Use this order so each check proves one new boundary:

1. Run the memory-backed quickstart and exercise sign-up, session lookup, and
   sign-out with a cookie jar.
2. Replace memory with SQLite or the intended shared primary backend, run
   additive migrations, restart the process, and prove users/sessions persist.
3. Put the selected transport behind the real proxy and verify the public base
   URL, secure cookies, client IP, trusted origin, and a rejected foreign
   origin.
4. Configure one authentication method at a time. For OAuth, test start and
   callback on different replicas when the deployment is distributed.
5. Add plugin factories in dependency order, rerun migrations, and test both
   authorized and cross-tenant/unauthorized paths.
6. Exercise failure responses, rate limits, revocation, replay, rollback, and
   graceful shutdown before enabling production traffic.

The [production guides](../guides/index.md) connect those tasks across packages.
The [capability matrix](../reference/capabilities.md) records the passing
server, protocol, storage, and transport boundaries. JavaScript client behavior
is validated separately from `clients/`.
