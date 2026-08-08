# anonymous

Go port of single-auth 1.6.26's `anonymous` server plugin.

Use `anonymous.NewFactory` with `singleauth.Options.PluginFactories`. The
factory binds the plugin to the root adapter, authoritative session resolver,
request-local `newSession`, secondary-storage revocation, cookie overrides,
dynamic secure cookie names, and root logger. The resulting descriptor is
shared by direct calls, `net/http`, fasthttp, and Fiber.

Server surface:

- `POST /sign-in/anonymous` (`signInAnonymous`)
- `POST /delete-anonymous-user` (`deleteAnonymousUser`)
- `user.isAnonymous`: optional boolean, `input: false`, default `false`
- post-link matching for the ten single-auth sign-in/sign-up/callback and
  verification path prefixes
- no plugin-specific rate rule; single-auth's global and built-in sign-in rule
  remains authoritative

`Options.Schema` accepts the storage schema override used for physical aliases.
Supplying only `FieldName` for `user.isAnonymous` preserves the upstream type,
required/input flags, and default.

Frozen JSON provenance is stored in
[`testdata/reference-1.6.26-oracle.json`](./testdata/reference-1.6.26-oracle.json)
and consumed by the native Go tests as immutable data. Updates are manually
reviewed against the read-only upstream snapshot.

```sh
go test ./plugins/anonymous
go test -race ./plugins/anonymous
```
