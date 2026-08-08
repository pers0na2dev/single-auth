---
title: "Architecture"
---

How configuration, plugins, dispatch, transports, and persistence fit together.

## Runtime construction

`singleauth.New` performs startup work once:

1. copies and normalizes `Options`;
2. resolves the secret or versioned secret ring;
3. merges the core schema, optional rate-limit schema, explicit schema, static plugin schemas, and plugin-factory schemas;
4. constructs or selects the primary adapter;
5. builds plugin factories against the authenticated host runtime;
6. installs database hooks and freezes them;
7. builds the rate limiter;
8. merges core and plugin endpoints into an immutable registry;
9. creates one transport-neutral dispatcher;
10. creates the standard-library handler around that dispatcher.

Configuration slices, maps, plugin descriptors, and endpoint descriptors are copied. Mutating the original values after `New` returns does not reconfigure the server.

## Request path

```text
HTTP server
  -> transport adapter
  -> contract.Request
  -> dispatcher
  -> initialize request context
  -> reject disabled paths
  -> rate limiter (HTTP requests only)
  -> plugin OnRequest handlers
  -> security middleware
  -> user and plugin path middleware
  -> match endpoint
  -> before hooks
  -> endpoint-local Use middleware
  -> endpoint handler
  -> after hooks
  -> plugin OnResponse handlers
  -> contract.Response
  -> transport adapter
```

All three HTTP transports use this pipeline. The direct API invokes the same endpoint registry, endpoint-local `Use` middleware, handlers, and before/after hooks. It intentionally bypasses disabled-path routing, HTTP rate limiting, security and other path middleware, plugin `OnRequest`/`OnResponse`, and transport observers.

## Static plugins and plugin factories

`Options.Plugins` accepts already-built `engine.Plugin` values. Use this form when a plugin does not need access to the root auth runtime.

`Options.PluginFactories` accepts `singleauth.PluginFactory`. Factories expose their schema before the adapter is initialized, then receive a bound host capable of issuing sessions, accessing storage, resolving base URLs, and registering runtime hooks. Most high-level server plugins should be configured as factories.

## Primary and secondary persistence

The primary `storage.Adapter` stores users, sessions, accounts, verifications, plugin models, and optionally database rate limits. When no adapter is supplied, `New` constructs an in-memory adapter from the final merged schema.

Secondary storage is optional and optimized for string or JSON values with expiry. It can become authoritative for sessions, verification tokens, and rate-limit counters depending on configuration. Redis implements this secondary contract; it is not a primary relational/document adapter.

## Concurrency model

The constructed runtime, dispatcher, registry, transport adapters, and built-in adapters are designed for concurrent use. Configuration callbacks and custom storage implementations must also be safe for concurrent calls. Single-use verification and authorization artifacts use atomic adapter operations or scoped locking to reject replay.
