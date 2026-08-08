---
title: "Transports"
---

Serve the same immutable authentication dispatcher through four execution surfaces.

`single-auth` converts every incoming request into `contract.Request` and every result into `contract.Response`. Authentication behavior therefore lives above the web-server implementation.

| Surface | Package | Use when |
| --- | --- | --- |
| Standard library | root package or `transport/nethttp` | Your application uses `http.Handler`, `ServeMux`, Chi, Gorilla, Echo adapters, or another net/http-compatible router |
| Direct fasthttp | `transport/fasthttp` | Your server is built directly on `github.com/valyala/fasthttp` |
| Fiber v3 | `transport/fiber` | Your application uses `github.com/gofiber/fiber/v3` |
| Direct API | root package | Trusted server code needs to invoke an endpoint without serializing an HTTP request |

Every HTTP transport preserves:

- repeated request and response headers, including multiple `Set-Cookie` fields;
- raw query strings and escaped paths;
- request bodies without a net/http conversion layer for fasthttp/Fiber;
- request context propagation;
- endpoint middleware, before hooks, after hooks, origin checks, and HTTP rate limiting;
- the same status codes and JSON error envelope.

> **Warning: Choose one adapter per incoming request**
>
> Do not send one request through multiple adapters. Construct one `Auth`, then mount the adapter native to the hosting server. The dispatcher is reusable and safe for concurrent calls.

## Shared adapter controls

All HTTP adapters expose a maximum-body option and a non-mutating error observer. The error observer runs after the stable wire response has been selected; it is for logging and metrics, not response replacement.

The direct fasthttp adapter additionally accepts a `ContextProvider` for hosts that need a stable request or server-lifecycle cancellation context.
