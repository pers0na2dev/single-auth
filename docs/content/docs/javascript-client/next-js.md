---
title: "Next.js integration"
description: "Proxy App Router auth requests to Go and read request-scoped sessions."
---

Client Components use the [React client](./react.md). For an App Router route
that keeps the Go service private, export a remote proxy:

```ts
// app/api/auth/[...all]/route.ts
import {
  createNextJsProxyHandler,
  toNextJsHandler,
} from "@pers0na2dev/single-auth/next-js";

export const { GET, POST, PATCH, PUT, DELETE } = toNextJsHandler(
  createNextJsProxyHandler({
    authURL: process.env.SINGLE_AUTH_URL!,
    forwardedHeaders(request) {
      const clientIP = request.headers.get("x-platform-client-ip");
      return clientIP ? { "x-forwarded-for": clientIP } : {};
    },
  }),
);
```

`authURL` is the complete Go auth base URL. The proxy preserves method, query,
streaming body, status, manual redirects, and multiple `Set-Cookie` headers
while removing hop-by-hop headers. It also forces `no-store`, prevents
compressed-response metadata from outliving a decoded body, and replaces
browser-controlled proxy/IP headers with the public host and protocol from the
Next request URL. `forwardedHeaders(request)` is the only source allowed to
restore forwarding/IP headers; use it only with a header that your deployment
edge strips or overwrites on every public request.

Configure that callback when the default Go rate limiter is enabled. Without a
trustworthy per-request IP, all requests behind the proxy share the Go
`no-trusted-ip` bucket. The example's `x-platform-client-ip` is a placeholder
for an edge-owned header from your deployment, not a header to accept directly
from a browser.

Server Components and Server Actions can read the request-scoped session:

```ts
import { getNextSession } from "@pers0na2dev/single-auth/next-js";

export default async function Page() {
  const session = await getNextSession({
    authURL: process.env.SINGLE_AUTH_URL!,
  });
  return <pre>{JSON.stringify(session, null, 2)}</pre>;
}
```

Pure RSC reads disable session and cookie-cache refresh because that context
cannot write replacement cookies. Server Actions apply refreshed cookies
through Next's request-scoped cookie store. Calls that supply explicit headers
can also supply a writable `cookies` store. `applyNextResponseCookies` remains
available for lower-level Fetch flows, and `toNextJsHandler` adapts any already
constructed Fetch-compatible handler.

If the Go server uses `DynamicBaseURL`, pass `publicOrigin` to
`getNextSession`; incoming forwarding and client-IP headers are discarded. A
separate `forwardedHeaders` source exists for values that server-owned code has
already authenticated:

```ts
const session = await getNextSession({
  authURL: process.env.SINGLE_AUTH_URL!,
  publicOrigin: process.env.APP_ORIGIN!,
});
```

The upstream `nextCookies()` server plugin is intentionally not exported: it
requires an in-process TypeScript auth server and would be dishonest for a
remote native Go server.
