# single-auth JavaScript clients

`@pers0na2dev/single-auth` is the isolated browser-client package for the
native Go server. It exports a vanilla client plus React, Next.js, Vue, and
Solid integrations:

```ts
import { createAuthClient } from "@pers0na2dev/single-auth/react";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
});
```

All clients use credentialed Fetch requests and the same dynamic endpoint
mapping as the preserved Better Auth 1.6.26 client. The package has no runtime
dependency on `better-auth-main/` or a JavaScript authentication server.

Framework entrypoints:

- `@pers0na2dev/single-auth` — vanilla browser client
- `@pers0na2dev/single-auth/react` — React 18/19 hooks
- `@pers0na2dev/single-auth/vue` — Vue refs and Nuxt `useFetch`
- `@pers0na2dev/single-auth/solid` — Solid accessors
- `@pers0na2dev/single-auth/next-js` — App Router proxy and server-session helpers

Next.js proxies a remote Go handler explicitly:

```ts
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

The proxy discards browser-controlled forwarding/IP headers, synthesizes the
public host and protocol, disables caching, and preserves multiple response
cookies. The upstream `nextCookies()` plugin is not exported because it
requires an in-process TypeScript auth server.

When the default Go rate limiter is enabled, `forwardedHeaders` must obtain a
per-request IP from a header that the deployment edge strips or overwrites.
Never forward a browser-controlled `X-Forwarded-For`; without a trusted IP all
proxied callers share one `no-trusted-ip` rate-limit bucket.

Run checks only from this directory:

```sh
bun install
bun run check
bun pm pack --dry-run
```
