---
title: "Browser client"
description: "Use the isolated Bun-built JavaScript client against the native single-auth Go HTTP API."
---

`@pers0na2dev/single-auth` is an ESM browser client for the native Go server.
It preserves the Better Auth-style dynamic endpoint API, credentialed requests,
session state, cross-tab updates, focus/online refresh, safe redirects, and
date-aware JSON parsing without depending on a JavaScript auth server.

## Install

```sh
bun add @pers0na2dev/single-auth
```

## Create a client

Pass the complete auth base URL, including `/api/auth` when the server uses the
default base path:

```ts
import { createAuthClient } from "@pers0na2dev/single-auth";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
});
```

Calls use camelCase in TypeScript and kebab-case on the wire:

```ts
const signedIn = await authClient.signIn.email({
  email: "ada@example.com",
  password: "correct horse battery staple",
});

await authClient.signOut();
```

`$fetch` exposes the underlying Better Fetch instance for explicit paths.
`$store` exposes session/plugin atoms and notification hooks. Unknown plugin
routes remain callable through the runtime proxy; application-specific route
types can be supplied through the client's generic API contract.

## Session behavior

The client sends credentials by default. `useSession` is backed by one
Nanostores atom and refreshes after successful authentication mutations,
cross-tab session messages, reconnects, configured polling, and window focus.
Server-side construction performs no background fetch.

The Go library and `go test ./...` never execute this package. Run its gates
from `clients/` with `bun run check`.

## Frameworks

- [React](./react.md)
- [Next.js](./next-js.md)
- [Vue](./vue.md)
- [Solid](./solid.md)
