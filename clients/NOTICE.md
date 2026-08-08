# Attribution

Parts of the client runtime and the React, Vue, and Solid reactive adapters are
derived from Better Auth 1.6.26, preserved in `better-auth-main/`, under the MIT
License. Copyright (c) 2024-present Bereket Engida.

The code is adapted to call the native `single-auth` Go HTTP API and does not
depend on the Better Auth JavaScript server runtime. The Next.js remote proxy
and server-session helpers are single-auth-specific replacements for Better
Auth's in-process TypeScript server plugin integration.
