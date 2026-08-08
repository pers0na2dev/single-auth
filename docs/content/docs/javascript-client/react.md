---
title: "React client"
description: "Subscribe to single-auth session state with React 18 or 19."
---

```tsx
import { createAuthClient } from "@pers0na2dev/single-auth/react";

const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
});

export function Account() {
  const { data, error, isPending, refetch } = authClient.useSession();

  if (isPending) return <p>Loading…</p>;
  if (error) return <button onClick={() => refetch()}>Retry</button>;
  if (!data) return <button onClick={() => authClient.signIn.social({ provider: "github" })}>Sign in</button>;
  return <p>{data.user.email}</p>;
}
```

The hook uses `useSyncExternalStore`, supports React 18 and 19, and shares the
same session atom as direct client calls. Plugin atoms become `useX` hooks.
