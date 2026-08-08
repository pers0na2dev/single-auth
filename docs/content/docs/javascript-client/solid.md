---
title: "Solid client"
description: "Expose single-auth session state as a Solid accessor."
---

```tsx
import { Show } from "solid-js";
import { createAuthClient } from "@pers0na2dev/single-auth/solid";

const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
});

export function Account() {
  const session = authClient.useSession();
  return (
    <Show when={session().data} fallback={<p>Signed out</p>}>
      {(data) => <p>{data().user.email}</p>}
    </Show>
  );
}
```

The adapter activates the shared Nanostore, reconciles updates into a Solid
store, and removes subscriptions with the current Solid owner.
