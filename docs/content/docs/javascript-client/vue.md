---
title: "Vue client"
description: "Use readonly reactive single-auth session state in Vue and Nuxt."
---

```ts
import { createAuthClient } from "@pers0na2dev/single-auth/vue";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
});
```

```vue
<script setup lang="ts">
import { authClient } from "~/lib/auth-client";

const session = authClient.useSession();
</script>

<template>
  <p v-if="session.isPending">Loading…</p>
  <p v-else-if="session.data">{{ session.data.user.email }}</p>
</template>
```

`useSession()` returns a readonly Vue ref and unsubscribes with the active Vue
scope. In Nuxt, `await authClient.useSession(useFetch)` uses Nuxt's
request-aware fetch path and reacts to the same session signal.
