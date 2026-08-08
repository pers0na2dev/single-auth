---
title: "Rotate secrets"
description: "Stage a versioned secret rotation while accounting for formats that still use only the active key."
---

single-auth supports an ordered versioned secret ring, but rotation is not
transparent for every cookie and token format. Treat a new active key as a
planned authentication event, not merely a configuration reload.

## What the secret protects

The active secret participates in:

- signed session-token cookie values;
- compact, JWT, and JWE session-data cache values;
- OAuth state cookie binding;
- verification-email JWTs and other signed verification formats;
- the do-not-remember cookie;
- encrypted OAuth state, account data, stored OAuth access/refresh tokens, and
  plugin secrets.

Version-tagged encrypted envelopes can retain old decryption keys. Several
signed formats still verify only with the first, active secret.

## Configure an ordered ring

```go
import baCrypto "github.com/pers0na2dev/single-auth/security/crypto"

options.Secrets = []baCrypto.SecretEntry{
    {Version: 3, Value: os.Getenv("AUTH_SECRET_V3")},
    {Version: 2, Value: os.Getenv("AUTH_SECRET_V2")},
    {Version: 1, Value: os.Getenv("AUTH_SECRET_V1")},
}
```

The first entry encrypts new version-tagged values and becomes the root active
secret. Every retained entry may decrypt a supported envelope carrying its
version. Versions must be unique and their values must meet the normal secret
requirements.

The environment form is ordered and comma-separated:

```text
SINGLE_AUTH_SECRETS=3:new-value,2:previous-value,1:oldest-value
```

`Options.Secrets` takes precedence over the environment. If no ring is
configured, lookup continues through `Options.Secret`, `SINGLE_AUTH_SECRET`,
and `AUTH_SECRET`. Explicit production mode rejects the built-in development
fallback.

## Compatibility matrix

| Format or value | Can retained old ring entries decode/verify it? |
| --- | --- |
| Version-tagged encrypted OAuth state | Yes. |
| Version-tagged encrypted account-data cookie | Yes. |
| Encrypted stored OAuth access/refresh token | Yes. |
| Plugin values using host versioned encryption | Yes. |
| Signed session-token cookie | No; active secret only. |
| Session-data cookie (`compact`, `jwt`, or `jwe`) | No; active secret only. |
| Verification-email JWT | No; active secret only. |
| OAuth-state cookie binding | No; active secret only. |
| Do-not-remember cookie | No; active secret only. |

Consequently, retaining the prior secret preserves encrypted payload access but
does not preserve all active browser sessions or in-flight flows.

## Staged rotation

### 1. Inventory lifetime and impact

Record:

- session lifetime and cookie-cache lifetime;
- verification/reset/OTP lifetimes;
- maximum OAuth authorization round-trip you intend to support;
- stored encrypted OAuth token lifetime;
- every plugin using root encryption;
- whether a forced reauthentication window is acceptable.

### 2. Prepare every replica

Distribute the new value through the same secret manager as the previous keys.
Do not put values in source, command history, logs, documentation output, or
trace or log attributes. Confirm every replica can read the full ring before
changing ordering.

### 3. Activate one ordered configuration

Roll all replicas from:

```text
2:current,1:old
```

to:

```text
3:new,2:current,1:old
```

Mixed active keys cause sessions and OAuth cookie bindings issued by one
replica to fail on another. Use an atomic configuration rollout or temporarily
drain traffic so the active-key transition is coherent.

### 4. Expect signed-format invalidation

After version 3 becomes first:

- existing session-token signatures may require users to sign in again;
- session-data caches are misses/invalid and are expired or reissued;
- existing verification links signed with version 2 can fail;
- users currently at an OAuth provider can return with a binding cookie signed
  by version 2 and fail state validation;
- encrypted account/token/plugin values tagged version 2 remain decryptable.

Schedule the change for a low-risk window and make the login/error experience
explicit. Do not weaken state or cookie validation to rescue interrupted flows.

### 5. Observe and reissue

Monitor stable error codes, session-null rates, OAuth state failures, email link
failures, and decrypt errors. Reissue verification or reset messages through
their normal endpoints. Let users start a new OAuth flow rather than replaying
old state.

### 6. Retire old decryption keys

Remove a retained entry only after every version-tagged value that needs it has
expired, been refreshed, or been deliberately migrated. Stored OAuth refresh
tokens can outlive browser sessions, so session lifetime alone is not a safe
retirement bound.

Removing a key is irreversible for ciphertext that exists only under that
version. Back up configuration according to your secret-management policy and
test decryptability before retirement.

## Emergency compromise

If the active secret is exposed, prioritize containment over seamless
compatibility:

1. block the exposure path and audit access;
2. activate a new uncompromised key consistently across replicas;
3. revoke server-side sessions where the risk model requires it;
4. rotate provider/client credentials independently if they were also exposed;
5. invalidate or expire outstanding verification/state values;
6. review logs for forged or anomalous activity;
7. remove the compromised key from the retained ring once required encrypted
   data has been migrated or consciously abandoned.

Retaining a compromised key for convenience preserves an attacker's ability to
decrypt supported old envelopes. Decide that trade-off as an incident-response
action, not as a default rotation step.

## Rotation test

In a non-production environment:

1. issue a session, OAuth state, verification message, and encrypted provider
   token under version 2;
2. promote version 3 while retaining version 2;
3. verify the encrypted provider token remains readable;
4. verify the expected signed cookies/links fail or are reissued;
5. start new session/OAuth/verification flows under version 3;
6. remove version 2 and prove only intentionally retained version-2 ciphertext
   becomes unreadable.

Read [Security](../core/security.md) and
[Configuration](../getting-started/configuration.md) for exact precedence and
validation rules.
