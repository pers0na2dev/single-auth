---
title: "Protocols"
---

OAuth 2.0, OpenID Connect, SAML 2.0, WebAuthn, and SCIM building blocks and server plugins.

`single-auth` separates transport-neutral protocol packages from stateful auth plugins. The low-level packages are useful for custom integrations; the plugins add routes, persistence, account linking, sessions, policy, and lifecycle hooks.

| Protocol | Low-level package | Stateful server feature |
| --- | --- | --- |
| OAuth 2.0 client | `github.com/pers0na2dev/single-auth/protocol/oauth2`, `github.com/pers0na2dev/single-auth/protocol/providers` | Core social sign-in and Generic OAuth plugin |
| OAuth 2.0 authorization server | Protocol helpers inside the plugin | [OAuth Provider](../plugins/oauth-provider.md) |
| OpenID Connect provider | JWT/JWKS and OAuth server primitives | [OAuth Provider](../plugins/oauth-provider.md); deprecated [OIDC Provider](../plugins/oidc-provider.md) |
| OpenID Connect relying party | `oauth2` and configured social providers | [SSO](../plugins/sso.md) and [Generic OAuth](../plugins/generic-oauth.md) |
| SAML 2.0 service provider | `github.com/pers0na2dev/single-auth/protocol/saml` | [SSO](../plugins/sso.md) |
| WebAuthn | `github.com/pers0na2dev/single-auth/protocol/webauthn` | [Passkey](../plugins/passkey.md) |
| SCIM 2.0 | Plugin-specific protocol implementation | [SCIM](../plugins/scim.md) |

## Choose the highest useful layer

Use the core social routes or a plugin when you want authentication behavior. Use a low-level protocol package only when you are deliberately building a custom provider, framework adapter, identity gateway, or protocol test harness.

The distinction matters because low-level calls do not automatically perform:

- trusted-origin, CSRF, or OAuth state checks;
- rate limiting;
- database transactions and hooks;
- user/account creation or account-linking policy;
- session cookie creation and rotation;
- plugin route conflict detection;
- audit logging or application redirects.

- [OAuth 2.0 client primitives](./oauth2-client-primitives.md)
- [OAuth and OIDC server](./oauth-and-oidc-server.md)
- [SAML 2.0](./saml.md)
- [WebAuthn](./webauthn.md)
- [SCIM](./scim.md)
- [Security boundaries](./security-boundaries.md)
