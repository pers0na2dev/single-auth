# Better Auth social providers

This package is the Go port of the built-in social-provider layer from Better
Auth `1.6.26`.

## Inventory

All supported baseline providers are implemented (Polar is intentionally out of scope):

Apple, Atlassian, Cognito, Discord, Dropbox, Facebook, Figma, GitHub, GitLab,
Google, Hugging Face, Kakao, Kick, LINE, Linear, LinkedIn, Microsoft Entra ID,
Naver, Notion, Paybin, PayPal, Railway, Reddit, Roblox, Salesforce,
Slack, Spotify, TikTok, Twitch, Twitter/X, Vercel, VK, WeChat, and Zoom.

There are no remaining built-in providers from
`packages/core/src/social-providers` in that baseline. Generic OAuth and plugin
providers are a separate plugin surface, not part of this inventory.

## Compatibility coverage

The tests freeze Better Auth-produced vectors for every authorization URL,
authorization-code request, refresh request, and normalized profile mapping.
They also cover PKCE, Basic/Post placement, redirect behavior, provider-specific
headers and bodies, opaque Facebook token binding, placeholder email rules,
JWT/JWKS verification, nonce handling, Google hosted domains, Microsoft tenant
restrictions, and PayPal subject binding. Frozen JSON provenance in `testdata`
is reviewed manually against the read-only upstream snapshot and consumed as
immutable data by native Go tests.

```sh
go test ./providers
go test -race ./providers
```
