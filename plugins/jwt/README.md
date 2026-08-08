# JWT plugin

`jwt` ports the single-auth 1.6.26 asymmetric JWT plugin. It exposes the
`/token` and `/jwks` routes, server-only `signJWT` and `verifyJWT` operations,
and the `set-auth-jwt` response header on `/get-session`.

```go
auth, err := singleauth.New(singleauth.Options{
	BaseURL: "https://auth.example.com",
	Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
	PluginFactories: []singleauth.PluginFactory{
		jwt.NewFactory(jwt.Options{}),
	},
})
```

The default is EdDSA with Ed25519. `ES256`, `ES512`, `PS256`, and `RS256`
are also supported through `JWKS.KeyPair`. Private JWKs are encrypted with the
root single-auth secret configuration unless
`DisablePrivateKeyEncryption` is enabled. Secret rotation and active root
transactions are inherited automatically through `NewFactory`.

Use `SignJWT`, `VerifyJWT`, `GetJWTToken`, `CreateJWK`,
`GenerateExportedKeyPair`, and `ToExpJWT` for the corresponding server-side
helpers. Server-only endpoints are deliberately unavailable through HTTP.
