# twofactor

Go port of the single-auth `two-factor` plugin frozen at `1.6.26`.

```go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://example.com",
    Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
    EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
    PluginFactories: []singleauth.PluginFactory{
        twofactor.NewFactory(twofactor.Options{
            OTP: twofactor.OTPOptions{
                SendOTP: func(ctx context.Context, message twofactor.OTPMessage, _ *engine.Context) error {
                    return mailer.Send(ctx, message.User["email"].(string), message.OTP)
                },
            },
        }),
    },
})
```

`auth` implements `net/http.Handler`. The same dispatcher is accepted by
`transport/fasthttp.NewHandler(auth.Dispatcher())` and
`transport/fiber.NewHandler(auth.Dispatcher())`.

Implemented compatibility surface:

- TOTP setup, URI generation, 6/8 digit verification and the upstream ±1 period window;
- out-of-band OTP with plain, SHA-256, encrypted and custom storage;
- encrypted-by-default backup codes, custom generators/codecs and atomic single use;
- trusted-device signed cookies with server-side records, expiry, rotation and revocation;
- single-use 10-minute sign-in challenges, five-guess challenge caps and cross-factor account lockout;
- passwordless-account management without weakening password checks for credential accounts;
- custom table/field mappings, direct-only server operations and client path metadata;
- raw response cookie scrubbing for email, username and phone credential sign-in;
- direct, `net/http`, `fasthttp` and Fiber transport coverage.

Frozen source provenance and all 83 exact upstream manifest IDs live in
`testdata/reference-1.6.26-oracle.json`. The file is reviewed manually against
the read-only upstream snapshot and consumed as data by native Go tests.

```sh
go test ./plugins/twofactor
go test -race ./plugins/twofactor
```
