# additionalfields

Server-side port of single-auth `1.6.26` additional fields.

```go
factory := additionalfields.NewFactory(additionalfields.Options{
    User: additionalfields.Fields{
        {
            Name: "role",
            Attribute: storage.FieldAttribute{
                Type:         storage.FieldString,
                Input:        storage.Bool(false),
                DefaultValue: storage.StaticValue("user"),
            },
        },
    },
})

auth := singleauth.MustNew(singleauth.Options{
    PluginFactories: []singleauth.PluginFactory{factory},
})
```

`Fields` is a slice rather than a map so the first validation/default failure
follows JavaScript property declaration order.

## Runtime boundary

single-auth implements this feature across its core rather than as a standalone
server plugin. In the Go port, the package owns:

- additional user, session, account, and verification schema composition;
- create/update parsing for `signUpEmail`, `updateUser`, and `updateSession`;
- sync Standard-Schema-style validation and exact single-auth error codes;
- defaults, provider-profile filtering, output filtering, and synthetic-user
  helpers through `Compile` / `Processor`.

`NewFactory` contributes the schema before root constructs its adapter and
binds the processor to the final host clock. `New` / `MustNew` remain available
for manual `engine.Plugin` composition.

The root auth runtime owns the adapter, database hooks, cookies, cookie cache,
and secondary storage. It consumes `plugin.Schema`, so adapters apply field
aliases/defaults/input-output transforms and root session code persists and
refreshes all additional fields in secondary storage. No adapter or secondary
store is injected twice into this plugin.

Code that creates or updates base models outside the built-in endpoints should
keep the `Processor` returned by `Compile` and call `ParseInput`,
`ParseProviderUserInput`, `SessionDefaults`, or `FilterOutput` at the same
boundary. `validator.output` is retained but is not automatically executed,
matching single-auth `1.6.26`; `ValidateOutput` is an explicit opt-in helper.

The descriptor and hooks use `contract.Request`, `contract.Response`, and
`engine.Context` only. The same plugin instance therefore works through
`net/http`, direct fasthttp, and Fiber's fasthttp bridge.
