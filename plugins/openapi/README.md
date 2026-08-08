# OpenAPI plugin

`plugins/openapi` implements single-auth 1.6.26's OpenAPI 3.1 generator and
Scalar reference page. It enumerates the finalized single-auth registry at
request time and derives model components from the merged storage schema.

Register `openapi.NewFactory(openapi.Options{})` in `Options.PluginFactories`.
The plugin exposes `generateOpenAPISchema` directly and serves
`GET /open-api/generate-schema` plus `GET /reference` through net/http,
fasthttp, and Fiber. `Options` supports a custom reference path, Scalar theme,
CSP nonce, and disabling the reference page.

Custom endpoints can attach `openapi.Metadata` with `openapi.WithMetadata`.
The public `Input` constructors preserve single-auth's optional, default,
prefault, nullable, non-optional, object, record, union, and intersection
semantics without evaluating default factories during schema generation.
