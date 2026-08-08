---
title: "OpenAPI"
description: "Generate an OpenAPI 3.1 document and optional Scalar reference from the finalized native Go endpoint registry."
---

OpenAPI generates a fresh OpenAPI 3.1 document from the finalized endpoint registry and composed storage schema. It can also serve that document through a Scalar browser reference.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/openapi` and use `NewFactory`. Endpoint enumeration is lazy: every factory is built before the registry is finalized, so OpenAPI does **not** need to be the last factory to include other plugin endpoints. Ordering matters only if another plugin intentionally transforms these routes or their responses.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/openapi"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            openapi.NewFactory(openapi.Options{
                Path:  "/reference",
                Theme: "default",
                Nonce: os.Getenv("CSP_NONCE"),
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

All paths are relative to the auth `BasePath` (`/api/auth` by default). The example serves JSON at `/api/auth/open-api/generate-schema` and Scalar at `/api/auth/reference`.

## Routes

| Method | Path | Content | Default authority |
| --- | --- | --- | --- |
| GET | `/open-api/generate-schema` | JSON `openapi.Document` | Public |
| GET | Configured `Path`, `/reference` by default | `text/html` Scalar reference | Public; returns 404 when `DisableDefaultReference` is true |

The two OpenAPI-owned endpoints mark themselves hidden and are excluded from the generated document. `DisableDefaultReference` does not unregister the reference route and does not disable JSON generation; it makes only the reference handler return `404 NOT_FOUND`.

Fetch the schema directly:

```bash
curl --fail-with-body \
  https://auth.example.com/api/auth/open-api/generate-schema
```

The schema route and browser reference do not authenticate themselves. Put explicit outer middleware/access policy in front of them when endpoint and model inventory is private. OpenAPI security declarations are documentation only; they do not enforce access to either the documentation or described auth routes.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `Path` | `/reference` | Scalar reference route relative to auth base path; must begin with `/` |
| `DisableDefaultReference` | `false` | Return 404 from the reference handler while keeping JSON schema generation |
| `Theme` | `default` | Passed to Scalar's browser configuration |
| `Nonce` | Empty | Added to the inline configuration script and external Scalar script |

An invalid `Path` fails startup. A path that collides with another registered endpoint fails normal registry construction. `Theme` and `Nonce` are inserted into HTML configuration; use trusted constant configuration values, never request-controlled strings.

The exported `Runtime` and `New(options, runtime)` support standalone embedding. `NewFactory` normally supplies the final schema, lazy endpoint list, dynamic base-URL resolver, configured `BaseURL`, and `DisabledPaths`.

## Generated document

Each request returns a new document with:

- OpenAPI version `3.1.1`.
- Fixed info title `single-auth`, description, and compatibility document version `1.1.0`.
- A server URL resolved from the live request/root proxy configuration, including the auth base path.
- Component schemas generated from the complete core and plugin-composed storage schema.
- Static `apiKeyCookie` and HTTP `bearerAuth` security-scheme descriptions.
- A frozen 1.6.26 catalog for detailed core route inputs/results, plus metadata-derived operations for other registered endpoints.
- Standard generated error responses for statuses 400, 401, 403, 404, 429, and 500 on metadata-derived operations.

The static security objects describe possible auth shapes; they do not guarantee that every operation uses both schemes, and `apiKeyCookie` is a documentation identifier rather than discovery of a custom runtime cookie name. Consult each endpoint's actual authority contract.

### Included and excluded endpoints

Generation enumerates the live finalized registry at request time. An endpoint is omitted when it:

- is marked `ServerOnly`;
- has an empty path;
- appears in root `DisabledPaths` by exact declared path;
- is one of the two OpenAPI-owned endpoints; or
- carries `openapi.Metadata{Hidden:true}`.

Only `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` operations are emitted. Route parameters such as `:id` become `{id}` and receive required string path parameters. If operation IDs collide, the later operation receives a method suffix such as `Post`, then a numeric suffix if needed.

The embedded core catalog is consulted only for a route/method that exists in the live registry; it cannot resurrect a disabled or unregistered endpoint. Plugin/custom endpoints without catalog entries receive metadata-derived operations.

### Model schemas and additional user fields

The generator converts storage field types into OpenAPI schemas, including date-time, JSON records, arrays, enums, defaults, and read-only ownership. Every model includes a read-only string `id`. Canonical model/field names appear in the document even when storage uses physical aliases.

Writable non-core user fields are merged into `/sign-up/email` and `/update-user` request bodies. On sign-up, a field is required only when its storage field is required and has no default. On update, those additional fields remain optional. Server-managed fields are marked read-only rather than accepted as client input.

The generated schema describes configured model shapes and may include sensitive internal field names. It does not change runtime serialization or input filtering.

## Document custom endpoints

Attach metadata to an `engine.Endpoint` with `openapi.WithMetadata`:

```go
body := openapi.Object(
    openapi.Prop("name", openapi.String().Min(1).Max(100)),
    openapi.Prop("enabled", openapi.Boolean().Optional()),
)

endpoint := openapi.WithMetadata(engine.Endpoint{
    Name:        "createWidget",
    Path:        "/widgets/:id",
    Methods:     []string{http.MethodPost},
    OperationID: "createWidget",
    Handler:     createWidget,
}, openapi.Metadata{
    Tags:        []string{"Widgets"},
    OperationID: "createWidget",
    Description: "Create a widget for an account.",
    Body:        openapi.InputRef(body),
})
```

`Metadata` supports:

| Field | Behavior for metadata-derived operations |
| --- | --- |
| `Tags`, `OperationID`, `Description` | Operation presentation and stable identifier |
| `Parameters` | Explicit parameter list |
| `Query` | An object input whose properties become query parameters when `Parameters` is nil |
| `Body` | Input DSL converted to an `application/json` request body |
| `RequestBody` | Fully authored request body; takes precedence over `Body` |
| `Responses` | Status responses merged over the standard generated error responses; add an explicit 2xx response |
| `Hidden` | Excludes the endpoint from the document |

For custom routes, `WithMetadata` preserves unrelated endpoint metadata and copies the method slice/map wrapper. Metadata is a documentation contract only; runtime handlers must validate the same shape independently.

POST, PUT, and PATCH operations get a JSON request body. Without body metadata, it is an optional empty object. GET and DELETE do not receive an inferred body. Path parameters are appended even when no metadata is provided.

## Input schema DSL

The package's `Input` constructors model the request shapes used by the native endpoint registry:

| Constructors | OpenAPI output |
| --- | --- |
| `Any`, `String`, `Number`, `Boolean`, `Null`, `Undefined` | Scalar/empty schemas |
| `Object(Prop(...))` | Object properties; fields that do not accept undefined are required |
| `Record(key, value)` | Object `propertyNames` and `additionalProperties` |
| `Array(item)` | Array items |
| `Literal(value)`, `Enum(values...)` | Enum-constrained values |
| `Union(...)`, `ExclusiveUnion(...)` | `anyOf` or `oneOf`; undefined branches are omitted |
| `Intersection(left, right)` | Compatible objects merge; incompatible shapes use `allOf` |

Chainable wrappers and annotations are `Optional`, `Nullable`, `Default`, `DefaultFactory`, `Prefault`, `NonOptional`, `Describe`, `Min`, and `Max`. Nullable scalar/object types use the OpenAPI 3.1 null type. Default/prefault wrappers affect undefined/required semantics but do not execute default factories or expose runtime-generated values while documenting. `Min` and `Max` currently describe string length.

`InputRef(value)` returns an independent pointer for `Metadata.Query` or `Metadata.Body`. `OpenAPISchema()` exposes standalone conversion, and `AcceptsUndefined()` exposes the same wrapper-aware body optionality decision used by generation.

For schemas beyond the DSL, author `Parameter`, `RequestBody`, `Response`, `MediaType`, and `Schema` values directly. `Schema.Type` accepts a string or string slice because OpenAPI 3.1 represents nullable types as unions.

## Direct generation

Trusted code can call the registered JSON operation directly:

```go
result, err := auth.API().Call(ctx, "generateOpenAPISchema", singleauth.DirectCallInput{
    Method: http.MethodGet,
    Scheme: "https",
    Host:   "auth.example.com",
})
```

The direct result contains the normal JSON response.

For typed in-process generation, construct `openapi.NewGenerator(openapi.GeneratorOptions{...})` and call `Generate(request)`, which returns `openapi.Document`. The generator snapshots schema/disabled paths, lazily calls `ListEndpoints` on each generation, and is safe for concurrent use when callbacks are safe.

The JSON route, Scalar route, direct API, `net/http`, direct `fasthttp`, and Fiber share the same generator behavior. Base-URL resolution uses request/proxy context; verify it behind your ingress with [Deploy behind a proxy](../guides/deploy-behind-a-proxy.md).

## Storage, lifecycle, and errors

OpenAPI contributes no storage model, database hook, or migration. It documents the composed schema but never creates or updates database objects.

There is no document cache: endpoint enumeration, base-URL resolution, model conversion, and embedded catalog decoding happen for each request. If the route is exposed at high volume, cache its successful response in trusted outer infrastructure while varying or normalizing the server URL appropriately.

Construction fails for a relative reference path, missing standalone endpoint callback, or invalid storage schema. At request time, base-URL resolution or document/HTML encoding failures follow the normal endpoint error path. A disabled reference has the stable `404 NOT_FOUND` response; schema generation remains available.

## Scalar, CSP, and disclosure security

The reference page embeds the generated document, one inline configuration script, and an external script from `https://cdn.jsdelivr.net/npm/@scalar/api-reference`. It is not a self-contained/offline asset and does not pin a Scalar version or include subresource integrity.

- Allow the Scalar CDN in browser/network policy, or disable the default reference and render the JSON document in infrastructure you control.
- `Nonce` is a static option applied verbatim to both executable script tags. Rotate/per-response nonce generation is not built into this option; if your CSP requires unique nonces, serve a custom reference page around the JSON route.
- Never derive `Theme` or `Nonce` from request input. They are interpolated into HTML rather than validated as a theme enum or escaped as arbitrary text.
- The JSON and reference routes disclose route names, parameter/body shapes, error responses, server URL, and composed model fields. Protect or disable them according to your threat model.
- Generated security declarations do not enforce runtime authentication. Keep each auth endpoint's session, permission, origin, and rate-limit checks configured independently.

If the document is missing a route, check `ServerOnly`, `DisabledPaths`, `Hidden`, empty paths, and supported HTTP methods. If a custom operation has only error responses, add an explicit 2xx `Metadata.Responses` entry. If `servers[0].url` is wrong behind a proxy, fix trusted forwarded-host/proto handling rather than hard-coding untrusted request headers.

See [Write a server plugin](../guides/write-a-server-plugin.md), [Security](../core/security.md), [Schemas](../storage/schemas.md), and the [OpenAPI package reference](../reference/packages/plugins--openapi.md).

**Status:** implemented with core-catalog parity, composed schemas, custom metadata/input DSL, lazy registry generation, Scalar rendering, direct generation, and all Go transport coverage.
