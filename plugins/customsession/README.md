# custom-session

Go port of single-auth 1.6.26's `custom-session` server plugin.

The plugin replaces `getSession` with a caller-defined projection while using
the core session implementation for token authority, refresh, public field
serialization, cookie cache, and response headers. Set-Cookie values are parsed
and re-emitted as independent header lines so refreshed session cookies retain
their own attributes and are never percent-encoded twice.

Set `ShouldMutateListDeviceSessionsEndpoint` to apply the same projection to
each value returned by single-auth's multi-session device-list endpoint.
