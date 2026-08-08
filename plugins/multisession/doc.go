// Package multisession implements single-auth 1.6.26's multi-session plugin.
//
// The package is transport neutral. NewFactory binds the plugin to a root
// single-auth runtime, while New accepts an explicit Runtime for standalone
// registries and tests.
package multisession
