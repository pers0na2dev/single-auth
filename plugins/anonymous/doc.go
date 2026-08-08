// Package anonymous implements the single-auth 1.6.26 anonymous server plugin.
//
// The descriptor is transport neutral. NewFactory binds it to single-auth's
// canonical persistence, session, cookie, secondary-storage, and logging
// semantics for net/http, fasthttp, Fiber, and direct endpoint invocation.
package anonymous
