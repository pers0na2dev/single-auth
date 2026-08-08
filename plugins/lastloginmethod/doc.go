// Package lastloginmethod implements single-auth 1.6.26's
// last-login-method plugin.
//
// The plugin is transport-neutral. NewFactory binds it to the root auth
// runtime, so the same descriptor observes sessions issued through direct
// calls, net/http, fasthttp, and Fiber. Database persistence is installed
// through the root database-hook registry before user-defined hooks.
package lastloginmethod
