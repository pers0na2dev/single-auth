// Package phonenumber implements the single-auth 1.6.26 phone-number plugin.
//
// The package is transport neutral. NewFactory binds the plugin to a
// single-auth instance, so the same endpoints are available through the
// direct API, net/http, fasthttp, and Fiber adapters.
package phonenumber
