// Package passkey implements the single-auth 1.6.26 passkey server plugin.
//
// The package is transport neutral. Its endpoints are engine endpoints, so the
// same plugin works through single-auth's net/http, fasthttp, and Fiber
// adapters. Browser calls to navigator.credentials remain client concerns.
package passkey
