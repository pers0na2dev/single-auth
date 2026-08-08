// Package captcha implements the single-auth 1.6.26 CAPTCHA request plugin.
//
// Verification runs in the HTTP-only onRequest stage. Direct endpoint calls
// intentionally bypass it, matching single-auth's direct API contract.
package captcha
