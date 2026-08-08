// Package oauthpopup ports single-auth's popup-based OAuth handoff plugin.
//
// The server endpoint starts the normal root OAuth flow in a first-party
// popup, then replaces the callback redirect with a CSP-locked page that sends
// the signed session cookie value to the trusted opener.
package oauthpopup
