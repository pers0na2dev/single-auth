// Package oauthproxy ports single-auth 1.6.26's OAuth proxy plugin.
//
// It moves an OAuth authorization-code callback through a trusted production
// origin while creating the user and session only in the originating preview
// environment. State and profile payloads are authenticated encryption values,
// are bound to the original OAuth state, expire quickly, and are single-use
// whenever the configured state strategy has server-side storage.
package oauthproxy
