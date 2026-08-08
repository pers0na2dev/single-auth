// Package saml implements transport-independent SAML 2.0 protocol primitives
// and validation used by single-auth.
//
// The package deliberately does not register authentication routes. It owns
// wire bindings, AuthnRequest construction, metadata parsing, XML signature
// verification, assertion validation, request correlation, and replay gates.
package saml
