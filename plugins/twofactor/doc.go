// Package twofactor implements the single-auth 1.6.26 two-factor plugin for
// single-auth.
//
// It provides TOTP enrollment and verification, emailed or otherwise delivered
// OTP challenges, single-use backup codes, trusted devices, per-challenge
// attempt caps, account-level lockout, passwordless-account management, custom
// storage codecs and schema aliases. NewFactory binds it to the root Auth
// runtime so the same behavior is available through direct calls, net/http,
// fasthttp and Fiber.
package twofactor
