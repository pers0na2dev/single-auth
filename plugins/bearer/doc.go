// Package bearer implements the single-auth 1.6.26 bearer server plugin.
//
// A valid Authorization bearer value is converted into the configured signed
// session cookie before endpoint execution. Session cookies written by an
// endpoint are exposed as Set-Auth-Token after execution.
package bearer
