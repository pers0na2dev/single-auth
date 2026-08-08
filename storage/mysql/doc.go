// Package mysql implements the single-auth storage contract on top of an
// already opened database/sql handle for MySQL-compatible servers.
//
// The package deliberately imports no concrete driver. The caller owns the
// handle and its DSN. For stable date round trips, configure the selected
// driver to parse TIMESTAMP values and use the same time zone on the client and
// server (UTC is the least surprising choice). A text TIMESTAMP fallback is
// supported for drivers that return []byte, but zone-less text is interpreted
// as UTC.
//
// MySQL has no portable INSERT, UPDATE, or DELETE RETURNING form. Operations
// that must return a row therefore use a real transaction; guarded single-row
// mutations claim their target with SELECT ... FOR UPDATE before mutating it.
package mysql
