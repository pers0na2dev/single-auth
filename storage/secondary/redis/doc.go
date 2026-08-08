// Package redis implements reference implementation-compatible secondary storage on top of
// a small, driver-neutral Redis command interface.
//
// Store implements the single-auth SecondaryStorage contract plus the optional
// atomic GetAndDelete and rate-limit Increment methods. The caller owns the
// Redis connection and adapts its chosen client to Commander. Redis 6.2 and
// newer use GETDEL; older servers transparently fall back to an atomic Lua
// script after one capability probe.
package redis
