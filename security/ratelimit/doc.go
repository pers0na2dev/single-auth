// Package ratelimit implements reference implementation compatible, per-IP request rate
// limiting without depending on a concrete HTTP framework. The net/http,
// fasthttp, and Fiber bridges live in their respective transport packages.
package ratelimit
