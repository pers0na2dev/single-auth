// Package engine implements the immutable endpoint registry, router, and
// dispatch pipeline used by single-auth transports and direct server calls.
//
// It is HTTP implementation agnostic and does not import net/http, fasthttp,
// or Fiber.
package engine
