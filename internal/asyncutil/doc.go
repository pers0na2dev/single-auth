// Package asyncutil provides bounded, order-preserving concurrent mapping.
//
// Its MapConcurrent contract mirrors the reference implementation's mapConcurrent utility while
// using context.Context for cancellation and Go errors for mapper rejection.
package asyncutil
