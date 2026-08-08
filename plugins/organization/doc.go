// Package organization implements the single-auth 1.6.26 organization plugin.
//
// The package is transport neutral. A bound Plugin exposes the same create
// operation to HTTP/direct dispatch and to database hooks, while keeping the
// organization and initial owner membership in one storage transaction.
package organization
