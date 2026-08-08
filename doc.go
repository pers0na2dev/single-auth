// Package singleauth is the application-facing facade for the native Go
// authentication runtime. Its API is generated from package core so the root
// import remains concise while implementation files stay logically grouped.
//
//go:generate go run ./internal/cmd/facadegen -core ./core -output ./facade_gen.go
package singleauth
