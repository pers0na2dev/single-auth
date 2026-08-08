// Package mcp implements the single-auth 1.6.26 MCP OAuth authorization
// server plugin.
//
// The server surface is transport neutral and therefore works through the
// root net/http handler as well as the fasthttp and Fiber adapters.
package mcp
