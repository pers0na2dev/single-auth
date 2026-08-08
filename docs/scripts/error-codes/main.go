package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
	checkOnly := flag.Bool("check", false, "verify that the checked-in core error catalog is current")
	flag.Parse()

	root, err := os.Getwd()
	check(err)
	page, count := renderErrorCodes()
	path := filepath.Join(root, "docs", "content", "docs", "reference", "error-codes.md")
	if *checkOnly {
		actual, readErr := os.ReadFile(path)
		check(readErr)
		if string(actual) != page {
			panic("core error-code reference is stale; run go run ./docs/scripts/error-codes")
		}
		fmt.Printf("verified %d core error codes\n", count)
		return
	}
	check(os.WriteFile(path, []byte(page), 0o644))
	fmt.Printf("generated %d core error codes\n", count)
}

func renderErrorCodes() (string, int) {
	codes := make([]string, 0, len(singleauth.BaseErrorMessages))
	for code := range singleauth.BaseErrorMessages {
		codes = append(codes, string(code))
	}
	sort.Strings(codes)

	var rows strings.Builder
	for _, code := range codes {
		message := singleauth.BaseErrorMessages[singleauth.ErrorCode(code)]
		rows.WriteString(fmt.Sprintf("| `%s` | %s |\n", code, escapeTable(message)))
	}

	page := `---
title: "Error handling and core codes"
---

Typed API errors, stable HTTP bodies, redaction, protocol-specific bodies, and the complete core error catalog.

HTTP transports and the direct API share ` + "`contract.APIError`" + `. It carries an HTTP status, stable code, public message, response headers, optional protocol wire body, and a server-only wrapped cause.

## Default wire shape

~~~json
{
  "code": "INVALID_EMAIL_OR_PASSWORD",
  "message": "Invalid email or password"
}
~~~

Unknown Go errors are redacted to status 500, code ` + "`INTERNAL_SERVER_ERROR`" + `, and message ` + "`Internal Server Error`" + `. The wrapped cause remains available to server logs and ` + "`errors.Is`" + `/` + "`errors.As`" + ` but is never serialized.

~~~go
result, err := auth.API().GetSession(ctx, input)
if err != nil {
    if apiErr, ok := contract.AsAPIError(err); ok {
        log.Printf("auth failure status=%d code=%s cause=%v",
            apiErr.Status, apiErr.Code, apiErr.Cause)
        return apiErr
    }
    return err
}
~~~

Do not return ` + "`Cause`" + ` to callers. It may contain database, cryptographic, provider, or network details.

## Protocol-specific errors

` + "`APIError.WireBody`" + ` lets protocol endpoints retain typed status/code/message while emitting their standard JSON shape, such as OAuth 2.0 ` + "`{\"error\",\"error_description\"}`" + `. SAML exposes stable ` + "`saml.Error`" + `/` + "`saml.APIError`" + ` codes. SCIM and OAuth plugins use protocol-specific bodies where their specifications require them.

Plugin packages define additional error constants near their handlers and list relevant failures on their individual documentation pages. The table below is the complete root/core catalog.

## Core error catalog

The endpoint determines the HTTP status for a code; the same semantic code can be used in more than one route context.

| Code | Default public message |
| --- | --- |
` + rows.String() + `

## Custom API errors

~~~go
err := contract.NewAPIError(
    contract.StatusForbidden,
    "ACCOUNT_SUSPENDED",
    "This account is suspended",
).WithHeaders(contract.NewHeaders(
    contract.HeaderField{Name: "Retry-After", Value: "3600"},
)).WithCause(internalCause)
~~~

` + "`WithCause`" + `, ` + "`WithHeaders`" + `, and ` + "`WithWireBody`" + ` return independent copies. ` + "`contract.ResponseFromError`" + ` performs the final stable conversion to a transport-neutral response.
`
	return page, len(codes)
}

func escapeTable(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
