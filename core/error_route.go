package core

import (
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

var safeErrorCode = regexp.MustCompile(`^['A-Za-z0-9_-]+$`)

func (a *Auth) errorPage(ctx *engine.Context) (contract.Response, error) {
	query, _ := ctx.Request().Query()
	code := query.Get("error")
	if code == "" {
		code = "UNKNOWN"
	}
	if !safeErrorCode.MatchString(code) {
		code = "UNKNOWN"
	}
	description := query.Get("error_description")
	redirectQuery := url.Values{"error": []string{code}}
	if description != "" {
		redirectQuery.Set("error_description", description)
	}
	if a.options.OnAPIError.ErrorURL != "" {
		separator := "?"
		if strings.Contains(a.options.OnAPIError.ErrorURL, "?") {
			separator = "&"
		}
		return redirectResponse(a.options.OnAPIError.ErrorURL + separator + redirectQuery.Encode()), nil
	}
	if strings.EqualFold(a.options.Environment, "production") && !a.options.OnAPIError.CustomizeDefaultErrorPage {
		return redirectResponse("/?" + redirectQuery.Encode()), nil
	}
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` +
		html.EscapeString(code) + ` | ` + html.EscapeString(a.options.AppName) +
		`</title><style>body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;display:grid;min-height:100vh;place-items:center;background:#fff;color:#111}.error{max-width:42rem;padding:2rem;border:2px solid #111}.code{font-weight:700;letter-spacing:.08em}.description{margin-top:1rem;white-space:pre-wrap}</style></head><body><main class="error"><div class="code">` +
		html.EscapeString(code) + `</div>`
	if description != "" {
		body += `<div class="description">` + html.EscapeString(description) + `</div>`
	}
	body += `</main></body></html>`
	return contract.NewResponse(
		contract.StatusOK,
		contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "text/html"}),
		[]byte(body),
	), nil
}
