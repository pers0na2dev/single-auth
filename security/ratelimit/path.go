package ratelimit

import (
	"net/url"
	"strings"
)

// NormalizePathname strips the auth base path and trailing slashes. Like the
// upstream WHATWG URL call, it requires an absolute URL and returns "/" when
// parsing fails.
func NormalizePathname(requestURL, basePath string) string {
	parsed, err := url.Parse(requestURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "/"
	}
	pathname := parsed.EscapedPath()
	if pathname == "" {
		pathname = "/"
	}
	pathname = strings.TrimRight(pathname, "/")
	if pathname == "" {
		pathname = "/"
	}

	normalizedBase := strings.TrimRight(basePath, "/")
	if normalizedBase == "" {
		return pathname
	}
	if pathname == normalizedBase {
		return "/"
	}
	if strings.HasPrefix(pathname, normalizedBase+"/") {
		pathname = strings.TrimRight(pathname[len(normalizedBase):], "/")
		if pathname == "" {
			return "/"
		}
	}
	return pathname
}
