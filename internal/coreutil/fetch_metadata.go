package coreutil

import "net/http"

// IsBrowserFetchRequest reports whether Fetch Metadata identifies a CORS
// browser fetch. Header.Get preserves the case-insensitive Headers.get
// behavior of the the reference implementation implementation.
func IsBrowserFetchRequest(headers http.Header) bool {
	return headers != nil && headers.Get("Sec-Fetch-Mode") == "cors"
}
