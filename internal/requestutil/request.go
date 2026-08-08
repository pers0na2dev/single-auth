// Package requestutil contains request helpers compatible with the reference implementation.
package requestutil

import "net/http"

// SafeCloneRequest clones request and falls back to a distinct, bodyless copy
// if the clone operation panics. This mirrors the reference implementation's defensive fallback
// for consumed or otherwise unusable Fetch API requests.
func SafeCloneRequest(request *http.Request) *http.Request {
	return safeCloneRequestWith(request, func(source *http.Request) *http.Request {
		return source.Clone(source.Context())
	})
}

func safeCloneRequestWith(request *http.Request, clone func(*http.Request) *http.Request) (result *http.Request) {
	if request == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			result = bodylessRequestCopy(request)
		}
	}()
	return clone(request)
}

func bodylessRequestCopy(request *http.Request) *http.Request {
	result := new(http.Request)
	*result = *request
	if request.URL != nil {
		urlCopy := *request.URL
		result.URL = &urlCopy
	}
	result.Header = request.Header.Clone()
	result.Trailer = request.Trailer.Clone()
	result.TransferEncoding = append([]string(nil), request.TransferEncoding...)
	result.Body = http.NoBody
	result.GetBody = nil
	result.ContentLength = 0
	return result
}
