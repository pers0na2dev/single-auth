package contract

import "encoding/json"

const defaultSuccessStatus = 200

// Response is an immutable, transport-neutral response snapshot.
type Response struct {
	status  int
	headers Headers
	body    []byte
}

// IsZero reports whether the response has never been initialized. A deliberate
// 200 response created with NewResponse is not zero.
func (r Response) IsZero() bool {
	return r.status == 0 && r.headers.Len() == 0 && r.body == nil
}

// NewResponse constructs an independent response. A zero status defaults to
// 200; other values are retained so conformance tests can catch invalid output.
func NewResponse(status int, headers Headers, body []byte) Response {
	if status == 0 {
		status = defaultSuccessStatus
	}
	return Response{
		status:  status,
		headers: headers.Clone(),
		body:    cloneBytes(body),
	}
}

// TextResponse creates a UTF-8 plain-text response.
func TextResponse(status int, body string) Response {
	headers := NewHeaders(HeaderField{
		Name:  "Content-Type",
		Value: "text/plain; charset=utf-8",
	})
	return NewResponse(status, headers, []byte(body))
}

// JSONResponse encodes value as JSON and creates an application/json response.
func JSONResponse(status int, value any) (Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return Response{}, err
	}
	headers := NewHeaders(HeaderField{
		Name:  "Content-Type",
		Value: "application/json; charset=utf-8",
	})
	return NewResponse(status, headers, body), nil
}

// Status returns the numeric status code.
func (r Response) Status() int {
	if r.status == 0 {
		return defaultSuccessStatus
	}
	return r.status
}

// Headers returns an independent copy of all response header lines.
func (r Response) Headers() Headers { return r.headers.Clone() }

// Body returns an independent copy of the response body.
func (r Response) Body() []byte { return cloneBytes(r.body) }

// Clone returns an independent response snapshot.
func (r Response) Clone() Response {
	return NewResponse(r.Status(), r.headers, r.body)
}

// WithStatus returns a copy carrying status.
func (r Response) WithStatus(status int) Response {
	clone := r.Clone()
	if status == 0 {
		status = defaultSuccessStatus
	}
	clone.status = status
	return clone
}

// WithHeaders returns a copy carrying an independent replacement collection.
func (r Response) WithHeaders(headers Headers) Response {
	clone := r.Clone()
	clone.headers = headers.Clone()
	return clone
}

// WithHeader returns a copy with every existing field of name replaced.
func (r Response) WithHeader(name, value string) Response {
	clone := r.Clone()
	clone.headers.Set(name, value)
	return clone
}

// WithAddedHeader returns a copy with one appended header line.
func (r Response) WithAddedHeader(name, value string) Response {
	clone := r.Clone()
	clone.headers.Add(name, value)
	return clone
}

// WithMergedHeaders returns a copy with src overlaid using response-header
// semantics. Set-Cookie appends; other names replace.
func (r Response) WithMergedHeaders(src Headers) Response {
	clone := r.Clone()
	clone.headers.MergeResponse(src)
	return clone
}

// WithBody returns a copy carrying an independent body.
func (r Response) WithBody(body []byte) Response {
	clone := r.Clone()
	clone.body = cloneBytes(body)
	return clone
}
