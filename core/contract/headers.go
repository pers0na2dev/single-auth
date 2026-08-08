package contract

import "strings"

// HeaderField is one header line. Repeated fields are represented by repeated
// entries rather than by comma-joining their values.
type HeaderField struct {
	Name  string
	Value string
}

// Headers is an ordered, case-insensitive, multi-value header collection.
//
// Its zero value is ready for use. Copying a Headers value directly aliases
// its backing storage; use Clone when the copy may be mutated independently.
// Request and Response accessors always return independent clones.
type Headers struct {
	fields []HeaderField
}

// NewHeaders constructs an ordered header collection. Empty field names are
// ignored because they cannot be represented by any supported HTTP transport.
func NewHeaders(fields ...HeaderField) Headers {
	h := Headers{}
	for _, field := range fields {
		h.Add(field.Name, field.Value)
	}
	return h
}

// Len returns the number of header lines, including repeated fields.
func (h Headers) Len() int {
	return len(h.fields)
}

// Fields returns an independent copy in wire order.
func (h Headers) Fields() []HeaderField {
	if len(h.fields) == 0 {
		return nil
	}
	fields := make([]HeaderField, len(h.fields))
	copy(fields, h.fields)
	return fields
}

// Clone returns an independently mutable copy.
func (h Headers) Clone() Headers {
	return Headers{fields: h.Fields()}
}

// Has reports whether at least one field with name exists.
func (h Headers) Has(name string) bool {
	_, ok := h.Get(name)
	return ok
}

// Get returns the first value for name. It deliberately does not comma-join
// repeated values: callers that need all values must use Values. This is
// particularly important for Set-Cookie, whose values are never joinable.
func (h Headers) Get(name string) (string, bool) {
	for _, field := range h.fields {
		if strings.EqualFold(field.Name, name) {
			return field.Value, true
		}
	}
	return "", false
}

// Values returns all values for name in wire order.
func (h Headers) Values(name string) []string {
	var values []string
	for _, field := range h.fields {
		if strings.EqualFold(field.Name, name) {
			values = append(values, field.Value)
		}
	}
	return values
}

// Add appends a header line. Empty field names are ignored.
func (h *Headers) Add(name, value string) {
	if h == nil || name == "" {
		return
	}
	h.fields = append(h.fields, HeaderField{Name: name, Value: value})
}

// Set replaces every existing field with name by one field appended at the
// position where this mutation occurs.
func (h *Headers) Set(name, value string) {
	if h == nil || name == "" {
		return
	}
	h.Delete(name)
	h.Add(name, value)
}

// Delete removes every field with name.
func (h *Headers) Delete(name string) {
	if h == nil || len(h.fields) == 0 {
		return
	}
	kept := h.fields[:0]
	for _, field := range h.fields {
		if !strings.EqualFold(field.Name, name) {
			kept = append(kept, field)
		}
	}
	h.fields = kept
}

// MergeResponse overlays src using the reference implementation response semantics: every
// Set-Cookie line is appended, while all other names replace their previous
// values. Repeated non-cookie values from src remain repeated and ordered.
func (h *Headers) MergeResponse(src Headers) {
	if h == nil || src.Len() == 0 {
		return
	}

	seen := make([]string, 0, src.Len())
	for _, field := range src.fields {
		if strings.EqualFold(field.Name, "Set-Cookie") {
			h.Add(field.Name, field.Value)
			continue
		}

		alreadySeen := false
		for _, name := range seen {
			if strings.EqualFold(name, field.Name) {
				alreadySeen = true
				break
			}
		}
		if !alreadySeen {
			h.Delete(field.Name)
			seen = append(seen, field.Name)
		}
		h.Add(field.Name, field.Value)
	}
}
