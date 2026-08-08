package oauth2

import (
	"strings"
)

// Param is one ordered application/x-www-form-urlencoded entry.
type Param struct {
	Name  string
	Value string
}

// Form mirrors URLSearchParams ordering, Set, Append, Has and Get semantics.
type Form struct {
	params []Param
}

// NewForm creates an empty ordered form.
func NewForm() *Form { return &Form{} }

// Params returns a defensive copy.
func (f *Form) Params() []Param { return append([]Param(nil), f.params...) }

// Append appends even when the name already exists.
func (f *Form) Append(name, value string) {
	f.params = append(f.params, Param{Name: name, Value: value})
}

// Set replaces the first value, removes later duplicates, or appends.
func (f *Form) Set(name, value string) {
	first := -1
	result := make([]Param, 0, len(f.params)+1)
	for _, param := range f.params {
		if param.Name != name {
			result = append(result, param)
			continue
		}
		if first < 0 {
			first = len(result)
			result = append(result, Param{Name: name, Value: value})
		}
	}
	if first < 0 {
		result = append(result, Param{Name: name, Value: value})
	}
	f.params = result
}

// Has reports whether a name exists.
func (f *Form) Has(name string) bool {
	for _, param := range f.params {
		if param.Name == name {
			return true
		}
	}
	return false
}

// Get returns the first value.
func (f *Form) Get(name string) (string, bool) {
	for _, param := range f.params {
		if param.Name == name {
			return param.Value, true
		}
	}
	return "", false
}

// Values returns every value in insertion order.
func (f *Form) Values(name string) []string {
	values := make([]string, 0)
	for _, param := range f.params {
		if param.Name == name {
			values = append(values, param.Value)
		}
	}
	return values
}

// Encode follows the WHATWG URLSearchParams form encoding set.
func (f *Form) Encode() string {
	parts := make([]string, 0, len(f.params))
	for _, param := range f.params {
		parts = append(parts, encodeFormComponent(param.Name)+"="+encodeFormComponent(param.Value))
	}
	return strings.Join(parts, "&")
}

func encodeFormComponent(value string) string {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '*' || b == '-' || b == '.' || b == '_' {
			builder.WriteByte(b)
			continue
		}
		if b == ' ' {
			builder.WriteByte('+')
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(hex[b>>4])
		builder.WriteByte(hex[b&0x0f])
	}
	return builder.String()
}
