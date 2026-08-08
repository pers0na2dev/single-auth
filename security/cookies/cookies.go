// Package cookies implements the reference implementation compatible cookie parsing,
// serialization and mutation helpers.
package cookies

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	SecurePrefix = "__Secure-"
	HostPrefix   = "__Host-"
)

// Pair is an ordered request cookie name/value pair.
type Pair struct {
	Name  string
	Value string
}

// Parsed preserves insertion order while applying the reference implementation's last-value
// wins behavior for duplicate request cookie names.
type Parsed struct {
	pairs []Pair
	index map[string]int
}

// Get returns a decoded semantic cookie value.
func (p Parsed) Get(name string) (string, bool) {
	idx, ok := p.index[name]
	if !ok {
		return "", false
	}
	return p.pairs[idx].Value, true
}

// Pairs returns a defensive ordered copy.
func (p Parsed) Pairs() []Pair {
	return append([]Pair(nil), p.pairs...)
}

// Set replaces a cookie in place or appends a new cookie.
func (p *Parsed) Set(name, value string) bool {
	if !ValidName(name) {
		return false
	}
	if p.index == nil {
		p.index = make(map[string]int)
	}
	if idx, ok := p.index[name]; ok {
		p.pairs[idx].Value = value
		return true
	}
	p.index[name] = len(p.pairs)
	p.pairs = append(p.pairs, Pair{Name: name, Value: value})
	return true
}

// Header serializes request cookies using the RFC 6265 "; " separator and
// JavaScript encodeURIComponent semantics.
func (p Parsed) Header() string {
	parts := make([]string, 0, len(p.pairs))
	for _, pair := range p.pairs {
		parts = append(parts, pair.Name+"="+encodeURIComponent(pair.Value))
	}
	return strings.Join(parts, "; ")
}

// Attributes is the parsed Set-Cookie representation.
type Attributes struct {
	Value       string
	MaxAge      *int
	Expires     *time.Time
	Domain      string
	Path        string
	Secure      bool
	HTTPOnly    bool
	Partitioned bool
	SameSite    string
	Other       map[string]string
}

// SetCookie is one ordered Set-Cookie record.
type SetCookie struct {
	Name       string
	Attributes Attributes
}

// Options controls Set-Cookie serialization. A nil MaxAge means absent; zero
// means explicit deletion.
type Options struct {
	MaxAge      *int
	Expires     *time.Time
	Domain      string
	Path        string
	Secure      bool
	HTTPOnly    bool
	Partitioned bool
	SameSite    string
}

// SessionLookupOptions controls GetSessionCookie. Empty fields use Better
// Auth's public helper defaults.
type SessionLookupOptions struct {
	CookiePrefix string
	CookieName   string
}

// StripSecurePrefix removes only a leading __Secure- or __Host- prefix.
func StripSecurePrefix(name string) string {
	if strings.HasPrefix(name, SecurePrefix) {
		return name[len(SecurePrefix):]
	}
	if strings.HasPrefix(name, HostPrefix) {
		return name[len(HostPrefix):]
	}
	return name
}

// GetSessionCookie returns the semantic session-token value from a Cookie
// header. It mirrors the reference implementation's public helper: both dot and dash separators
// are accepted, and an explicitly present __Secure- cookie wins over a stale
// non-secure cookie (including when the secure value is empty).
func GetSessionCookie(header string, options SessionLookupOptions) (string, bool) {
	prefix := options.CookiePrefix
	if prefix == "" {
		prefix = "single-auth"
	}
	name := options.CookieName
	if name == "" {
		name = "session_token"
	}
	parsed := Parse(header)
	getCookie := func(candidate string) (string, bool) {
		if value, exists := parsed.Get(SecurePrefix + candidate); exists {
			return value, true
		}
		return parsed.Get(candidate)
	}
	for _, separator := range []string{".", "-"} {
		value, exists := getCookie(prefix + separator + name)
		if exists && value != "" {
			return value, true
		}
	}
	return "", false
}

// OptionsFromAttributes converts parsed Set-Cookie attributes back into the
// option shape accepted by Serialize.
func OptionsFromAttributes(attributes Attributes) Options {
	return Options{
		MaxAge:      attributes.MaxAge,
		Expires:     attributes.Expires,
		Domain:      attributes.Domain,
		Path:        attributes.Path,
		Secure:      attributes.Secure,
		HTTPOnly:    attributes.HTTPOnly,
		Partitioned: attributes.Partitioned,
		SameSite:    attributes.SameSite,
	}
}

// ScrubSetCookieValues removes a cookie and all of its numbered chunk variants
// from individual or comma-collapsed Set-Cookie header values. Survivors are
// returned as independent header values in wire order.
func ScrubSetCookieValues(values []string, cookieName string) []string {
	if len(values) == 0 || cookieName == "" {
		return append([]string(nil), values...)
	}
	exact := cookieName + "="
	chunk := cookieName + "."
	survivors := make([]string, 0, len(values))
	for _, value := range values {
		for _, entry := range SplitSetCookieHeader(value) {
			if strings.HasPrefix(entry, exact) || strings.HasPrefix(entry, chunk) {
				continue
			}
			survivors = append(survivors, entry)
		}
	}
	return survivors
}

// SplitSetCookieHeader splits a comma-joined header while preserving commas in
// Expires values using the same lookahead as the reference implementation 1.6.26.
func SplitSetCookieHeader(header string) []string {
	if header == "" {
		return nil
	}
	result := make([]string, 0, 2)
	start := 0
	for i := 0; i < len(header); i++ {
		if header[i] != ',' {
			continue
		}
		j := i + 1
		for j < len(header) && header[j] == ' ' {
			j++
		}
		for j < len(header) && header[j] != '=' && header[j] != ';' && header[j] != ',' {
			j++
		}
		if j < len(header) && header[j] == '=' {
			if part := strings.TrimSpace(header[start:i]); part != "" {
				result = append(result, part)
			}
			start = i + 1
			for start < len(header) && header[start] == ' ' {
				start++
			}
			i = start - 1
		}
	}
	if last := strings.TrimSpace(header[start:]); last != "" {
		result = append(result, last)
	}
	return result
}

// ParseSetCookieHeader parses possibly comma-joined Set-Cookie values.
func ParseSetCookieHeader(header string) []SetCookie {
	result := make([]SetCookie, 0)
	positions := make(map[string]int)
	for _, cookie := range SplitSetCookieHeader(header) {
		parts := strings.Split(cookie, ";")
		nameValue := ""
		if len(parts) > 0 {
			nameValue = strings.TrimSpace(parts[0])
		}
		name, value, ok := strings.Cut(nameValue, "=")
		if !ok || name == "" {
			continue
		}
		attributes := Attributes{Value: tryDecode(unquote(value))}
		for _, rawAttribute := range parts[1:] {
			attribute := strings.TrimSpace(rawAttribute)
			attrName, attrValue, hasValue := strings.Cut(attribute, "=")
			attrName = strings.ToLower(strings.TrimSpace(attrName))
			if hasValue {
				attrValue = strings.TrimSpace(attrValue)
			}
			switch attrName {
			case "max-age":
				if parsed, ok := parseLeadingInt(attrValue); ok {
					attributes.MaxAge = &parsed
				}
			case "expires":
				if parsed, err := http.ParseTime(attrValue); err == nil {
					attributes.Expires = &parsed
				}
			case "domain":
				attributes.Domain = attrValue
			case "path":
				attributes.Path = attrValue
			case "secure":
				attributes.Secure = true
			case "httponly":
				attributes.HTTPOnly = true
			case "partitioned":
				attributes.Partitioned = true
			case "samesite":
				attributes.SameSite = strings.ToLower(attrValue)
			case "":
			default:
				if attributes.Other == nil {
					attributes.Other = make(map[string]string)
				}
				if hasValue {
					attributes.Other[attrName] = attrValue
				} else {
					attributes.Other[attrName] = ""
				}
			}
		}
		parsed := SetCookie{Name: name, Attributes: attributes}
		if idx, exists := positions[name]; exists {
			result[idx] = parsed
		} else {
			positions[name] = len(result)
			result = append(result, parsed)
		}
	}
	return result
}

// Parse parses a Cookie request header.
func Parse(header string) Parsed {
	parsed := Parsed{index: make(map[string]int)}
	if len(header) < 2 {
		return parsed
	}
	for _, chunk := range strings.Split(header, ";") {
		eq := strings.IndexByte(chunk, '=')
		if eq < 0 {
			continue
		}
		name := trimOWS(chunk[:eq])
		value := unquote(trimOWS(chunk[eq+1:]))
		if ValidName(name) && validValue(value) {
			parsed.Set(name, tryDecode(value))
		}
	}
	return parsed
}

// SetRequestCookie performs the reference implementation's parse-mutate-serialize operation.
func SetRequestCookie(header, name, value string) string {
	parsed := Parse(header)
	parsed.Set(name, value)
	return parsed.Header()
}

// ApplySetCookies merges response cookie values into a request Cookie header.
func ApplySetCookies(header string, setCookieValues []string) string {
	parsed := Parse(header)
	for _, value := range setCookieValues {
		for _, cookie := range ParseSetCookieHeader(value) {
			parsed.Set(cookie.Name, cookie.Attributes.Value)
		}
	}
	return parsed.Header()
}

// Serialize emits a Set-Cookie line in the order used by the reference implementation's writer.
func Serialize(name, value string, options Options) string {
	if !ValidName(name) {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(name) + len(value) + 64)
	builder.WriteString(name)
	builder.WriteByte('=')
	builder.WriteString(encodeURIComponent(value))
	if options.MaxAge != nil {
		builder.WriteString("; Max-Age=")
		builder.WriteString(strconv.Itoa(*options.MaxAge))
	}
	if options.Domain != "" {
		builder.WriteString("; Domain=")
		builder.WriteString(options.Domain)
	}
	if options.Path != "" {
		builder.WriteString("; Path=")
		builder.WriteString(options.Path)
	}
	if options.Expires != nil {
		builder.WriteString("; Expires=")
		builder.WriteString(options.Expires.UTC().Format(http.TimeFormat))
	}
	if options.HTTPOnly {
		builder.WriteString("; HttpOnly")
	}
	if options.Secure {
		builder.WriteString("; Secure")
	}
	if options.SameSite != "" {
		builder.WriteString("; SameSite=")
		switch strings.ToLower(options.SameSite) {
		case "strict":
			builder.WriteString("Strict")
		case "none":
			builder.WriteString("None")
		default:
			builder.WriteString("Lax")
		}
	}
	if options.Partitioned {
		builder.WriteString("; Partitioned")
	}
	return builder.String()
}

// ValidName implements the reference implementation's RFC 7230 cookie token character set.
func ValidName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x27) || c == 0x2a || c == 0x2b || c == 0x2d || c == 0x2e ||
			(c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || c == 0x5e || c == 0x5f || c == 0x60 ||
			(c >= 0x61 && c <= 0x7a) || c == 0x7c || c == 0x7e {
			continue
		}
		return false
	}
	return true
}

func validValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == 0x20 || c == 0x21 || (c >= 0x23 && c <= 0x3a) || (c >= 0x3c && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) {
			continue
		}
		return false
	}
	return true
}

func trimOWS(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}

func unquote(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

func tryDecode(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func encodeURIComponent(value string) string {
	var builder strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '!' || b == '~' || b == '*' || b == '\'' || b == '(' || b == ')' {
			builder.WriteByte(b)
			continue
		}
		builder.WriteString(fmt.Sprintf("%%%02X", b))
	}
	return builder.String()
}

func parseLeadingInt(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	end := 0
	if value[0] == '+' || value[0] == '-' {
		end++
	}
	start := end
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == start {
		return 0, false
	}
	n, err := strconv.ParseInt(value[:end], 10, 0)
	return int(n), err == nil
}
