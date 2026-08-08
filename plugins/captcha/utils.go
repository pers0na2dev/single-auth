package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
)

const defaultBasePath = "/api/auth"

type formField struct {
	name  string
	value string
}

// encodeForm follows URLSearchParams rather than net/url.QueryEscape: field
// order is significant and '~' belongs to the form percent-encode set.
func encodeForm(fields []formField) string {
	var output strings.Builder
	for index, field := range fields {
		if index != 0 {
			output.WriteByte('&')
		}
		output.WriteString(formEscape(field.name))
		output.WriteByte('=')
		output.WriteString(formEscape(field.value))
	}
	return output.String()
}

func formEscape(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var output strings.Builder
	for _, octet := range []byte(value) {
		switch {
		case octet >= 'a' && octet <= 'z',
			octet >= 'A' && octet <= 'Z',
			octet >= '0' && octet <= '9',
			octet == '*', octet == '-', octet == '.', octet == '_':
			output.WriteByte(octet)
		case octet == ' ':
			output.WriteByte('+')
		default:
			output.WriteByte('%')
			output.WriteByte(hexadecimal[octet>>4])
			output.WriteByte(hexadecimal[octet&0x0f])
		}
	}
	return output.String()
}

func javascriptJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	// JSON.stringify emits these valid JSON characters literally; encoding/json
	// escapes them even when HTML escaping is disabled.
	encoded = []byte(strings.ReplaceAll(string(encoded), `\u2028`, "\u2028"))
	encoded = []byte(strings.ReplaceAll(string(encoded), `\u2029`, "\u2029"))
	return encoded, nil
}

func protectedPath(rawPath, basePath string, configured []string) bool {
	if basePath == "" {
		basePath = defaultBasePath
	}
	pathname := strings.Replace(rawPath, basePath, "", 1)
	if strings.HasSuffix(pathname, "//") {
		pathname = pathname[:len(pathname)-1]
	}
	if strings.HasPrefix(pathname, "//") {
		pathname = pathname[1:]
	}
	if !strings.HasPrefix(pathname, "/") {
		pathname = "/" + pathname
	}

	endpoints := configured
	if len(endpoints) == 0 {
		endpoints = defaultEndpoints
	}
	exemptEmailOTP := true
	if len(configured) > 0 {
		for _, endpoint := range configured {
			if endpoint == "/sign-in/email-otp" {
				exemptEmailOTP = false
				break
			}
		}
	}
	for _, endpoint := range endpoints {
		if strings.Contains(pathname, endpoint) &&
			!(exemptEmailOTP && strings.Contains(pathname, "/sign-in/email-otp")) {
			return true
		}
	}
	return false
}

func requestURL(request contract.Request) string {
	if request.Host() == "" {
		return request.Target()
	}
	scheme := request.Scheme()
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, request.Host(), request.Target())
}

func javascriptTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case float64:
		return typed != 0
	default:
		// Arrays and objects are truthy in JavaScript, including empty ones.
		return true
	}
}

func strictString(value any) (string, bool) {
	stringValue, ok := value.(string)
	return stringValue, ok
}

func javascriptProperty(value any, name string) any {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return object[name]
}
