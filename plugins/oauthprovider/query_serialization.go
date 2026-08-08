package oauthprovider

import (
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SignedQueryIssuedAtParam is the single-auth signed-query issuance field.
const SignedQueryIssuedAtParam = "ba_iat"

// SearchParamsToQuery converts URL values into single-auth's query shape:
// singleton parameters are strings and repeated parameters are string slices.
func SearchParamsToQuery(params url.Values) map[string]any {
	result := make(map[string]any, len(params))
	for key, values := range params {
		switch len(values) {
		case 1:
			result[key] = values[0]
		default:
			result[key] = append([]string(nil), values...)
		}
	}
	return result
}

// RemovePromptFromQuery returns a deep copy of query with the first matching
// space-delimited prompt removed. The input is never mutated.
func RemovePromptFromQuery(query url.Values, prompt string) url.Values {
	next := cloneURLValues(query)
	rawPrompt := next.Get("prompt")
	if rawPrompt == "" {
		return next
	}
	prompts := strings.Split(rawPrompt, " ")
	for index, candidate := range prompts {
		if candidate != prompt {
			continue
		}
		prompts = append(prompts[:index], prompts[index+1:]...)
		if len(prompts) == 0 {
			next.Del("prompt")
		} else {
			next.Set("prompt", strings.Join(prompts, " "))
		}
		break
	}
	return next
}

// GetSignedQueryIssuedAt reads single-auth's positive finite ba_iat epoch
// milliseconds value from a serialized query.
func GetSignedQueryIssuedAt(oauthQuery string) (time.Time, bool) {
	params, err := url.ParseQuery(oauthQuery)
	if err != nil {
		return time.Time{}, false
	}
	raw := params.Get(SignedQueryIssuedAtParam)
	if raw == "" {
		return time.Time{}, false
	}
	issuedAt, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(issuedAt) || math.IsInf(issuedAt, 0) || issuedAt <= 0 || issuedAt > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(math.Trunc(issuedAt))).UTC(), true
}

func cloneURLValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = append([]string(nil), entries...)
	}
	return clone
}
