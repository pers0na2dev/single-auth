package oauthprovider

import (
	"net/url"
	"sort"
	"strings"
)

const (
	// SignedQueryParameterNameParam declares every signed OAuth parameter.
	SignedQueryParameterNameParam = "ba_param"
	// PostLoginClearedParam is single-auth's signed post-login marker.
	PostLoginClearedParam = "ba_pl"
)

// CanonicalizeOAuthQueryParams serializes query pairs sorted first by key and
// then by value, retaining repeated parameters.
func CanonicalizeOAuthQueryParams(params url.Values) string {
	pairs := make([]oauthQueryPair, 0)
	for key, values := range params {
		for _, value := range values {
			pairs = append(pairs, oauthQueryPair{Key: key, Value: value})
		}
	}
	sort.SliceStable(pairs, func(left, right int) bool {
		if pairs[left].Key != pairs[right].Key {
			return pairs[left].Key < pairs[right].Key
		}
		return pairs[left].Value < pairs[right].Value
	})
	return serializeOAuthQueryPairs(pairs)
}

// SetSignedOAuthQueryParameterNames replaces ba_param declarations with the
// sorted unique names of the current parameters plus ba_param itself.
func SetSignedOAuthQueryParameterNames(params url.Values) {
	params.Del(SignedQueryParameterNameParam)
	names := make([]string, 0, len(params)+1)
	for key := range params {
		names = append(names, key)
	}
	names = append(names, SignedQueryParameterNameParam)
	sort.Strings(names)
	for _, name := range names {
		params.Add(SignedQueryParameterNameParam, name)
	}
}

// BuildSignedOAuthQuery keeps only the signature, declarations, and declared
// signed fields. Pair order and repeated fields are preserved.
func BuildSignedOAuthQuery(search string) (string, bool) {
	pairs := parseOAuthQueryPairs(strings.TrimPrefix(search, "?"))
	hasSignature := false
	signedNames := make(map[string]struct{})
	for _, pair := range pairs {
		switch pair.Key {
		case "sig":
			hasSignature = true
		case SignedQueryParameterNameParam:
			signedNames[pair.Value] = struct{}{}
		}
	}
	if !hasSignature || len(signedNames) == 0 {
		return "", false
	}
	filtered := make([]oauthQueryPair, 0, len(pairs))
	for _, pair := range pairs {
		_, signed := signedNames[pair.Key]
		if pair.Key == "sig" || pair.Key == SignedQueryParameterNameParam || signed {
			filtered = append(filtered, pair)
		}
	}
	return serializeOAuthQueryPairs(filtered), true
}

type oauthQueryPair struct {
	Key   string
	Value string
}

func parseOAuthQueryPairs(raw string) []oauthQueryPair {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "&")
	pairs := make([]oauthQueryPair, 0, len(parts))
	for _, part := range parts {
		key, value, found := strings.Cut(part, "=")
		if !found {
			value = ""
		}
		decodedKey, keyErr := url.QueryUnescape(key)
		decodedValue, valueErr := url.QueryUnescape(value)
		if keyErr != nil {
			decodedKey = key
		}
		if valueErr != nil {
			decodedValue = value
		}
		pairs = append(pairs, oauthQueryPair{Key: decodedKey, Value: decodedValue})
	}
	return pairs
}

func serializeOAuthQueryPairs(pairs []oauthQueryPair) string {
	serialized := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		serialized = append(serialized, oauthFormEscape(pair.Key)+"="+oauthFormEscape(pair.Value))
	}
	return strings.Join(serialized, "&")
}

func oauthFormEscape(value string) string {
	// Go and URLSearchParams share application/x-www-form-urlencoded encoding
	// for these values, except that WHATWG also escapes a literal tilde.
	return strings.ReplaceAll(url.QueryEscape(value), "~", "%7E")
}
