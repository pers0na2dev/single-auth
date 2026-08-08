package ratelimit

import (
	"regexp"
	"strings"
)

// WildcardMatch implements the default slash-separated behavior of Better
// Auth's wildcard-match dependency. '*' and '?' stay within a path segment;
// '**' can span segments; repeated slash/backslash separators are accepted.
func WildcardMatch(pattern, sample string) bool {
	expression, err := regexp.Compile("^" + wildcardExpression(pattern) + "$")
	return err == nil && expression.MatchString(sample)
}

func wildcardExpression(pattern string) string {
	const requiredSeparator = `[/\\]+?`
	const optionalSeparator = `[/\\]*?`
	const wildcard = `[^/\\]`
	segments := strings.Split(pattern, "/")
	var result strings.Builder
	for segmentIndex, segment := range segments {
		var separator string
		if segmentIndex == len(segments)-1 {
			separator = optionalSeparator
		} else if segments[segmentIndex+1] != "**" {
			separator = requiredSeparator
		}
		if segment == "" && segmentIndex > 0 {
			continue
		}
		if segment == "**" {
			if separator != "" {
				if segmentIndex > 0 {
					result.WriteString(separator)
				}
				result.WriteString("(?:")
				result.WriteString(wildcard)
				result.WriteString("*?")
				result.WriteString(separator)
				result.WriteString(")*?")
			}
			continue
		}
		for index := 0; index < len(segment); index++ {
			switch segment[index] {
			case '\\':
				if index+1 < len(segment) {
					index++
					result.WriteString(regexp.QuoteMeta(string(segment[index])))
				}
			case '?':
				result.WriteString(wildcard)
			case '*':
				result.WriteString(wildcard)
				result.WriteString("*?")
			default:
				result.WriteString(regexp.QuoteMeta(string(segment[index])))
			}
		}
		result.WriteString(separator)
	}
	return result.String()
}
