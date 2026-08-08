// Package stringutil ports the reference implementation's Unicode-aware identifier casing
// helpers. Separators are discarded, apostrophes are removed, acronym
// boundaries are preserved, and uncased letters such as Hangul stay grouped.
package stringutil

import (
	"strings"
	"unicode"
)

// CapitalizeFirstLetter uppercases the first Unicode code point and leaves the
// remainder unchanged.
func CapitalizeFirstLetter(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// ToSnakeCase converts value to lowercase underscore-separated words.
func ToSnakeCase(value string) string {
	words := splitWords(value)
	for index := range words {
		words[index] = strings.ToLower(words[index])
	}
	return strings.Join(words, "_")
}

// ToKebabCase converts value to lowercase hyphen-separated words.
func ToKebabCase(value string) string {
	words := splitWords(value)
	for index := range words {
		words[index] = strings.ToLower(words[index])
	}
	return strings.Join(words, "-")
}

// ToCamelCase converts value to lower camel case while preserving the casing
// of every word after its first code point, matching the reference implementation 1.6.26.
func ToCamelCase(value string) string {
	words := splitWords(value)
	for index := range words {
		if index == 0 {
			words[index] = strings.ToLower(words[index])
			continue
		}
		words[index] = CapitalizeFirstLetter(words[index])
	}
	return strings.Join(words, "")
}

// ToPascalCase converts value to Pascal case.
func ToPascalCase(value string) string {
	words := splitWords(value)
	for index, word := range words {
		lower := []rune(strings.ToLower(word))
		if len(lower) != 0 {
			lower[0] = unicode.ToUpper(lower[0])
		}
		words[index] = string(lower)
	}
	return strings.Join(words, "")
}

func splitWords(value string) []string {
	filtered := make([]rune, 0, len(value))
	for _, current := range []rune(value) {
		if current != '\'' && current != '\u2019' {
			filtered = append(filtered, current)
		}
	}

	words := make([]string, 0)
	for index := 0; index < len(filtered); {
		current := filtered[index]
		switch {
		case isLowerOrDigit(current):
			end := index + 1
			for end < len(filtered) && isLowerOrDigit(filtered[end]) {
				end++
			}
			words = append(words, string(filtered[index:end]))
			index = end
		case unicode.IsUpper(current):
			upperEnd := index + 1
			for upperEnd < len(filtered) && unicode.IsUpper(filtered[upperEnd]) {
				upperEnd++
			}
			if upperEnd < len(filtered) && unicode.IsLower(filtered[upperEnd]) {
				if upperEnd-index > 1 {
					upperEnd--
					words = append(words, string(filtered[index:upperEnd]))
					index = upperEnd
					continue
				}
				end := upperEnd + 1
				for end < len(filtered) && isLowerOrDigit(filtered[end]) {
					end++
				}
				words = append(words, string(filtered[index:end]))
				index = end
				continue
			}
			words = append(words, string(filtered[index:upperEnd]))
			index = upperEnd
		case unicode.Is(unicode.Lo, current):
			end := index + 1
			for end < len(filtered) && unicode.Is(unicode.Lo, filtered[end]) {
				end++
			}
			words = append(words, string(filtered[index:end]))
			index = end
		default:
			index++
		}
	}
	return words
}

func isLowerOrDigit(value rune) bool {
	return unicode.IsLower(value) || unicode.IsDigit(value)
}
