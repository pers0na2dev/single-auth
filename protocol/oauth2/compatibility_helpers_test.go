package oauth2

import "strings"

func validCompatibilityCase(id, file, suite, title string) bool {
	return id != "" && file != "" && suite != "" && title != "" &&
		strings.HasSuffix(id, "::"+suite+"::"+title)
}

func compatibilityIDExists(ids []string, candidate string) bool {
	for _, id := range ids {
		if id == candidate {
			return true
		}
	}
	return false
}
