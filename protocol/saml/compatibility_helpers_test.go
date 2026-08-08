package saml

import "strings"

func samlCompatibilityKey(suite, title string) string {
	return suite + "::" + title
}

func validSAMLCompatibilityCase(id, file, suite, title string) bool {
	return id != "" && file != "" && suite != "" && title != "" &&
		strings.HasSuffix(id, "::"+suite+"::"+title)
}
