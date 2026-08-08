package oidcprovider

import "strings"

// Prompt is one recognized OpenID Connect prompt value.
type Prompt string

const (
	PromptLogin         Prompt = "login"
	PromptConsent       Prompt = "consent"
	PromptSelectAccount Prompt = "select_account"
	PromptNone          Prompt = "none"
)

// PromptSet is the deduplicated result of ParsePrompt.
type PromptSet map[Prompt]struct{}

// Has reports whether prompt is present.
func (set PromptSet) Has(prompt Prompt) bool {
	_, exists := set[prompt]
	return exists
}

// ParsePrompt implements the exact frozen parser: recognized values are
// deduplicated, unknown values are ignored, and none cannot be combined with
// another recognized prompt.
func ParsePrompt(value string) (PromptSet, error) {
	result := PromptSet{}
	for _, field := range strings.Split(value, " ") {
		switch Prompt(strings.TrimSpace(field)) {
		case PromptLogin:
			result[PromptLogin] = struct{}{}
		case PromptConsent:
			result[PromptConsent] = struct{}{}
		case PromptSelectAccount:
			result[PromptSelectAccount] = struct{}{}
		case PromptNone:
			result[PromptNone] = struct{}{}
		}
	}
	if result.Has(PromptNone) && len(result) > 1 {
		return nil, invalidRequest("prompt none must only be used alone")
	}
	return result, nil
}
