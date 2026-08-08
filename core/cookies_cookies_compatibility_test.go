package core

import "testing"

type cookiesBehaviorVector struct {
	Suite string
	Title string
}

func TestCookieScenarios(t *testing.T) {
	for _, vector := range cookieBehaviorCases() {
		vector := vector
		runner, ok := cookieBehaviorRunner(vector)
		if !ok {
			t.Fatalf("no Go runner for %q / %q", vector.Suite, vector.Title)
		}
		t.Run(vector.Suite+"/"+vector.Title, func(t *testing.T) {
			runner(t)
		})
	}
}

func TestCookieScenarioDefinitions(t *testing.T) {
	cases := cookieBehaviorCases()
	if len(cases) != 105 {
		t.Fatalf("cookie scenarios=%d, want 105", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, vector := range cases {
		if vector.Suite == "" || vector.Title == "" {
			t.Fatalf("invalid cookie scenario: suite=%q title=%q", vector.Suite, vector.Title)
		}
		key := vector.Suite + "\x00" + vector.Title
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate cookie scenario %q / %q", vector.Suite, vector.Title)
		}
		seen[key] = struct{}{}
	}
}

func cookieBehaviorRunner(vector cookiesBehaviorVector) (func(*testing.T), bool) {
	if runner, ok := cookieBehaviorUtilityRunner(vector); ok {
		return runner, true
	}
	if runner, ok := cookieBehaviorSessionRunner(vector); ok {
		return runner, true
	}
	return cookieBehaviorAuthRunner(vector)
}
