package core

import "testing"

func TestBaseErrorCatalog(t *testing.T) {
	t.Parallel()
	if len(BaseErrorMessages) != 49 {
		t.Fatalf("upstream implementation 1.6.26 has 49 base errors, got %d", len(BaseErrorMessages))
	}
	if got := ErrorMessage(ErrorUserAlreadyExists); got != "User already exists." {
		t.Fatalf("punctuation drifted: %q", got)
	}
	if got := ErrorMessage(ErrorMethodNeedsDeferredSession); got != "POST method requires deferSessionRefresh to be enabled in session config" {
		t.Fatalf("message drifted: %q", got)
	}
}
