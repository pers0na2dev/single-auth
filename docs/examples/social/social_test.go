package social

import "testing"

func TestGoogleExampleConstructs(t *testing.T) {
	auth, err := Google(
		"google-client-id",
		"google-client-secret",
		"documentation-example-secret-that-is-long-enough",
	)
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil {
		t.Fatal("Google() returned a nil auth runtime")
	}
}
