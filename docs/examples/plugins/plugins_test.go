package plugins

import "testing"

func TestPluginExampleConstructs(t *testing.T) {
	auth, err := New("documentation-example-secret-that-is-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil {
		t.Fatal("New() returned a nil auth runtime")
	}
}
