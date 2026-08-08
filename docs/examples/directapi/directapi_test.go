package directapi

import "testing"

func TestDirectAPIExampleCreatesAndResolvesSession(t *testing.T) {
	auth, session, err := CreateSession(
		t.Context(),
		"documentation-example-secret-that-is-long-enough",
	)
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil {
		t.Fatal("CreateSession() returned a nil auth runtime")
	}
	if session == nil {
		t.Fatal("CreateSession() did not resolve the issued session")
	}
	if session.User.Email != "owner@example.com" {
		t.Fatalf("session user email = %q", session.User.Email)
	}
	if session.Session.Token == "" {
		t.Fatal("session token is empty")
	}
}
