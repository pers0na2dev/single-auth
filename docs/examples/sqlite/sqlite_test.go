package sqlite

import "testing"

func TestSQLiteExampleMigrates(t *testing.T) {
	database, auth, err := Open(
		t.Context(),
		"file:single-auth-docs?mode=memory&cache=shared",
		"documentation-example-secret-that-is-long-enough",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if auth == nil {
		t.Fatal("Open() returned a nil auth runtime")
	}
}
