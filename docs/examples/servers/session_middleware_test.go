package servers

import (
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
)

func newRefreshingDocumentationAuth(
	t *testing.T,
) (*singleauth.Auth, func()) {
	t.Helper()

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	zero := time.Duration(0)
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "https://auth.example.com",
		Secret:  testSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
		},
		TrustedOrigins: []string{"https://app.example.com"},
		Session: singleauth.SessionOptions{
			UpdateAge: &zero,
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	return auth, func() {
		now = now.Add(time.Second)
	}
}
