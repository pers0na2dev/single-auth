package enterprise

import "testing"

const testSecret = "documentation-example-secret-that-is-long-enough"

func TestEnterpriseExamplesConstruct(t *testing.T) {
	tests := []struct {
		name string
		new  func() error
	}{
		{name: "API keys", new: func() error { _, err := APIKeys(testSecret); return err }},
		{name: "SSO", new: func() error { _, err := SSO("client", "secret", testSecret); return err }},
		{name: "OAuth provider", new: func() error { _, err := OAuthAuthorizationServer(testSecret); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.new(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
