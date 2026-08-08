package singleauth_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type ipv6SmokeCase struct {
	Title    string
	Expected ipv6SmokeExpected
}

type ipv6SmokeExpected struct {
	Addresses   []string
	Statuses    []int
	RateLimited []bool
}

func TestIPv6RateLimitHTTPSmokeBehavior(t *testing.T) {
	for _, scenario := range ipv6SmokeCases() {
		scenario := scenario
		t.Run(scenario.Title, func(t *testing.T) {
			enabled := true
			prefix := 64
			auth, err := singleauth.New(singleauth.Options{
				BaseURL:          "http://localhost:3000",
				Database:         memory.MustNew(),
				EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
				TrustedOrigins:   []string{"http://localhost:*"},
				RateLimit: singleauth.RateLimitOptions{
					Enabled: &enabled,
					Window:  60,
					Max:     3,
				},
				Advanced: singleauth.AdvancedOptions{
					IPAddress: ratelimit.IPOptions{IPv6Subnet: &prefix},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(auth)
			defer server.Close()

			actual := ipv6SmokeExpected{Addresses: append([]string(nil), scenario.Expected.Addresses...)}
			for _, address := range scenario.Expected.Addresses {
				request, err := http.NewRequest(
					http.MethodPost,
					server.URL+"/api/auth/sign-in/email",
					bytes.NewBufferString(`{"email":"test@test.com","password":"password"}`),
				)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", "http://localhost:3000")
				request.Header.Set("X-Forwarded-For", address)
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				actual.Statuses = append(actual.Statuses, response.StatusCode)
				actual.RateLimited = append(actual.RateLimited, response.StatusCode == http.StatusTooManyRequests)
			}
			if !reflect.DeepEqual(actual, scenario.Expected) {
				t.Fatalf("IPv6 smoke observation=%#v, want %#v", actual, scenario.Expected)
			}
		})
	}
}

func ipv6SmokeCases() []ipv6SmokeCase {
	return []ipv6SmokeCase{
		{
			Title: "groups IPv6 addresses from the same /64 subnet",
			Expected: ipv6SmokeExpected{
				Addresses: []string{
					"2001:db8:abcd:1234:0000:0000:0000:0001",
					"2001:db8:abcd:1234:1111:2222:3333:4444",
					"2001:db8:abcd:1234:ffff:ffff:ffff:ffff",
					"2001:db8:abcd:1234:0000:0000:0000:0001",
				},
				Statuses:    []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests},
				RateLimited: []bool{false, false, false, true},
			},
		},
		{
			Title: "normalizes equivalent IPv6 representations",
			Expected: ipv6SmokeExpected{
				Addresses: []string{
					"2001:db8::1",
					"2001:DB8::1",
					"2001:0db8::1",
					"2001:db8:0:0:0:0:0:1",
				},
				Statuses:    []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests},
				RateLimited: []bool{false, false, false, true},
			},
		},
		{
			Title: "keeps different /64 subnets independent",
			Expected: ipv6SmokeExpected{
				Addresses: []string{
					"2001:db8:abcd:1111:0000:0000:0000:0001",
					"2001:db8:abcd:2222:0000:0000:0000:0001",
					"2001:db8:abcd:3333:0000:0000:0000:0001",
				},
				Statuses:    []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized},
				RateLimited: []bool{false, false, false},
			},
		},
	}
}
