package coreutil

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestCoreUtilityBehavior(t *testing.T) {
	cases := []string{
		"createPlaceholderEmail::creates a namespaced address on the reserved placeholder domain",
		"createPlaceholderEmail::keeps equal identifiers distinct across namespaces",
		"createPlaceholderEmail::rejects an invalid address",
		"isBrowserFetchRequest::returns true for browser fetch requests",
		"isBrowserFetchRequest::returns false for navigation requests",
		"isBrowserFetchRequest::returns false without fetch metadata",
	}
	for _, caseKey := range cases {
		caseKey := caseKey
		t.Run(strings.ReplaceAll(caseKey, "/", "_"), func(t *testing.T) {
			switch caseKey {
			case "createPlaceholderEmail::creates a namespaced address on the reserved placeholder domain":
				got, err := CreatePlaceholderEmail(PlaceholderEmailOptions{Identifier: "account-id", Namespace: "namespace"})
				if err != nil || got != "account-id@namespace.placeholder.invalid" {
					t.Fatalf("CreatePlaceholderEmail()=(%q,%v)", got, err)
				}
			case "createPlaceholderEmail::keeps equal identifiers distinct across namespaces":
				first, firstErr := CreatePlaceholderEmail(PlaceholderEmailOptions{Identifier: "account-id", Namespace: "first"})
				second, secondErr := CreatePlaceholderEmail(PlaceholderEmailOptions{Identifier: "account-id", Namespace: "second"})
				if firstErr != nil || secondErr != nil || first != "account-id@first.placeholder.invalid" || second != "account-id@second.placeholder.invalid" || first == second {
					t.Fatalf("namespace addresses=(%q,%q), errors=(%v,%v)", first, second, firstErr, secondErr)
				}
			case "createPlaceholderEmail::rejects an invalid address":
				got, err := CreatePlaceholderEmail(PlaceholderEmailOptions{Identifier: "account-id", Namespace: ""})
				if got != "" || !errors.Is(err, ErrInvalidPlaceholderEmail) || err.Error() != "Invalid placeholder email" {
					t.Fatalf("invalid result=(%q,%v)", got, err)
				}
			case "isBrowserFetchRequest::returns true for browser fetch requests":
				headers := make(http.Header)
				headers.Set("Sec-Fetch-Mode", "cors")
				if got := IsBrowserFetchRequest(headers); !got {
					t.Fatal("CORS fetch was not detected")
				}
			case "isBrowserFetchRequest::returns false for navigation requests":
				headers := make(http.Header)
				headers.Set("Sec-Fetch-Mode", "navigate")
				if got := IsBrowserFetchRequest(headers); got {
					t.Fatal("navigation request was classified as a fetch")
				}
			case "isBrowserFetchRequest::returns false without fetch metadata":
				if got := IsBrowserFetchRequest(nil); got {
					t.Fatal("request without fetch metadata was classified as a fetch")
				}
			default:
				t.Fatalf("unexpected core utility case %q", caseKey)
			}
		})
	}
}
