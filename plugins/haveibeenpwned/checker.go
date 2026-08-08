package haveibeenpwned

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP range protocol requires SHA-1.
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type checker struct {
	client  HTTPDoer
	message string
}

func newChecker(options Options) *checker {
	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &checker{client: client, message: options.CustomPasswordCompromisedMessage}
}

// CheckPassword checks one plaintext password using the k-anonymity range
// protocol. Empty passwords are ignored exactly like upstream; endpoint-level
// required/length validation remains authoritative.
func CheckPassword(ctx context.Context, password string, options Options) error {
	return newChecker(options).check(ctx, password)
}

func (checker *checker) check(ctx context.Context, password string) error {
	if password == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	digest := sha1.Sum([]byte(password)) // #nosec G401 -- HIBP protocol hash.
	hash := strings.ToUpper(hex.EncodeToString(digest[:]))
	prefix, suffix := hash[:5], hash[5:]

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		RangeAPIBaseURL+prefix,
		nil,
	)
	if err != nil {
		return unavailableCheckError(err)
	}
	request.Header.Set("Add-Padding", "true")
	request.Header.Set("User-Agent", "Reference Password Checker")
	response, err := checker.client.Do(request)
	if err != nil {
		return unavailableCheckError(err)
	}
	if response == nil {
		return unavailableCheckError(fmt.Errorf("HIBP client returned a nil response"))
	}
	if response.Body == nil {
		return unavailableCheckError(fmt.Errorf("HIBP response body is nil"))
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return statusCheckError(response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return unavailableCheckError(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		candidate, _, _ := strings.Cut(line, ":")
		if strings.EqualFold(candidate, suffix) {
			return compromisedError(checker.message)
		}
	}
	return nil
}
