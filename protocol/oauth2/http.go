package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DoForm posts a form, refuses redirects and decodes a JSON object response.
func DoForm(ctx context.Context, client *http.Client, endpoint string, request FormRequest) (map[string]any, error) {
	body := request.Body.Encode()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, value := range request.Headers {
		httpRequest.Header.Set(key, value)
	}
	response, err := DoRefusingRedirects(client, httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	data := make(map[string]any)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("OAuth endpoint %q returned %d: %s", endpoint, response.StatusCode, strings.TrimSpace(string(raw)))
	}
	return data, nil
}

// NormalizeTokens maps provider JSON fields to the reference implementation tokens.
func NormalizeTokens(data map[string]any, now time.Time) Tokens {
	tokens := Tokens{
		TokenType:    stringField(data, "token_type"),
		AccessToken:  stringField(data, "access_token"),
		RefreshToken: stringField(data, "refresh_token"),
		IDToken:      stringField(data, "id_token"),
		Raw:          data,
	}
	if scopes, ok := data["scope"].(string); ok && scopes != "" {
		tokens.Scopes = strings.Split(scopes, " ")
	} else if list, ok := data["scope"].([]string); ok {
		tokens.Scopes = append([]string(nil), list...)
	} else if list, ok := data["scope"].([]any); ok {
		for _, value := range list {
			if scope, ok := value.(string); ok {
				tokens.Scopes = append(tokens.Scopes, scope)
			}
		}
	} else {
		tokens.Scopes = []string{}
	}
	if seconds, ok := secondsField(data["expires_in"]); ok && seconds != 0 {
		expires := now.Add(time.Duration(seconds * float64(time.Second)))
		tokens.AccessTokenExpiresAt = &expires
	}
	if seconds, ok := secondsField(data["refresh_token_expires_in"]); ok && seconds != 0 {
		expires := now.Add(time.Duration(seconds * float64(time.Second)))
		tokens.RefreshTokenExpiresAt = &expires
	}
	return tokens
}

// RefreshAccessTokenOptions controls RefreshAccessToken.
type RefreshAccessTokenOptions struct {
	RefreshToken   string
	Options        ProviderOptions
	TokenEndpoint  string
	Authentication Authentication
	ExtraParams    []Param
	Resources      []string
	Client         *http.Client
}

// RefreshAccessToken exchanges a refresh token without following redirects and
// returns the normalized token object used by the reference implementation's core OAuth helper.
func RefreshAccessToken(ctx context.Context, options RefreshAccessTokenOptions) (Tokens, error) {
	request := CreateRefreshAccessTokenRequest(RefreshTokenRequestOptions{
		RefreshToken:   options.RefreshToken,
		Options:        options.Options,
		Authentication: options.Authentication,
		ExtraParams:    options.ExtraParams,
		Resources:      options.Resources,
	})
	data, err := DoForm(ctx, options.Client, options.TokenEndpoint, request)
	if err != nil {
		return Tokens{}, err
	}
	tokens := NormalizeTokens(data, time.Now())
	// the reference implementation constructs a fresh refresh result rather than exposing the
	// provider response as Raw. An absent scope remains absent as well.
	tokens.Raw = nil
	if _, ok := data["scope"]; !ok {
		tokens.Scopes = nil
	}
	return tokens, nil
}

// ApplyDefaultAccessTokenExpiry fills a missing provider expiry.
func ApplyDefaultAccessTokenExpiry(tokens Tokens, expiresIn time.Duration, now time.Time) Tokens {
	if tokens.AccessTokenExpiresAt == nil && expiresIn > 0 {
		expires := now.Add(expiresIn)
		tokens.AccessTokenExpiresAt = &expires
	}
	return tokens
}

func stringField(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return value
}

func secondsField(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		seconds, err := typed.Float64()
		return seconds, err == nil
	case float64:
		return typed, true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	default:
		return 0, false
	}
}
