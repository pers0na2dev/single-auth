package oauthprovider

import (
	"encoding/base64"
	"errors"
	"strings"
)

var ErrInvalidBasicAuthorization = errors.New("invalid authorization header format")

// ClientCredentials is the RFC 7617 Basic representation consumed by OAuth
// client authentication endpoints.
type ClientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// BasicToClientCredentials parses single-auth's Basic authorization format.
// A non-Basic header returns (nil, nil); malformed Basic data returns
// ErrInvalidBasicAuthorization. Only the first colon separates the ID so all
// remaining colons stay in the client secret.
func BasicToClientCredentials(authorization string) (*ClientCredentials, error) {
	if !strings.HasPrefix(authorization, "Basic ") {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, "Basic "))
	if err != nil {
		return nil, ErrInvalidBasicAuthorization
	}
	separator := strings.IndexByte(string(decoded), ':')
	if separator < 0 {
		return nil, ErrInvalidBasicAuthorization
	}
	id := string(decoded[:separator])
	secret := string(decoded[separator+1:])
	if id == "" || secret == "" {
		return nil, ErrInvalidBasicAuthorization
	}
	return &ClientCredentials{ClientID: id, ClientSecret: secret}, nil
}
