package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// JWK is one JSON Web Key from a provider's published key set.
type JWK = map[string]any

// FetchJWK returns the key matching kid. Provider key fetches intentionally
// use ordinary fetch redirect behavior, matching the reference implementation's exported key
// helpers rather than the stricter shared token endpoint helper.
func FetchJWK(ctx context.Context, client *http.Client, jwksURI, kid string) (JWK, error) {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := doJSON(ctx, clientOrDefault(client), http.MethodGet, jwksURI, nil, nil, &set); err != nil {
		return nil, err
	}
	if set.Keys == nil {
		return nil, errors.New("Keys not found")
	}
	for _, key := range set.Keys {
		if stringValue(key["kid"]) == kid {
			return key, nil
		}
	}
	return nil, fmt.Errorf("JWK with kid %s not found", kid)
}

// PublicKeyFromJWK imports the RSA or EC key types used by the built-ins.
func PublicKeyFromJWK(jwk JWK) (crypto.PublicKey, error) {
	switch stringValue(jwk["kty"]) {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["n"]))
		if err != nil {
			return nil, err
		}
		eRaw, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["e"]))
		if err != nil {
			return nil, err
		}
		e := 0
		for _, value := range eRaw {
			e = e<<8 | int(value)
		}
		if e == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch stringValue(jwk["crv"]) {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %s", stringValue(jwk["crv"]))
		}
		x, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["x"]))
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(stringValue(jwk["y"]))
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	default:
		return nil, fmt.Errorf("unsupported JWK key type %s", stringValue(jwk["kty"]))
	}
}

func GetApplePublicKey(ctx context.Context, kid string, clients ...*http.Client) (crypto.PublicKey, error) {
	return fetchPublicKey(ctx, optionalClient(clients), "https://appleid.apple.com/auth/keys", kid)
}

func GetGooglePublicKey(ctx context.Context, kid string, clients ...*http.Client) (crypto.PublicKey, error) {
	return fetchPublicKey(ctx, optionalClient(clients), "https://www.googleapis.com/oauth2/v3/certs", kid)
}

func GetCognitoPublicKey(ctx context.Context, kid, region, userPoolID string, clients ...*http.Client) (crypto.PublicKey, error) {
	uri := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)
	return fetchPublicKey(ctx, optionalClient(clients), uri, kid)
}

func GetMicrosoftPublicKey(ctx context.Context, kid, tenant, authority string, clients ...*http.Client) (crypto.PublicKey, error) {
	authority = strings.TrimRight(authority, "/")
	return fetchPublicKey(ctx, optionalClient(clients), authority+"/"+tenant+"/discovery/v2.0/keys", kid)
}

func GetPayPalPublicKey(ctx context.Context, kid, jwksURI string, clients ...*http.Client) (crypto.PublicKey, error) {
	return fetchPublicKey(ctx, optionalClient(clients), jwksURI, kid)
}

func fetchPublicKey(ctx context.Context, client *http.Client, uri, kid string) (crypto.PublicKey, error) {
	jwk, err := FetchJWK(ctx, client, uri, kid)
	if err != nil {
		return nil, err
	}
	return PublicKeyFromJWK(jwk)
}

func optionalClient(clients []*http.Client) *http.Client {
	if len(clients) != 0 && clients[0] != nil {
		return clients[0]
	}
	return http.DefaultClient
}

func clientOrDefault(client *http.Client) *http.Client {
	if client == nil {
		return http.DefaultClient
	}
	return client
}

type VerifyGoogleIDTokenOptions struct {
	Token      string
	Audience   any
	Nonce      string
	HTTPClient *http.Client
}

// VerifyGoogleIDToken mirrors the reference implementation's exported helper. Invalid tokens
// return a nil claims object and nil error; transport/configuration errors are
// likewise treated as failed verification by the upstream helper.
func VerifyGoogleIDToken(ctx context.Context, options VerifyGoogleIDTokenOptions) (map[string]any, error) {
	provider := &Provider{Options: Options{HTTPClient: options.HTTPClient}}
	claims, err := verifyRemoteJWT(ctx, provider, options.Token, "https://www.googleapis.com/oauth2/v3/certs", jwtPolicy{issuers: []string{"https://accounts.google.com", "accounts.google.com"}, audiences: audienceOptions(options.Audience), maxAge: time.Hour})
	if err != nil {
		return nil, nil
	}
	if options.Nonce != "" && stringValue(claims["nonce"]) != options.Nonce {
		return nil, nil
	}
	return claims, nil
}

func IsGoogleHostedDomainAllowed(configuredHostedDomain string, tokenHostedDomain any) bool {
	return googleHostedDomainAllowed(configuredHostedDomain, tokenHostedDomain)
}
