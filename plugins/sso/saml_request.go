package sso

import (
	"crypto"
	"fmt"
	"strings"

	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
)

func metadataSizeLimit(values ...int) int {
	if len(values) > 0 && values[0] > 0 {
		return values[0]
	}
	return defaultMaxMetadataSize
}

func validateSAMLMetadataSize(config SAMLConfig, limit int) error {
	limit = metadataSizeLimit(limit)
	if config.IDPMetadata != nil && len([]byte(config.IDPMetadata.Metadata)) > limit {
		return fmt.Errorf("IdP metadata exceeds maximum allowed size (%d bytes)", limit)
	}
	if config.SPMetadata != nil && len([]byte(config.SPMetadata.Metadata)) > limit {
		return fmt.Errorf("SP metadata exceeds maximum allowed size (%d bytes)", limit)
	}
	return nil
}

func samlAuthnRequestSigner(config SAMLConfig) (crypto.Signer, error) {
	if !config.AuthnRequestsSigned {
		return nil, nil
	}
	privateKey := strings.TrimSpace(config.PrivateKey)
	password := ""
	if config.SPMetadata != nil {
		if value := strings.TrimSpace(config.SPMetadata.PrivateKey); value != "" {
			privateKey = value
		}
		password = config.SPMetadata.PrivateKeyPass
	}
	if privateKey == "" {
		return nil, fmt.Errorf("SAML AuthnRequest signing requires an SP private key")
	}
	return samlprotocol.ParsePrivateKeyPEM([]byte(privateKey), password)
}

func samlEntryPointWithAdditionalParams(endpoint string, additional map[string]any) (string, error) {
	if len(additional) == 0 {
		return endpoint, nil
	}
	parsed, err := absoluteHTTPURL(endpoint)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	for key, value := range additional {
		key = strings.TrimSpace(key)
		if key == "" || reservedSAMLRedirectParameter(key) || value == nil {
			continue
		}
		switch typed := value.(type) {
		case []string:
			query.Del(key)
			for _, item := range typed {
				query.Add(key, item)
			}
		case []any:
			query.Del(key)
			for _, item := range typed {
				query.Add(key, fmt.Sprint(item))
			}
		default:
			query.Set(key, fmt.Sprint(value))
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func reservedSAMLRedirectParameter(key string) bool {
	switch strings.ToLower(key) {
	case strings.ToLower(string(samlprotocol.SAMLRequestParameter)),
		strings.ToLower(string(samlprotocol.SAMLResponseParameter)),
		"relaystate", "sigalg", "signature":
		return true
	default:
		return false
	}
}
