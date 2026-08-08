package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	MaxClientDataJSONBytes      = 64 << 10
	MaxAttestationObjectBytes   = 2 << 20
	MaxAuthenticatorDataBytes   = 1 << 20
	MaxCredentialPublicKeyBytes = 16 << 10
	MaxCredentialIDBytes        = 1024
	MaxSignatureBytes           = 16 << 10
)

var (
	ErrInvalidBase64URL = errors.New("invalid base64url value")
	ErrInputTooLarge    = errors.New("WebAuthn input exceeds size limit")
)

func encodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func trimBase64URLPadding(value string) string {
	return strings.ReplaceAll(value, "=", "")
}

func isBase64URL(value string) bool {
	trimmed := trimBase64URLPadding(value)
	if trimmed == "" {
		return value == ""
	}
	_, err := base64.RawURLEncoding.DecodeString(trimmed)
	return err == nil
}

func decodeBase64URL(value, field string, maximum int) ([]byte, error) {
	if maximum >= 0 && len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, fmt.Errorf("%w: encoded %s exceeded the maximum length for %d decoded bytes", ErrInputTooLarge, field, maximum)
	}
	if !isBase64URL(value) {
		return nil, fmt.Errorf("%w for %s", ErrInvalidBase64URL, field)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(trimBase64URLPadding(value))
	if err != nil {
		return nil, fmt.Errorf("%w for %s: %v", ErrInvalidBase64URL, field, err)
	}
	if len(decoded) > maximum {
		return nil, fmt.Errorf("%w: %s was %d bytes, maximum %d", ErrInputTooLarge, field, len(decoded), maximum)
	}
	return decoded, nil
}

func decodeBase64(value, field string, maximum int) ([]byte, error) {
	if maximum >= 0 && len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, fmt.Errorf("%w: encoded %s exceeded the maximum length for %d decoded bytes", ErrInputTooLarge, field, maximum)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 value for %s: %w", field, err)
		}
	}
	if len(decoded) > maximum {
		return nil, fmt.Errorf("%w: %s was %d bytes, maximum %d", ErrInputTooLarge, field, len(decoded), maximum)
	}
	return decoded, nil
}

func challengeBytes(value any, random io.Reader) ([]byte, error) {
	switch challenge := value.(type) {
	case nil:
		if random == nil {
			random = rand.Reader
		}
		out := make([]byte, 32)
		if _, err := io.ReadFull(random, out); err != nil {
			return nil, fmt.Errorf("generate challenge: %w", err)
		}
		return out, nil
	case string:
		return []byte(challenge), nil
	case []byte:
		return append([]byte(nil), challenge...), nil
	default:
		return nil, fmt.Errorf("challenge must be nil, string, or []byte, got %T", value)
	}
}

func randomBytes(random io.Reader, size int) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(random, out); err != nil {
		return nil, err
	}
	return out, nil
}

func DecodeClientDataJSON(encoded string) (ClientDataJSON, []byte, error) {
	raw, err := decodeBase64URL(encoded, "clientDataJSON", MaxClientDataJSONBytes)
	if err != nil {
		return ClientDataJSON{}, nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	var clientData ClientDataJSON
	if err := decoder.Decode(&clientData); err != nil {
		return ClientDataJSON{}, nil, fmt.Errorf("decode clientDataJSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ClientDataJSON{}, nil, errors.New("decode clientDataJSON: trailing JSON values")
		}
		return ClientDataJSON{}, nil, fmt.Errorf("decode clientDataJSON trailing data: %w", err)
	}
	return clientData, raw, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func boolDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
