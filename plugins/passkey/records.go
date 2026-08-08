package passkey

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

func passkeyError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func unauthorized() *contract.APIError {
	return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func recordString(record storage.Record, key string) (string, bool) {
	if record == nil {
		return "", false
	}
	value, exists := record[key]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func recordBool(record storage.Record, key string) (bool, bool) {
	if record == nil {
		return false, false
	}
	value, exists := record[key]
	if !exists || value == nil {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case float64:
		return typed != 0, true
	default:
		return false, false
	}
}

func recordUint32(record storage.Record, key string) (uint32, bool) {
	if record == nil {
		return 0, false
	}
	value, exists := record[key]
	if !exists || value == nil {
		return 0, false
	}
	var number uint64
	switch typed := value.(type) {
	case uint32:
		number = uint64(typed)
	case uint64:
		number = typed
	case uint:
		number = uint64(typed)
	case int:
		if typed < 0 {
			return 0, false
		}
		number = uint64(typed)
	case int64:
		if typed < 0 {
			return 0, false
		}
		number = uint64(typed)
	case float64:
		if typed < 0 || typed != math.Trunc(typed) {
			return 0, false
		}
		number = uint64(typed)
	case json.Number:
		parsed, err := strconv.ParseUint(string(typed), 10, 32)
		if err != nil {
			return 0, false
		}
		number = parsed
	default:
		return 0, false
	}
	if number > math.MaxUint32 {
		return 0, false
	}
	return uint32(number), true
}

func recordTime(record storage.Record, key string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	value, exists := record[key]
	if !exists || value == nil {
		return time.Time{}, false
	}
	switch typed := value.(type) {
	case time.Time:
		return typed, !typed.IsZero()
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			parsed, err := time.Parse(layout, typed)
			if err == nil {
				return parsed, true
			}
		}
	}
	return time.Time{}, false
}

func userID(state *SessionState) (string, bool) {
	if state == nil {
		return "", false
	}
	return recordString(state.User, "id")
}

func registrationUserFromSession(state *SessionState) (RegistrationUser, bool) {
	id, ok := userID(state)
	if !ok || id == "" {
		return RegistrationUser{}, false
	}
	name, _ := recordString(state.User, "email")
	if name == "" {
		name = id
	}
	return RegistrationUser{ID: id, Name: name, DisplayName: name}, true
}

func credentialFromRecord(record storage.Record) (webauthn.Credential, error) {
	id, ok := recordString(record, "credentialID")
	if !ok {
		return webauthn.Credential{}, fmt.Errorf("passkey credentialID is invalid")
	}
	encodedKey, ok := recordString(record, "publicKey")
	if !ok {
		return webauthn.Credential{}, fmt.Errorf("passkey publicKey is invalid")
	}
	publicKey, err := decodeStandardBase64(encodedKey)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode passkey public key: %w", err)
	}
	counter, ok := recordUint32(record, "counter")
	if !ok {
		return webauthn.Credential{}, fmt.Errorf("passkey counter is invalid")
	}
	return webauthn.Credential{
		ID: id, PublicKey: publicKey, Counter: counter, Transports: recordTransports(record),
	}, nil
}
