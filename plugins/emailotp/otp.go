package emailotp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
)

// Identifier returns single-auth's exact verification identifier.
func Identifier(otpType OTPType, email string) string {
	return string(otpType) + "-otp-" + email
}

// SplitStoredValue splits the stored code and attempt suffix at the final
// colon, allowing custom encrypted values to contain colons.
func SplitStoredValue(input string) (string, string) {
	index := strings.LastIndexByte(input, ':')
	if index < 0 {
		return input, ""
	}
	return input[:index], input[index+1:]
}

func parseAttempts(value string) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func (p *plugin) generateOTP(data OTPData, ctx *engine.Context) (string, error) {
	if generator := p.options.GenerateOTP; generator != nil {
		value, err := generator(data, ctx)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
	}
	return randomDigits(p.random, p.options.OTPLength)
}

func randomDigits(random io.Reader, length int) (string, error) {
	result := make([]byte, length)
	buffer := make([]byte, 1)
	for index := range result {
		for {
			if _, err := io.ReadFull(random, buffer); err != nil {
				return "", err
			}
			if buffer[0] < 250 {
				result[index] = '0' + buffer[0]%10
				break
			}
		}
	}
	return string(result), nil
}

func defaultHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func constantTimeStringEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func (p *plugin) storeOTP(ctx context.Context, otp string) (string, error) {
	storageOptions := p.options.Storage
	switch {
	case storageOptions.CustomHash != nil:
		return storageOptions.CustomHash(ctx, otp)
	case storageOptions.CustomEncrypt != nil:
		return storageOptions.CustomEncrypt(ctx, otp)
	case storageOptions.Mode == StoreHashed:
		return defaultHash(otp), nil
	case storageOptions.Mode == StoreEncrypted:
		return baCrypto.EncryptWithReader(p.options.Runtime.Secret, []byte(otp), p.random)
	default:
		return otp, nil
	}
}

func (p *plugin) verifyStoredOTP(ctx context.Context, stored, provided string) (bool, error) {
	storageOptions := p.options.Storage
	var expected string
	var err error
	switch {
	case storageOptions.CustomHash != nil:
		expected, err = storageOptions.CustomHash(ctx, provided)
		if err == nil {
			return constantTimeStringEqual(expected, stored), nil
		}
		return false, err
	case storageOptions.CustomDecrypt != nil:
		expected, err = storageOptions.CustomDecrypt(ctx, stored)
	case storageOptions.Mode == StoreHashed:
		return constantTimeStringEqual(defaultHash(provided), stored), nil
	case storageOptions.Mode == StoreEncrypted:
		var value []byte
		value, err = baCrypto.Decrypt(p.options.Runtime.Secret, stored)
		expected = string(value)
	default:
		expected = stored
	}
	if err != nil {
		return false, err
	}
	return constantTimeStringEqual(expected, provided), nil
}

func (p *plugin) retrieveOTP(ctx context.Context, stored string) (string, bool, error) {
	storageOptions := p.options.Storage
	switch {
	case storageOptions.CustomHash != nil, storageOptions.Mode == StoreHashed:
		return "", false, nil
	case storageOptions.CustomDecrypt != nil:
		value, err := storageOptions.CustomDecrypt(ctx, stored)
		return value, err == nil, err
	case storageOptions.Mode == StoreEncrypted:
		value, err := baCrypto.Decrypt(p.options.Runtime.Secret, stored)
		return string(value), err == nil, err
	case storageOptions.Mode == StorePlain:
		return stored, true, nil
	default:
		return "", false, fmt.Errorf("emailotp: unsupported StoreMode %q", storageOptions.Mode)
	}
}
