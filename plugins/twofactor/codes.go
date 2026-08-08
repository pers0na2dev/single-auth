package twofactor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) generateBackupCodeSet() ([]string, string, error) {
	var codes []string
	if p.options.BackupCodes.CustomGenerate != nil {
		codes = append([]string(nil), p.options.BackupCodes.CustomGenerate()...)
	} else {
		codes = make([]string, p.options.BackupCodes.Amount)
		for index := range codes {
			code, err := randomFromAlphabet(
				p.random,
				p.options.BackupCodes.Length,
				"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			)
			if err != nil {
				return nil, "", err
			}
			split := 5
			if split > len(code) {
				split = len(code)
			}
			codes[index] = code[:split] + "-" + code[split:]
		}
	}
	encoded, err := p.encodeBackupCodes(codes)
	return codes, encoded, err
}

func (p *plugin) encodeBackupCodes(codes []string) (string, error) {
	raw, err := json.Marshal(codes)
	if err != nil {
		return "", err
	}
	storage := p.options.BackupCodes.Storage
	switch {
	case storage.Encrypt != nil:
		return storage.Encrypt(string(raw))
	case storage.Mode == OTPStorageEncrypted:
		return p.encryptSecret(raw)
	default:
		return string(raw), nil
	}
}

func (p *plugin) decodeBackupCodes(value string) ([]string, error) {
	storage := p.options.BackupCodes.Storage
	raw := value
	var err error
	switch {
	case storage.Decrypt != nil:
		raw, err = storage.Decrypt(value)
	case storage.Mode == OTPStorageEncrypted:
		var decoded []byte
		decoded, err = p.options.Runtime.DecryptSecret(value)
		raw = string(decoded)
	}
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, nil
	}
	return result, nil
}

func (p *plugin) encryptSecret(value []byte) (string, error) {
	if p.options.Runtime.EncryptSecret == nil {
		return "", errors.New("twofactor: secret encryption is unavailable")
	}
	return p.options.Runtime.EncryptSecret(value)
}

func (p *plugin) storedOTP(otp string) (string, error) {
	storage := p.options.OTP.Storage
	switch {
	case storage.Hash != nil:
		return storage.Hash(otp)
	case storage.Encrypt != nil:
		return storage.Encrypt(otp)
	case storage.Mode == OTPStorageHashed:
		return hashOTP(otp), nil
	case storage.Mode == OTPStorageEncrypted:
		return p.encryptSecret([]byte(otp))
	default:
		return otp, nil
	}
}

func (p *plugin) compareStoredOTP(stored, input string) (bool, error) {
	storage := p.options.OTP.Storage
	left, right := stored, input
	var err error
	switch {
	case storage.Hash != nil:
		right, err = storage.Hash(input)
	case storage.Decrypt != nil:
		left, err = storage.Decrypt(stored)
	case storage.Mode == OTPStorageHashed:
		right = hashOTP(input)
	case storage.Mode == OTPStorageEncrypted:
		var decoded []byte
		decoded, err = p.options.Runtime.DecryptSecret(stored)
		left = string(decoded)
	}
	if err != nil {
		return false, err
	}
	return constantTimeStrings(left, right), nil
}

func (p *plugin) sendOTP(ctx *engine.Context, user storage.Record, otp string) error {
	if p.options.OTP.SendOTP == nil {
		return twoFactorError(400, CodeOTPNotConfigured)
	}
	return p.options.Runtime.RunBackground(ctx.GoContext(), func(background context.Context) error {
		return p.options.OTP.SendOTP(background, OTPMessage{User: user, OTP: otp}, ctx)
	})
}

func removeBackupCode(codes []string, code string) ([]string, bool) {
	found := false
	result := make([]string, 0, len(codes))
	for _, candidate := range codes {
		if candidate == code {
			found = true
			continue
		}
		result = append(result, candidate)
	}
	return result, found
}

func normalizeCode(value string) string { return strings.TrimSpace(value) }
