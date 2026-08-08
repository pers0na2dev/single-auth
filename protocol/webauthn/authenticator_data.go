package webauthn

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

var firefox117BadEdDSAPrefix = []byte{
	0xa3, 0x01, 0x63, 0x4f, 0x4b, 0x50, 0x03, 0x27,
	0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39,
}

func ParseAuthenticatorData(authData []byte) (ParsedAuthenticatorData, error) {
	if len(authData) > MaxAuthenticatorDataBytes {
		return ParsedAuthenticatorData{}, fmt.Errorf("%w: authenticator data was %d bytes", ErrInputTooLarge, len(authData))
	}
	if len(authData) < 37 {
		return ParsedAuthenticatorData{}, fmt.Errorf("authenticator data was %d bytes, expected at least 37 bytes", len(authData))
	}
	pointer := 0
	result := ParsedAuthenticatorData{}
	result.RPIDHash = append([]byte(nil), authData[pointer:pointer+32]...)
	pointer += 32
	flags := authData[pointer]
	result.FlagsBuffer = []byte{flags}
	result.Flags = AuthenticatorFlags{
		UP:       flags&(1<<0) != 0,
		UV:       flags&(1<<2) != 0,
		BE:       flags&(1<<3) != 0,
		BS:       flags&(1<<4) != 0,
		AT:       flags&(1<<6) != 0,
		ED:       flags&(1<<7) != 0,
		FlagsInt: flags,
	}
	pointer++
	result.CounterBuffer = append([]byte(nil), authData[pointer:pointer+4]...)
	result.Counter = binary.BigEndian.Uint32(authData[pointer : pointer+4])
	pointer += 4

	if result.Flags.AT {
		if len(authData)-pointer < 18 {
			return ParsedAuthenticatorData{}, errors.New("attested credential data was truncated before AAGUID or credential ID length")
		}
		result.AAGUID = append([]byte(nil), authData[pointer:pointer+16]...)
		pointer += 16
		credentialIDLength := int(binary.BigEndian.Uint16(authData[pointer : pointer+2]))
		pointer += 2
		if credentialIDLength > MaxCredentialIDBytes {
			return ParsedAuthenticatorData{}, fmt.Errorf("%w: credential ID was %d bytes", ErrInputTooLarge, credentialIDLength)
		}
		if credentialIDLength > len(authData)-pointer {
			return ParsedAuthenticatorData{}, errors.New("credential ID length exceeded authenticator data")
		}
		result.CredentialID = append([]byte(nil), authData[pointer:pointer+credentialIDLength]...)
		pointer += credentialIDLength

		remaining := authData[pointer:]
		patched := append([]byte(nil), remaining...)
		firefoxWorkaround := len(patched) >= len(firefox117BadEdDSAPrefix)
		if firefoxWorkaround {
			for index := range firefox117BadEdDSAPrefix {
				if patched[index] != firefox117BadEdDSAPrefix[index] {
					firefoxWorkaround = false
					break
				}
			}
		}
		if firefoxWorkaround {
			patched[0] = 0xa4
		}
		var key map[int64]any
		consumed, err := decodeCBORFirst(patched, &key)
		if err != nil {
			return ParsedAuthenticatorData{}, fmt.Errorf("decode credential public key: %w", err)
		}
		if consumed > MaxCredentialPublicKeyBytes {
			return ParsedAuthenticatorData{}, fmt.Errorf("%w: credential public key was %d bytes", ErrInputTooLarge, consumed)
		}
		encoded, err := encodeCBOR(key)
		if err != nil {
			return ParsedAuthenticatorData{}, fmt.Errorf("normalize credential public key: %w", err)
		}
		result.CredentialPublicKey = encoded
		pointer += consumed
	}

	if result.Flags.ED {
		if pointer >= len(authData) {
			return ParsedAuthenticatorData{}, errors.New("extension-data flag was set but no extension data was present")
		}
		var extensions any
		consumed, err := decodeCBORFirst(authData[pointer:], &extensions)
		if err != nil {
			return ParsedAuthenticatorData{}, fmt.Errorf("error decoding authenticator extensions: %w", err)
		}
		result.ExtensionsDataBuffer = append([]byte(nil), authData[pointer:pointer+consumed]...)
		result.ExtensionsData, err = mapStringAny(extensions)
		if err != nil {
			return ParsedAuthenticatorData{}, fmt.Errorf("error decoding authenticator extensions: %w", err)
		}
		pointer += consumed
	}

	if pointer != len(authData) {
		return ParsedAuthenticatorData{}, errors.New("leftover bytes detected while parsing authenticator data")
	}
	return result, nil
}

func ParseBackupFlags(flags AuthenticatorFlags) (CredentialDeviceType, bool, error) {
	deviceType := SingleDevice
	if flags.BE {
		deviceType = MultiDevice
	}
	if deviceType == SingleDevice && flags.BS {
		return "", false, errors.New("single-device credential indicated that it was backed up, which should be impossible")
	}
	return deviceType, flags.BS, nil
}

func aaguidString(aaguid []byte) (string, error) {
	if len(aaguid) != 16 {
		return "", fmt.Errorf("AAGUID was %d bytes, expected 16", len(aaguid))
	}
	encoded := hex.EncodeToString(aaguid)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
