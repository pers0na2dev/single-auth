package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
)

func verifyEnvelope(id, rawID, credentialType string) error {
	if id == "" {
		return errors.New("missing credential ID")
	}
	if id != rawID {
		return errors.New("credential ID was not base64url-encoded")
	}
	if _, err := decodeBase64URL(id, "credential ID", MaxCredentialIDBytes); err != nil {
		if errors.Is(err, ErrInvalidBase64URL) {
			return errors.New("credential ID was not base64url-encoded")
		}
		return err
	}
	if credentialType != PublicKeyCredentialType {
		return fmt.Errorf("unexpected credential type %s, expected %q", credentialType, PublicKeyCredentialType)
	}
	return nil
}

func verifyClientData(clientData ClientDataJSON, expectedTypeDefault, ceremony string, expectedTypes []string, expectedChallenge string, challengeVerifier ChallengeVerifier, expectedOrigins []string, registrationTokenBinding bool) error {
	if expectedTypes != nil {
		if !contains(expectedTypes, clientData.Type) {
			return fmt.Errorf("unexpected %s response type %q, expected one of: %s", ceremony, clientData.Type, strings.Join(expectedTypes, ", "))
		}
	} else if clientData.Type != expectedTypeDefault {
		return fmt.Errorf("unexpected %s response type: %s", ceremony, clientData.Type)
	}

	if challengeVerifier != nil {
		valid, err := challengeVerifier(clientData.Challenge)
		if err != nil {
			return fmt.Errorf("custom challenge verifier: %w", err)
		}
		if !valid {
			challengeCeremony := ceremony
			if ceremony == "authentication" {
				// Copy/paste quirk in @simplewebauthn/server 13.2.3.
				challengeCeremony = "registration"
			}
			return fmt.Errorf("custom challenge verifier returned false for %s response challenge %q", challengeCeremony, clientData.Challenge)
		}
	} else if clientData.Challenge != expectedChallenge {
		return fmt.Errorf("unexpected %s response challenge %q, expected %q", ceremony, clientData.Challenge, expectedChallenge)
	}

	if !contains(expectedOrigins, clientData.Origin) {
		if len(expectedOrigins) == 1 {
			return fmt.Errorf("unexpected %s response origin %q, expected %q", ceremony, clientData.Origin, expectedOrigins[0])
		}
		return fmt.Errorf("unexpected %s response origin %q, expected one of: %s", ceremony, clientData.Origin, strings.Join(expectedOrigins, ", "))
	}

	if clientData.TokenBinding != nil {
		validStatus := clientData.TokenBinding.Status == "present" || clientData.TokenBinding.Status == "supported"
		if registrationTokenBinding {
			validStatus = validStatus || clientData.TokenBinding.Status == "not-supported"
		} else {
			// This spelling intentionally matches @simplewebauthn/server 13.2.3.
			validStatus = validStatus || clientData.TokenBinding.Status == "notSupported"
		}
		if !validStatus {
			return fmt.Errorf("unexpected tokenBinding status %s", clientData.TokenBinding.Status)
		}
	}
	return nil
}

func matchExpectedRPID(rpIDHash []byte, expectedRPIDs []string) (string, error) {
	if len(rpIDHash) != sha256.Size {
		return "", errors.New("unexpected RP ID hash")
	}
	for _, expected := range expectedRPIDs {
		digest := sha256.Sum256([]byte(expected))
		if subtle.ConstantTimeCompare(rpIDHash, digest[:]) == 1 {
			return expected, nil
		}
	}
	return "", errors.New("unexpected RP ID hash")
}
