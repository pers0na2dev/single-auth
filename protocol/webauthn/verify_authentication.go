package webauthn

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

func VerifyAuthenticationResponse(options VerifyAuthenticationOptions) (VerifiedAuthenticationResponse, error) {
	response := options.Response
	if err := verifyEnvelope(response.ID, response.RawID, response.Type); err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	if response.Response.ClientDataJSON == "" {
		return VerifiedAuthenticationResponse{}, errors.New("credential response clientDataJSON was not a string")
	}
	clientData, rawClientData, err := DecodeClientDataJSON(response.Response.ClientDataJSON)
	if err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	if err := verifyClientData(clientData, "webauthn.get", "authentication", options.ExpectedTypes, options.ExpectedChallenge, options.ChallengeVerifier, options.ExpectedOrigins, false); err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	if !isBase64URL(response.Response.AuthenticatorData) {
		return VerifiedAuthenticationResponse{}, errors.New("credential response authenticatorData was not a base64url string")
	}
	if !isBase64URL(response.Response.Signature) {
		return VerifiedAuthenticationResponse{}, errors.New("credential response signature was not a base64url string")
	}
	authenticatorData, err := decodeBase64URL(response.Response.AuthenticatorData, "authenticatorData", MaxAuthenticatorDataBytes)
	if err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	parsed, err := ParseAuthenticatorData(authenticatorData)
	if err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	matchedRPID, err := matchExpectedRPID(parsed.RPIDHash, options.ExpectedRPIDs)
	if err != nil {
		return VerifiedAuthenticationResponse{}, err
	}

	advancedConfigured := options.AdvancedFIDOConfig != nil || options.AdvancedUserVerification != ""
	advancedUserVerification := options.AdvancedUserVerification
	if options.AdvancedFIDOConfig != nil {
		advancedUserVerification = options.AdvancedFIDOConfig.UserVerification
	}
	if advancedConfigured {
		if advancedUserVerification == "required" && !parsed.Flags.UV {
			return VerifiedAuthenticationResponse{}, errors.New("user verification required, but user could not be verified")
		}
	} else {
		if !parsed.Flags.UP {
			return VerifiedAuthenticationResponse{}, errors.New("user not present during authentication")
		}
		if boolDefault(options.RequireUserVerification, true) && !parsed.Flags.UV {
			return VerifiedAuthenticationResponse{}, errors.New("user verification required, but user could not be verified")
		}
	}

	if err := ValidateSignCount(options.Credential.Counter, parsed.Counter); err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	deviceType, backedUp, err := ParseBackupFlags(parsed.Flags)
	if err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	clientDataHash := sha256.Sum256(rawClientData)
	signatureBase := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	signatureBase = append(signatureBase, authenticatorData...)
	signatureBase = append(signatureBase, clientDataHash[:]...)
	signature, err := decodeBase64URL(response.Response.Signature, "signature", MaxSignatureBytes)
	if err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	verified, err := VerifySignature(options.Credential.PublicKey, signature, signatureBase)
	if err != nil {
		return VerifiedAuthenticationResponse{}, err
	}
	return VerifiedAuthenticationResponse{
		Verified: verified,
		AuthenticationInfo: AuthenticationInfo{
			CredentialID:                  options.Credential.ID,
			NewCounter:                    parsed.Counter,
			UserVerified:                  parsed.Flags.UV,
			CredentialDeviceType:          deviceType,
			CredentialBackedUp:            backedUp,
			Origin:                        clientData.Origin,
			RPID:                          matchedRPID,
			AuthenticatorExtensionResults: cloneAnyMap(parsed.ExtensionsData),
		},
	}, nil
}

// ValidateSignCount applies SimpleWebAuthn's replay rule. Authenticators that
// report zero forever are accepted only while both stored and reported values
// remain zero; otherwise the new value must strictly increase.
func ValidateSignCount(stored, reported uint32) error {
	if (reported > 0 || stored > 0) && reported <= stored {
		return fmt.Errorf("response counter value %d was lower than expected %d", reported, stored)
	}
	return nil
}
