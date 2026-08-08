package webauthn

import (
	"errors"
	"fmt"
)

func GenerateRegistrationOptions(input GenerateRegistrationOptionsInput) (CreationOptionsJSON, error) {
	challenge, err := challengeBytes(input.Challenge, input.Random)
	if err != nil {
		return CreationOptionsJSON{}, err
	}
	userID := append([]byte(nil), input.UserID...)
	if input.UserID == nil {
		userID, err = randomBytes(input.Random, 32)
		if err != nil {
			return CreationOptionsJSON{}, fmt.Errorf("generate user ID: %w", err)
		}
	}
	timeout := input.Timeout
	if input.TimeoutMS != nil {
		timeout = *input.TimeoutMS
	} else if timeout == 0 {
		timeout = DefaultTimeoutMS
	}
	attestation := input.AttestationType
	if attestation == "" {
		attestation = "none"
	}

	algorithms := input.SupportedAlgorithmIDs
	if algorithms == nil {
		algorithms = DefaultRegistrationAlgorithmIdentifiers
	}
	parameters := make([]CredentialParameter, len(algorithms))
	for index, algorithm := range algorithms {
		parameters[index] = CredentialParameter{Alg: algorithm, Type: PublicKeyCredentialType}
	}

	excluded := make([]CredentialDescriptor, len(input.ExcludeCredentials))
	for index, credential := range input.ExcludeCredentials {
		if _, err := decodeBase64URL(credential.ID, "excludeCredential ID", MaxCredentialIDBytes); errors.Is(err, ErrInvalidBase64URL) {
			return CreationOptionsJSON{}, fmt.Errorf("excludeCredential id %q is not a valid base64url string", credential.ID)
		} else if err != nil {
			return CreationOptionsJSON{}, err
		}
		credential.ID = trimBase64URLPadding(credential.ID)
		credential.Type = PublicKeyCredentialType
		credential.Transports = append([]string(nil), credential.Transports...)
		excluded[index] = credential
	}

	selection := AuthenticatorSelectionCriteria{}
	if input.AuthenticatorSelection == nil {
		resident := false
		selection = AuthenticatorSelectionCriteria{
			ResidentKey:        "preferred",
			RequireResidentKey: &resident,
			UserVerification:   "preferred",
		}
	} else {
		selection = *input.AuthenticatorSelection
		if selection.ResidentKey == "" {
			if selection.RequireResidentKey != nil && *selection.RequireResidentKey {
				selection.ResidentKey = "required"
			}
		} else {
			required := selection.ResidentKey == "required"
			selection.RequireResidentKey = &required
		}
	}

	hints := []string{}
	switch input.PreferredAuthenticatorType {
	case "":
	case "securityKey":
		hints = append(hints, "security-key")
		selection.AuthenticatorAttachment = "cross-platform"
	case "localDevice":
		hints = append(hints, "client-device")
		selection.AuthenticatorAttachment = "platform"
	case "remoteDevice":
		hints = append(hints, "hybrid")
		selection.AuthenticatorAttachment = "cross-platform"
	default:
		// The TypeScript API narrows this value, but an unknown runtime value is
		// ignored rather than rejected.
	}

	extensions := make(map[string]any, len(input.Extensions)+1)
	for key, value := range input.Extensions {
		extensions[key] = value
	}
	extensions["credProps"] = true

	return CreationOptionsJSON{
		Challenge:              encodeBase64URL(challenge),
		RP:                     RelyingPartyEntity{Name: input.RPName, ID: input.RPID},
		User:                   UserEntity{ID: encodeBase64URL(userID), Name: input.UserName, DisplayName: input.UserDisplayName},
		PubKeyCredParams:       parameters,
		Timeout:                timeout,
		Attestation:            attestation,
		ExcludeCredentials:     excluded,
		AuthenticatorSelection: selection,
		Extensions:             extensions,
		Hints:                  hints,
	}, nil
}

func GenerateAuthenticationOptions(input GenerateAuthenticationOptionsInput) (RequestOptionsJSON, error) {
	challenge, err := challengeBytes(input.Challenge, input.Random)
	if err != nil {
		return RequestOptionsJSON{}, err
	}
	timeout := input.Timeout
	if input.TimeoutMS != nil {
		timeout = *input.TimeoutMS
	} else if timeout == 0 {
		timeout = DefaultTimeoutMS
	}
	userVerification := input.UserVerification
	if userVerification == "" {
		userVerification = "preferred"
	}

	var allowed []CredentialDescriptor
	if input.AllowCredentials != nil {
		allowed = make([]CredentialDescriptor, len(input.AllowCredentials))
		for index, credential := range input.AllowCredentials {
			if _, err := decodeBase64URL(credential.ID, "allowCredential ID", MaxCredentialIDBytes); errors.Is(err, ErrInvalidBase64URL) {
				return RequestOptionsJSON{}, fmt.Errorf("allowCredential id %q is not a valid base64url string", credential.ID)
			} else if err != nil {
				return RequestOptionsJSON{}, err
			}
			credential.ID = trimBase64URLPadding(credential.ID)
			credential.Type = PublicKeyCredentialType
			credential.Transports = append([]string(nil), credential.Transports...)
			allowed[index] = credential
		}
	}

	var extensions map[string]any
	if input.Extensions != nil {
		extensions = make(map[string]any, len(input.Extensions))
		for key, value := range input.Extensions {
			extensions[key] = value
		}
	}
	return RequestOptionsJSON{
		RPID:             input.RPID,
		Challenge:        encodeBase64URL(challenge),
		AllowCredentials: allowed,
		Timeout:          timeout,
		UserVerification: userVerification,
		Extensions:       extensions,
	}, nil
}
