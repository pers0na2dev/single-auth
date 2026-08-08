package webauthn

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

type decodedAttestationObject struct {
	Format   string
	AuthData []byte
	AttStmt  map[string]any
}

func decodeAttestationObject(encoded string) (decodedAttestationObject, []byte, error) {
	raw, err := decodeBase64URL(encoded, "attestationObject", MaxAttestationObjectBytes)
	if err != nil {
		return decodedAttestationObject{}, nil, err
	}
	var object map[string]any
	if err := decodeCBORExact(raw, &object); err != nil {
		return decodedAttestationObject{}, nil, fmt.Errorf("decode attestation object: %w", err)
	}
	format, err := stringField(object["fmt"], "attestation fmt")
	if err != nil {
		return decodedAttestationObject{}, nil, err
	}
	authData, err := byteString(object["authData"], "attestation authData")
	if err != nil {
		return decodedAttestationObject{}, nil, err
	}
	statement, err := mapStringAny(object["attStmt"])
	if err != nil {
		return decodedAttestationObject{}, nil, fmt.Errorf("attestation statement: %w", err)
	}
	return decodedAttestationObject{Format: format, AuthData: authData, AttStmt: statement}, raw, nil
}

func VerifyRegistrationResponse(options VerifyRegistrationOptions) (VerifiedRegistrationResponse, error) {
	response := options.Response
	if err := verifyEnvelope(response.ID, response.RawID, response.Type); err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	clientData, rawClientData, err := DecodeClientDataJSON(response.Response.ClientDataJSON)
	if err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	if err := verifyClientData(clientData, "webauthn.create", "registration", options.ExpectedTypes, options.ExpectedChallenge, options.ChallengeVerifier, options.ExpectedOrigins, true); err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	attestation, rawAttestation, err := decodeAttestationObject(response.Response.AttestationObject)
	if err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	parsed, err := ParseAuthenticatorData(attestation.AuthData)
	if err != nil {
		return VerifiedRegistrationResponse{}, err
	}

	matchedRPID := ""
	if options.ExpectedRPIDs != nil {
		matchedRPID, err = matchExpectedRPID(parsed.RPIDHash, options.ExpectedRPIDs)
		if err != nil {
			return VerifiedRegistrationResponse{}, err
		}
	}
	if boolDefault(options.RequireUserPresence, true) && !parsed.Flags.UP {
		return VerifiedRegistrationResponse{}, errors.New("user presence was required, but user was not present")
	}
	if boolDefault(options.RequireUserVerification, true) && !parsed.Flags.UV {
		return VerifiedRegistrationResponse{}, errors.New("user verification was required, but user could not be verified")
	}
	if len(parsed.CredentialID) == 0 {
		return VerifiedRegistrationResponse{}, errors.New("no credential ID was provided by authenticator")
	}
	if len(parsed.CredentialPublicKey) == 0 {
		return VerifiedRegistrationResponse{}, errors.New("no public key was provided by authenticator")
	}
	if len(parsed.AAGUID) == 0 {
		return VerifiedRegistrationResponse{}, errors.New("no AAGUID was present during registration")
	}
	credentialPublicKey, err := DecodeCredentialPublicKey(parsed.CredentialPublicKey)
	if err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	algorithms := options.SupportedAlgorithmIDs
	if algorithms == nil {
		algorithms = SupportedCOSEAlgorithmIdentifiers
	}
	if !containsInt(algorithms, credentialPublicKey.Alg) {
		parts := make([]string, len(algorithms))
		for index, algorithm := range algorithms {
			parts[index] = fmt.Sprintf("%d", algorithm)
		}
		return VerifiedRegistrationResponse{}, fmt.Errorf("unexpected public key alg %q, expected one of %q", fmt.Sprintf("%d", credentialPublicKey.Alg), strings.Join(parts, ", "))
	}

	clientDataHash := sha256.Sum256(rawClientData)
	verified, err := verifyAttestation(attestationVerificationInput{
		Format:                   attestation.Format,
		Statement:                attestation.AttStmt,
		AuthData:                 attestation.AuthData,
		ClientDataHash:           clientDataHash[:],
		ParsedAuthData:           parsed,
		CredentialPublicKey:      credentialPublicKey,
		Roots:                    options.AttestationRoots,
		Now:                      options.Now,
		SafetyNetEnforceCTSCheck: boolDefault(options.AttestationSafetyNetEnforceCTSCheck, true),
	})
	if err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	if !verified {
		return VerifiedRegistrationResponse{Verified: false}, nil
	}
	deviceType, backedUp, err := ParseBackupFlags(parsed.Flags)
	if err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	aaguid, err := aaguidString(parsed.AAGUID)
	if err != nil {
		return VerifiedRegistrationResponse{}, err
	}
	return VerifiedRegistrationResponse{
		Verified: true,
		RegistrationInfo: &RegistrationInfo{
			Format: attestation.Format,
			AAGUID: aaguid,
			Credential: Credential{
				ID:         encodeBase64URL(parsed.CredentialID),
				PublicKey:  append([]byte(nil), parsed.CredentialPublicKey...),
				Counter:    parsed.Counter,
				Transports: append([]string(nil), response.Response.Transports...),
			},
			CredentialType:                response.Type,
			AttestationObject:             rawAttestation,
			UserVerified:                  parsed.Flags.UV,
			CredentialDeviceType:          deviceType,
			CredentialBackedUp:            backedUp,
			Origin:                        clientData.Origin,
			RPID:                          matchedRPID,
			AuthenticatorExtensionResults: cloneAnyMap(parsed.ExtensionsData),
		},
	}, nil
}
