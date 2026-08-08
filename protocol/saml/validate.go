package saml

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/beevik/etree"
)

// ResponseValidationOptions composes the protocol spike's independent
// validation primitives into the order used by the reference implementation's SAML pipeline.
type ResponseValidationOptions struct {
	MaxResponseSize        int
	ExpectedIssuer         string
	Signatures             SignatureVerificationOptions
	Timestamp              TimestampValidationOptions
	Binding                ResponseBindingValidationOptions
	InResponseTo           InResponseToValidationOptions
	Replay                 AssertionReplayOptions
	EnableReplayProtection *bool
	Decryption             *AssertionDecryptionOptions
}

// AssertionDecryptionOptions enables the encrypted-assertion path. Its
// presence mirrors idpMetadata.isAssertionEncrypted=true; an encrypted
// assertion is then required and is unwrapped with the SP's RSA key.
type AssertionDecryptionOptions struct {
	PrivateKey *rsa.PrivateKey
}

// ValidatedResponse is returned only after signature, time, binding,
// correlation, and replay gates have succeeded.
type ValidatedResponse struct {
	Response      Response
	Signatures    SignatureVerificationResult
	BindingSigned bool
	RelayState    string
	AuthnRequest  *AuthnRequestRecord
	ReplayRecord  *AssertionReplayRecord
}

// ValidatePOSTResponse validates an HTTP-POST SAMLResponse. the reference implementation limits
// the received base64 value before decoding, so this entry point applies both
// encoded and decoded size bounds.
func ValidatePOSTResponse(
	ctx context.Context,
	encodedResponse string,
	relayState string,
	options ResponseValidationOptions,
) (ValidatedResponse, error) {
	maxBytes := responseSizeLimit(options.MaxResponseSize)
	if len([]byte(encodedResponse)) > maxBytes {
		return ValidatedResponse{}, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", maxBytes),
		)
	}
	xmlData, err := DecodePOSTMessage(encodedResponse, maxBytes)
	if err != nil {
		return ValidatedResponse{}, err
	}
	validated, err := validateResponseXML(ctx, xmlData, false, options)
	if err != nil {
		return ValidatedResponse{}, err
	}
	validated.RelayState = relayState
	return validated, nil
}

// ValidateRedirectResponse verifies the exact HTTP-Redirect query signature,
// inflates the SAMLResponse, and runs the common response pipeline. A valid
// Redirect-binding signature satisfies the default "any signature" policy;
// explicit response/assertion/both XML placement policies remain in force.
func ValidateRedirectResponse(
	ctx context.Context,
	rawQuery string,
	trustedKeys []crypto.PublicKey,
	options ResponseValidationOptions,
) (ValidatedResponse, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedResponse{}, err
	}
	message, err := ParseRedirectBinding(
		rawQuery,
		trustedKeys,
		options.Signatures.Algorithms,
		responseSizeLimit(options.MaxResponseSize),
	)
	if err != nil {
		return ValidatedResponse{}, err
	}
	if message.Parameter != SAMLResponseParameter {
		return ValidatedResponse{}, newError(
			"SAML_RESPONSE_MISSING",
			"SAML Redirect binding does not contain a SAMLResponse",
		)
	}
	validated, err := validateResponseXML(ctx, message.XML, message.Signed, options)
	if err != nil {
		return ValidatedResponse{}, err
	}
	validated.RelayState = message.RelayState
	return validated, nil
}

// ValidateResponseXML validates decoded XML. It is useful for framework
// adapters that have already applied a SAML binding.
func ValidateResponseXML(
	ctx context.Context,
	xmlData []byte,
	options ResponseValidationOptions,
) (ValidatedResponse, error) {
	return validateResponseXML(ctx, xmlData, false, options)
}

func validateResponseXML(
	ctx context.Context,
	xmlData []byte,
	bindingSigned bool,
	options ResponseValidationOptions,
) (ValidatedResponse, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedResponse{}, err
	}
	maxBytes := responseSizeLimit(options.MaxResponseSize)
	if len(xmlData) > maxBytes {
		return ValidatedResponse{}, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", maxBytes),
		)
	}
	encrypted := HasEncryptedAssertion(xmlData)
	if options.Decryption != nil && !encrypted {
		return ValidatedResponse{}, newError(
			"SAML_ENCRYPTED_ASSERTION_MISSING",
			"SAML response is missing the required encrypted assertion",
		)
	}
	var originalResponseElement *etree.Element
	if encrypted && options.Decryption != nil {
		if options.Decryption.PrivateKey == nil {
			return ValidatedResponse{}, newError(
				"SAML_DECRYPTION_KEY_MISSING",
				"No SAML assertion decryption private key is configured",
			)
		}
		decrypted, original, decryptErr := decryptResponseAssertion(
			xmlData,
			options.Decryption.PrivateKey,
			options.Signatures.Algorithms,
			maxBytes,
		)
		if decryptErr != nil {
			return ValidatedResponse{}, decryptErr
		}
		xmlData = decrypted
		originalResponseElement = original
	} else if err := ValidateResponseAlgorithms("", xmlData, options.Signatures.Algorithms); err != nil {
		return ValidatedResponse{}, err
	}
	response, err := ParseResponseWithLimit(xmlData, maxBytes)
	if err != nil {
		return ValidatedResponse{}, err
	}
	response.signatureElement = originalResponseElement

	signatureOptions := options.Signatures
	if bindingSigned &&
		(signatureOptions.Requirement == "" || signatureOptions.Requirement == SignatureAny) {
		signatureOptions.Requirement = SignatureNone
	}
	signatures, err := VerifyResponseSignatures(response, signatureOptions)
	if err != nil {
		return ValidatedResponse{}, err
	}
	if err := validateProtocolEnvelope(response, options.ExpectedIssuer); err != nil {
		return ValidatedResponse{}, err
	}
	if err := ValidateTimestamp(&response.Assertion.Conditions, options.Timestamp); err != nil {
		return ValidatedResponse{}, err
	}
	if err := ValidateResponseBinding(response, options.Binding); err != nil {
		return ValidatedResponse{}, err
	}
	if err := validateSubjectConfirmationTimestamps(response, options); err != nil {
		return ValidatedResponse{}, err
	}

	correlationOptions := options.InResponseTo
	if correlationOptions.Now == nil {
		correlationOptions.Now = options.Timestamp.Now
	}
	if len(correlationOptions.ExpectedRecipients) == 0 {
		correlationOptions.ExpectedRecipients = options.Binding.ExpectedRecipients
	}
	correlation, err := ValidateInResponseTo(ctx, response, correlationOptions)
	if err != nil {
		return ValidatedResponse{}, err
	}

	validated := ValidatedResponse{
		Response:      response,
		Signatures:    signatures,
		BindingSigned: bindingSigned,
		AuthnRequest:  correlation,
	}
	if replayProtectionEnabled(options.EnableReplayProtection) {
		replayOptions := options.Replay
		if replayOptions.Now == nil {
			replayOptions.Now = options.Timestamp.Now
		}
		if replayOptions.ClockSkew == nil {
			replayOptions.ClockSkew = options.Timestamp.ClockSkew
		}
		replay, err := ReserveAssertionReplay(ctx, response, replayOptions)
		if err != nil {
			return ValidatedResponse{}, err
		}
		if replay.AssertionID != "" {
			validated.ReplayRecord = &replay
		}
	}
	return validated, nil
}

func validateProtocolEnvelope(response Response, expectedIssuer string) error {
	if response.element != nil && response.element.Tag == "Response" {
		if response.Version != "2.0" {
			return newError(
				"SAML_RESPONSE_VERSION_INVALID",
				"SAML Response Version must be 2.0",
			)
		}
		if response.StatusCode != StatusSuccess {
			return newError(
				"SAML_STATUS_NOT_SUCCESS",
				"SAML Response status is not Success",
			)
		}
		if response.IssueInstant != "" {
			if _, err := time.Parse(time.RFC3339Nano, response.IssueInstant); err != nil {
				return newError(
					"SAML_ISSUE_INSTANT_INVALID",
					"SAML Response has an invalid IssueInstant",
					err,
				)
			}
		}
	}
	if response.Assertion.Version != "2.0" {
		return newError(
			"SAML_ASSERTION_VERSION_INVALID",
			"SAML Assertion Version must be 2.0",
		)
	}
	if response.Assertion.Issuer == "" {
		return newError(
			"SAML_ISSUER_MISSING",
			"SAML Assertion is missing Issuer",
		)
	}
	if response.Assertion.IssueInstant != "" {
		if _, err := time.Parse(time.RFC3339Nano, response.Assertion.IssueInstant); err != nil {
			return newError(
				"SAML_ISSUE_INSTANT_INVALID",
				"SAML Assertion has an invalid IssueInstant",
				err,
			)
		}
	}
	if response.Issuer != "" && response.Assertion.Issuer != "" &&
		response.Issuer != response.Assertion.Issuer {
		return newError(
			"SAML_ISSUER_MISMATCH",
			"SAML Response and Assertion issuers do not match",
		)
	}
	if expectedIssuer != "" {
		if response.Assertion.Issuer != expectedIssuer ||
			(response.Issuer != "" && response.Issuer != expectedIssuer) {
			return newError(
				"SAML_ISSUER_MISMATCH",
				"SAML issuer does not match the configured Identity Provider",
			)
		}
	}
	return nil
}

func validateSubjectConfirmationTimestamps(
	response Response,
	options ResponseValidationOptions,
) error {
	expectedRecipients := stringSet(options.Binding.ExpectedRecipients)
	var lastError error
	matchedRecipient := false
	for _, confirmation := range response.Assertion.SubjectConfirmations {
		if confirmation.Method != BearerConfirmation {
			continue
		}
		if _, matched := expectedRecipients[confirmation.Recipient]; !matched {
			continue
		}
		matchedRecipient = true
		conditions := Conditions{
			NotBefore:    confirmation.NotBefore,
			NotOnOrAfter: confirmation.NotOnOrAfter,
		}
		err := ValidateTimestamp(&conditions, TimestampValidationOptions{
			ClockSkew: options.Timestamp.ClockSkew,
			Now:       options.Timestamp.Now,
		})
		if err == nil {
			return nil
		}
		lastError = err
	}
	if matchedRecipient && lastError != nil {
		return lastError
	}
	return nil
}

func responseSizeLimit(configured int) int {
	if configured <= 0 {
		return DefaultMaxResponseSize
	}
	return configured
}

func replayProtectionEnabled(configured *bool) bool {
	return configured == nil || *configured
}
