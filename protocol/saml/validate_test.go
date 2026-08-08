package saml

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestValidatePOSTResponseEndToEnd(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	signedXML := signFixture(t, validResponseFixture(), privateKey, certificate, true, false)
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	if err := store.PutAuthnRequest(context.Background(), AuthnRequestRecord{
		RequestID:  fixtureRequestID,
		ProviderID: "provider",
		CreatedAt:  fixtureNow,
		ExpiresAt:  fixtureNow.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	validated, err := ValidatePOSTResponse(
		context.Background(),
		base64.StdEncoding.EncodeToString(signedXML),
		"relay-state",
		ResponseValidationOptions{
			ExpectedIssuer: fixtureIssuer,
			Signatures: SignatureVerificationOptions{
				Certificates: []*x509.Certificate{certificate},
			},
			Timestamp: TimestampValidationOptions{
				Now: func() time.Time { return fixtureNow },
			},
			Binding: ResponseBindingValidationOptions{
				ExpectedAudiences:  []string{fixtureAudience},
				ExpectedRecipients: []string{fixtureRecipient},
			},
			InResponseTo: InResponseToValidationOptions{
				ProviderID: "provider",
				Store:      store,
			},
			Replay: AssertionReplayOptions{
				ProviderID: "provider",
				Store:      store,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !validated.Signatures.ResponseSigned || validated.Signatures.AssertionSigned ||
		validated.Response.Assertion.NameID != "user@example.com" ||
		validated.Response.Assertion.Attributes["email"][0] != "user@example.com" ||
		validated.AuthnRequest == nil || validated.ReplayRecord == nil ||
		validated.RelayState != "relay-state" {
		t.Fatalf("validated response = %+v", validated)
	}
}

func TestValidateRedirectResponseEndToEnd(t *testing.T) {
	t.Parallel()
	privateKey, certificate := testKeyPair(t)
	redirectURL, err := BuildRedirectURL(
		context.Background(),
		"https://sp.example.com/saml/acs",
		SAMLResponseParameter,
		validResponseFixture(),
		"relay",
		privateKey,
		SignatureRSASHA256,
	)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := ValidateRedirectResponse(
		context.Background(),
		parsedURL.RawQuery,
		PublicKeys([]*x509.Certificate{certificate}),
		ResponseValidationOptions{
			ExpectedIssuer: fixtureIssuer,
			Timestamp: TimestampValidationOptions{
				Now: func() time.Time { return fixtureNow },
			},
			Binding: ResponseBindingValidationOptions{
				ExpectedAudiences:  []string{fixtureAudience},
				ExpectedRecipients: []string{fixtureRecipient},
			},
			InResponseTo: InResponseToValidationOptions{
				EnableValidation: boolPointer(false),
			},
			EnableReplayProtection: boolPointer(false),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !validated.BindingSigned || validated.Signatures.ResponseSigned ||
		validated.RelayState != "relay" {
		t.Fatalf("validated redirect response = %+v", validated)
	}
}

func TestValidateResponsePipelineNegativeCases(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	baseOptions := func() ResponseValidationOptions {
		return ResponseValidationOptions{
			ExpectedIssuer: fixtureIssuer,
			Signatures: SignatureVerificationOptions{
				Certificates: []*x509.Certificate{certificate},
			},
			Timestamp: TimestampValidationOptions{
				Now: func() time.Time { return fixtureNow },
			},
			Binding: ResponseBindingValidationOptions{
				ExpectedAudiences:  []string{fixtureAudience},
				ExpectedRecipients: []string{fixtureRecipient},
			},
			InResponseTo: InResponseToValidationOptions{
				EnableValidation: boolPointer(false),
			},
			EnableReplayProtection: boolPointer(false),
		}
	}

	t.Run("unsigned POST response", func(t *testing.T) {
		if _, err := ValidateResponseXML(context.Background(), validResponseFixture(), baseOptions()); !IsErrorCode(err, "SAML_SIGNATURE_MISSING") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong audience is rejected after signature validation", func(t *testing.T) {
		xmlData := bytes.Replace(
			validResponseFixture(),
			[]byte(fixtureAudience),
			[]byte(otherAudience),
			1,
		)
		signed := signFixture(t, xmlData, privateKey, certificate, true, false)
		if _, err := ValidateResponseXML(context.Background(), signed, baseOptions()); !IsErrorCode(err, "SAML_AUDIENCE_MISMATCH") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("non-success status", func(t *testing.T) {
		xmlData := bytes.Replace(
			validResponseFixture(),
			[]byte(StatusSuccess),
			[]byte("urn:oasis:names:tc:SAML:2.0:status:Responder"),
			1,
		)
		signed := signFixture(t, xmlData, privateKey, certificate, true, false)
		if _, err := ValidateResponseXML(context.Background(), signed, baseOptions()); !IsErrorCode(err, "SAML_STATUS_NOT_SUCCESS") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("expired matching bearer confirmation", func(t *testing.T) {
		xmlData := bytes.Replace(
			validResponseFixture(),
			[]byte(`NotOnOrAfter="2026-08-08T12:05:00Z"`),
			[]byte(`NotOnOrAfter="2026-08-08T11:54:59Z"`),
			1,
		)
		signed := signFixture(t, xmlData, privateKey, certificate, true, false)
		if _, err := ValidateResponseXML(context.Background(), signed, baseOptions()); !IsErrorCode(err, "SAML_EXPIRED") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("response size", func(t *testing.T) {
		options := baseOptions()
		options.MaxResponseSize = 32
		if _, err := ValidateResponseXML(context.Background(), validResponseFixture(), options); !IsErrorCode(err, "SAML_RESPONSE_TOO_LARGE") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestValidateResponseAtomicReplay(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	xmlData := bytes.ReplaceAll(validResponseFixture(), []byte(` InResponseTo="_request"`), nil)
	signed := signFixture(t, xmlData, privateKey, certificate, true, false)
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	options := ResponseValidationOptions{
		ExpectedIssuer: fixtureIssuer,
		Signatures: SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
		},
		Timestamp: TimestampValidationOptions{Now: func() time.Time { return fixtureNow }},
		Binding: ResponseBindingValidationOptions{
			ExpectedAudiences:  []string{fixtureAudience},
			ExpectedRecipients: []string{fixtureRecipient},
		},
		InResponseTo: InResponseToValidationOptions{
			ProviderID: "provider",
			Store:      store,
		},
		Replay: AssertionReplayOptions{
			ProviderID: "provider",
			Store:      store,
		},
	}
	if _, err := ValidateResponseXML(context.Background(), signed, options); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateResponseXML(context.Background(), signed, options); !IsErrorCode(err, "SAML_ASSERTION_REPLAYED") {
		t.Fatalf("second response error = %v", err)
	}
}

func TestValidateResponseConcurrentSPInitiatedOnlyOneSucceeds(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	signed := signFixture(t, validResponseFixture(), privateKey, certificate, true, false)
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	if err := store.PutAuthnRequest(context.Background(), AuthnRequestRecord{
		RequestID:  fixtureRequestID,
		ProviderID: "provider",
		CreatedAt:  fixtureNow,
		ExpiresAt:  fixtureNow.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	options := concurrentValidationOptions(certificate, store)
	errors := runTwoValidations(t, signed, options)
	assertOneSuccessAndOneCode(t, errors, "SAML_IN_RESPONSE_TO_UNKNOWN")
}

func TestValidateResponseConcurrentIDPInitiatedOnlyOneSucceeds(t *testing.T) {
	privateKey, certificate := testKeyPair(t)
	xmlData := bytes.ReplaceAll(validResponseFixture(), []byte(` InResponseTo="_request"`), nil)
	signed := signFixture(t, xmlData, privateKey, certificate, true, false)
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	options := concurrentValidationOptions(certificate, store)
	errors := runTwoValidations(t, signed, options)
	assertOneSuccessAndOneCode(t, errors, "SAML_ASSERTION_REPLAYED")
}

func concurrentValidationOptions(
	certificate *x509.Certificate,
	store *MemoryStore,
) ResponseValidationOptions {
	return ResponseValidationOptions{
		ExpectedIssuer: fixtureIssuer,
		Signatures: SignatureVerificationOptions{
			Certificates: []*x509.Certificate{certificate},
		},
		Timestamp: TimestampValidationOptions{Now: func() time.Time { return fixtureNow }},
		Binding: ResponseBindingValidationOptions{
			ExpectedAudiences:  []string{fixtureAudience},
			ExpectedRecipients: []string{fixtureRecipient},
		},
		InResponseTo: InResponseToValidationOptions{
			ProviderID: "provider",
			Store:      store,
		},
		Replay: AssertionReplayOptions{
			ProviderID: "provider",
			Store:      store,
		},
	}
}

func runTwoValidations(
	t *testing.T,
	xmlData []byte,
	options ResponseValidationOptions,
) []error {
	t.Helper()
	errors := make([]error, 2)
	var waitGroup sync.WaitGroup
	for index := range errors {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, errors[index] = ValidateResponseXML(context.Background(), xmlData, options)
		}()
	}
	waitGroup.Wait()
	return errors
}

func assertOneSuccessAndOneCode(t *testing.T, errors []error, code string) {
	t.Helper()
	successes := 0
	failures := 0
	for _, err := range errors {
		if err == nil {
			successes++
			continue
		}
		if IsErrorCode(err, code) {
			failures++
			continue
		}
		t.Fatalf("unexpected validation error: %v", err)
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes = %d, %s failures = %d", successes, code, failures)
	}
}
