package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/url"
	"strings"
	"unicode"
)

// MessageParameter identifies the SAML protocol message carried by a binding.
type MessageParameter string

const (
	SAMLRequestParameter  MessageParameter = "SAMLRequest"
	SAMLResponseParameter MessageParameter = "SAMLResponse"
)

// RedirectMessage is a decoded HTTP-Redirect binding message.
type RedirectMessage struct {
	Parameter  MessageParameter
	XML        []byte
	RelayState string
	SigAlg     string
	Signed     bool
}

// BuildPOSTForm returns the reference implementation's auto-submitting HTTP-POST binding form.
func BuildPOSTForm(
	action string,
	parameter MessageParameter,
	encodedValue string,
	relayState string,
) (string, error) {
	parsed, err := url.Parse(action)
	if err != nil || !parsed.IsAbs() ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", newBadRequest(
			"SAML_POST_BINDING_LOCATION_INVALID",
			"SAML POST binding location must be an absolute http or https URL",
			err,
		)
	}
	if parameter != SAMLRequestParameter && parameter != SAMLResponseParameter {
		return "", newError("SAML_PARAMETER_INVALID", "Invalid SAML binding parameter")
	}
	form := `<!DOCTYPE html><html><body onload="document.forms[0].submit();"><form method="POST" action="` +
		html.EscapeString(action) + `"><input type="hidden" name="` +
		html.EscapeString(string(parameter)) + `" value="` +
		html.EscapeString(encodedValue) + `" />`
	if relayState != "" {
		form += `<input type="hidden" name="RelayState" value="` +
			html.EscapeString(relayState) + `" />`
	}
	form += `<noscript><input type="submit" value="Continue" /></noscript></form></body></html>`
	return form, nil
}

// EncodePOSTMessage encodes XML for the HTTP-POST binding.
func EncodePOSTMessage(xmlData []byte) string {
	return base64.StdEncoding.EncodeToString(xmlData)
}

// EncodeRedirectMessage applies raw DEFLATE and base64 as required by SAML
// Bindings section 3.4.
func EncodeRedirectMessage(xmlData []byte) (string, error) {
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write(xmlData); err != nil {
		_ = writer.Close()
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), nil
}

// DecodeRedirectMessage inflates a base64 Redirect-binding payload with a
// strict decompressed size bound.
func DecodeRedirectMessage(encoded string, maxDecodedBytes int) ([]byte, error) {
	limit := maxDecodedBytes
	if limit <= 0 {
		limit = DefaultMaxResponseSize
	}
	if len(encoded) > limit*8+4096 {
		return nil, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", limit),
		)
	}
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, encoded)
	maxCompressedBytes := limit + limit/4 + 1024
	if len(compact) > base64.StdEncoding.EncodedLen(maxCompressedBytes)+4 {
		return nil, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", limit),
		)
	}
	compressed, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		compressed, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err != nil {
		return nil, newError("SAML_INVALID_ENCODING", "Invalid SAML Redirect encoding", err)
	}
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, newError("SAML_INVALID_ENCODING", "Invalid SAML Redirect encoding", err)
	}
	if len(decoded) > limit {
		return nil, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", limit),
		)
	}
	if len(decoded) == 0 || !bytes.Contains(decoded, []byte("<")) {
		return nil, newError("SAML_INVALID_ENCODING", "Invalid SAML Redirect encoding")
	}
	return decoded, nil
}

// BuildRedirectURL creates a SAML HTTP-Redirect URL and optionally signs its
// exact binding query string. Existing endpoint query parameters are retained
// but are not part of the SAML signature input.
func BuildRedirectURL(
	ctx context.Context,
	endpoint string,
	parameter MessageParameter,
	xmlData []byte,
	relayState string,
	signer crypto.Signer,
	signatureAlgorithm string,
) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || !parsed.IsAbs() ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", newError(
			"SAML_REDIRECT_BINDING_LOCATION_INVALID",
			"SAML Redirect binding location must be an absolute http or https URL",
			err,
		)
	}
	if parameter != SAMLRequestParameter && parameter != SAMLResponseParameter {
		return "", newError("SAML_PARAMETER_INVALID", "Invalid SAML binding parameter")
	}
	encoded, err := EncodeRedirectMessage(xmlData)
	if err != nil {
		return "", err
	}
	parts := []string{string(parameter) + "=" + queryEscape(encoded)}
	if relayState != "" {
		parts = append(parts, "RelayState="+queryEscape(relayState))
	}
	if signer != nil {
		if signatureAlgorithm == "" {
			signatureAlgorithm, err = defaultSignatureAlgorithm(signer)
			if err != nil {
				return "", err
			}
		} else {
			signatureAlgorithm = normalizeSignatureAlgorithm(signatureAlgorithm)
		}
		if err := ValidateSignatureAlgorithm(signatureAlgorithm, AlgorithmValidationOptions{}); err != nil {
			return "", err
		}
		parts = append(parts, "SigAlg="+queryEscape(signatureAlgorithm))
		signedData := strings.Join(parts, "&")
		signature, err := signBinding(signer, signatureAlgorithm, []byte(signedData))
		if err != nil {
			return "", err
		}
		parts = append(parts, "Signature="+queryEscape(base64.StdEncoding.EncodeToString(signature)))
	}
	query := strings.Join(parts, "&")
	if parsed.RawQuery != "" {
		parsed.RawQuery += "&" + query
	} else {
		parsed.RawQuery = query
	}
	return parsed.String(), nil
}

// ParseRedirectBinding decodes a Redirect-binding request or response and, if
// signed, verifies the signature against at least one trusted public key.
func ParseRedirectBinding(
	rawQuery string,
	trustedKeys []crypto.PublicKey,
	algorithmOptions AlgorithmValidationOptions,
	maxDecodedBytes int,
) (RedirectMessage, error) {
	limit := maxDecodedBytes
	if limit <= 0 {
		limit = DefaultMaxResponseSize
	}
	if len(rawQuery) > limit*8+4096 {
		return RedirectMessage{}, newError(
			"SAML_RESPONSE_TOO_LARGE",
			fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", limit),
		)
	}
	parameters, err := parseRawBindingParameters(rawQuery)
	if err != nil {
		return RedirectMessage{}, err
	}
	message := RedirectMessage{
		Parameter:  parameters.parameter,
		RelayState: parameters.relayState,
		SigAlg:     parameters.sigAlg,
		Signed:     parameters.signature != "",
	}
	if parameters.signature != "" {
		if parameters.sigAlg == "" {
			return RedirectMessage{}, newError(
				"SAML_SIGNATURE_ALGORITHM_MISSING",
				"Signed SAML Redirect message is missing SigAlg",
			)
		}
		if len(trustedKeys) == 0 {
			return RedirectMessage{}, newError(
				"SAML_SIGNING_CERTIFICATE_MISSING",
				"No trusted SAML signing certificate is configured",
			)
		}
		if err := ValidateSignatureAlgorithm(parameters.sigAlg, algorithmOptions); err != nil {
			return RedirectMessage{}, err
		}
		signature, err := base64.StdEncoding.DecodeString(parameters.signature)
		if err != nil {
			return RedirectMessage{}, newError(
				"SAML_SIGNATURE_INVALID",
				"Invalid SAML Redirect signature",
				err,
			)
		}
		verified := false
		for _, key := range trustedKeys {
			if verifyBinding(key, parameters.sigAlg, []byte(parameters.signedData), signature) == nil {
				verified = true
				break
			}
		}
		if !verified {
			return RedirectMessage{}, newError(
				"SAML_SIGNATURE_INVALID",
				"Invalid SAML Redirect signature",
			)
		}
	}
	decoded, err := DecodeRedirectMessage(parameters.messageValue, limit)
	if err != nil {
		return RedirectMessage{}, err
	}
	message.XML = decoded
	return message, nil
}

type rawBindingParameters struct {
	parameter    MessageParameter
	messageValue string
	relayState   string
	sigAlg       string
	signature    string
	signedData   string
}

func parseRawBindingParameters(rawQuery string) (rawBindingParameters, error) {
	values := make(map[string]string)
	rawValues := make(map[string]string)
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		name, rawValue, found := strings.Cut(part, "=")
		if !found {
			rawValue = ""
		}
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			return rawBindingParameters{}, newError(
				"SAML_REDIRECT_QUERY_INVALID",
				"Invalid SAML Redirect query",
				err,
			)
		}
		switch decodedName {
		case string(SAMLRequestParameter), string(SAMLResponseParameter), "RelayState", "SigAlg", "Signature":
			if _, duplicate := rawValues[decodedName]; duplicate {
				return rawBindingParameters{}, newError(
					"SAML_REDIRECT_DUPLICATE_PARAMETER",
					"SAML Redirect query contains duplicate protocol parameters",
				)
			}
			decodedValue, err := url.QueryUnescape(rawValue)
			if err != nil {
				return rawBindingParameters{}, newError(
					"SAML_REDIRECT_QUERY_INVALID",
					"Invalid SAML Redirect query",
					err,
				)
			}
			rawValues[decodedName] = rawValue
			values[decodedName] = decodedValue
		}
	}
	requestValue, hasRequest := values[string(SAMLRequestParameter)]
	responseValue, hasResponse := values[string(SAMLResponseParameter)]
	if hasRequest == hasResponse {
		return rawBindingParameters{}, newError(
			"SAML_MESSAGE_MISSING",
			"SAML Redirect query must contain exactly one SAMLRequest or SAMLResponse",
		)
	}
	_, hasSignature := values["Signature"]
	_, hasSignatureAlgorithm := values["SigAlg"]
	if hasSignature != hasSignatureAlgorithm {
		return rawBindingParameters{}, newError(
			"SAML_REDIRECT_SIGNATURE_PARAMETERS_INVALID",
			"SAML Redirect signature requires both SigAlg and Signature",
		)
	}
	parameter := SAMLRequestParameter
	messageValue := requestValue
	if hasResponse {
		parameter = SAMLResponseParameter
		messageValue = responseValue
	}
	parts := []string{string(parameter) + "=" + rawValues[string(parameter)]}
	if rawRelay, ok := rawValues["RelayState"]; ok {
		parts = append(parts, "RelayState="+rawRelay)
	}
	if rawAlgorithm, ok := rawValues["SigAlg"]; ok {
		parts = append(parts, "SigAlg="+rawAlgorithm)
	}
	return rawBindingParameters{
		parameter:    parameter,
		messageValue: messageValue,
		relayState:   values["RelayState"],
		sigAlg:       values["SigAlg"],
		signature:    values["Signature"],
		signedData:   strings.Join(parts, "&"),
	}, nil
}

func queryEscape(value string) string {
	// WHATWG URLSearchParams percent-encodes '~', unlike net/url.
	return strings.ReplaceAll(url.QueryEscape(value), "~", "%7E")
}

func signatureHash(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case SignatureRSASHA1:
		return crypto.SHA1, nil
	case SignatureRSASHA256, SignatureECDSASHA256:
		return crypto.SHA256, nil
	case SignatureRSASHA384, SignatureECDSASHA384:
		return crypto.SHA384, nil
	case SignatureRSASHA512, SignatureECDSASHA512:
		return crypto.SHA512, nil
	default:
		return 0, newError(
			"SAML_UNKNOWN_ALGORITHM",
			fmt.Sprintf("SAML signature algorithm not recognized: %s", algorithm),
		)
	}
}

func signBinding(signer crypto.Signer, algorithm string, data []byte) ([]byte, error) {
	hashAlgorithm, err := signatureHash(algorithm)
	if err != nil {
		return nil, err
	}
	if !hashAlgorithm.Available() {
		return nil, newError("SAML_HASH_UNAVAILABLE", "SAML signature hash is unavailable")
	}
	switch algorithm {
	case SignatureRSASHA1, SignatureRSASHA256, SignatureRSASHA384, SignatureRSASHA512:
		if _, ok := signer.Public().(*rsa.PublicKey); !ok {
			return nil, newError("SAML_SIGNING_KEY_INVALID", "SAML signature algorithm requires an RSA key")
		}
	default:
		if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
			return nil, newError("SAML_SIGNING_KEY_INVALID", "SAML signature algorithm requires an ECDSA key")
		}
	}
	hash := hashAlgorithm.New()
	_, _ = hash.Write(data)
	signature, err := signer.Sign(rand.Reader, hash.Sum(nil), hashAlgorithm)
	if err != nil {
		return nil, newError("SAML_SIGNATURE_FAILED", "Failed to sign SAML Redirect message", err)
	}
	return signature, nil
}

func verifyBinding(
	key crypto.PublicKey,
	algorithm string,
	data []byte,
	signature []byte,
) error {
	hashAlgorithm, err := signatureHash(algorithm)
	if err != nil {
		return err
	}
	hash := hashAlgorithm.New()
	_, _ = hash.Write(data)
	digest := hash.Sum(nil)
	switch publicKey := key.(type) {
	case *rsa.PublicKey:
		if !strings.Contains(algorithm, "rsa-") {
			return newError("SAML_SIGNING_KEY_INVALID", "SAML signature algorithm requires a different key type")
		}
		return rsa.VerifyPKCS1v15(publicKey, hashAlgorithm, digest, signature)
	case *ecdsa.PublicKey:
		if !strings.Contains(algorithm, "ecdsa-") || !ecdsa.VerifyASN1(publicKey, digest, signature) {
			return newError("SAML_SIGNATURE_INVALID", "Invalid SAML Redirect signature")
		}
		return nil
	default:
		return newError("SAML_SIGNING_KEY_INVALID", "Unsupported SAML signing key type")
	}
}

// PublicKeys returns public keys from parsed trusted certificates.
func PublicKeys(certificates []*x509.Certificate) []crypto.PublicKey {
	keys := make([]crypto.PublicKey, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate != nil && certificate.PublicKey != nil {
			keys = append(keys, certificate.PublicKey)
		}
	}
	return keys
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return newError("SAML_REQUEST_CANCELLED", "SAML request cancelled", err)
	}
	return nil
}
