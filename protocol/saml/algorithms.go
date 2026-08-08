package saml

import (
	"fmt"
	"os"
	"strings"

	"github.com/beevik/etree"
)

// DeprecatedAlgorithmBehavior controls compatibility with SHA-1, RSA1_5, and
// 3DES configurations.
type DeprecatedAlgorithmBehavior string

const (
	DeprecatedReject DeprecatedAlgorithmBehavior = "reject"
	DeprecatedWarn   DeprecatedAlgorithmBehavior = "warn"
	DeprecatedAllow  DeprecatedAlgorithmBehavior = "allow"
)

// AlgorithmValidationOptions mirrors the reference implementation's allow-list and deprecated
// algorithm controls. Warn receives the complete security warning.
type AlgorithmValidationOptions struct {
	OnDeprecated                    DeprecatedAlgorithmBehavior
	AllowedSignatureAlgorithms      []string
	AllowedDigestAlgorithms         []string
	AllowedKeyEncryptionAlgorithms  []string
	AllowedDataEncryptionAlgorithms []string
	Warn                            func(string)
}

var secureSignatureAlgorithms = map[string]struct{}{
	SignatureRSASHA256:   {},
	SignatureRSASHA384:   {},
	SignatureRSASHA512:   {},
	SignatureECDSASHA256: {},
	SignatureECDSASHA384: {},
	SignatureECDSASHA512: {},
}

var secureDigestAlgorithms = map[string]struct{}{
	DigestSHA256: {},
	DigestSHA384: {},
	DigestSHA512: {},
}

var shortSignatureAlgorithms = map[string]string{
	"sha1":         SignatureRSASHA1,
	"sha256":       SignatureRSASHA256,
	"sha384":       SignatureRSASHA384,
	"sha512":       SignatureRSASHA512,
	"rsa-sha1":     SignatureRSASHA1,
	"rsa-sha256":   SignatureRSASHA256,
	"rsa-sha384":   SignatureRSASHA384,
	"rsa-sha512":   SignatureRSASHA512,
	"ecdsa-sha256": SignatureECDSASHA256,
	"ecdsa-sha384": SignatureECDSASHA384,
	"ecdsa-sha512": SignatureECDSASHA512,
}

var shortDigestAlgorithms = map[string]string{
	"sha1":   DigestSHA1,
	"sha256": DigestSHA256,
	"sha384": DigestSHA384,
	"sha512": DigestSHA512,
}

func normalizeSignatureAlgorithm(value string) string {
	if normalized, ok := shortSignatureAlgorithms[strings.ToLower(value)]; ok {
		return normalized
	}
	return value
}

func normalizeDigestAlgorithm(value string) string {
	if normalized, ok := shortDigestAlgorithms[strings.ToLower(value)]; ok {
		return normalized
	}
	return value
}

func deprecatedBehavior(options AlgorithmValidationOptions) DeprecatedAlgorithmBehavior {
	if options.OnDeprecated == "" {
		return DeprecatedWarn
	}
	return options.OnDeprecated
}

func handleDeprecated(
	message string,
	code string,
	options AlgorithmValidationOptions,
) error {
	switch deprecatedBehavior(options) {
	case DeprecatedReject:
		return newAlgorithmBadRequest(code, message)
	case DeprecatedAllow:
		return nil
	case DeprecatedWarn:
		warning := "[SAML Security Warning] " + message
		if options.Warn != nil {
			options.Warn(warning)
		} else {
			_, _ = fmt.Fprintln(os.Stderr, warning)
		}
		return nil
	default:
		// A runtime value outside the supported set falls through unchanged.
		return nil
	}
}

func newAlgorithmBadRequest(code, message string) *APIError {
	err := newBadRequest(code, message)
	err.Body["code"] = code
	return err
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// ValidateSignatureAlgorithm validates one XMLDSIG or Redirect-binding
// SignatureMethod URI.
func ValidateSignatureAlgorithm(
	algorithm string,
	options AlgorithmValidationOptions,
) error {
	if algorithm == "" {
		return nil
	}
	if options.AllowedSignatureAlgorithms != nil {
		if !containsString(options.AllowedSignatureAlgorithms, algorithm) {
			return newAlgorithmBadRequest(
				"SAML_ALGORITHM_NOT_ALLOWED",
				fmt.Sprintf("SAML signature algorithm not in allow-list: %s", algorithm),
			)
		}
		return nil
	}
	if algorithm == SignatureRSASHA1 {
		return handleDeprecated(
			fmt.Sprintf(
				"SAML response uses deprecated signature algorithm: %s. Please configure your IdP to use SHA-256 or stronger.",
				algorithm,
			),
			"SAML_DEPRECATED_ALGORITHM",
			options,
		)
	}
	if _, ok := secureSignatureAlgorithms[algorithm]; !ok {
		return newAlgorithmBadRequest(
			"SAML_UNKNOWN_ALGORITHM",
			fmt.Sprintf("SAML signature algorithm not recognized: %s", algorithm),
		)
	}
	return nil
}

// ValidateDigestAlgorithm validates one XMLDSIG DigestMethod URI.
func ValidateDigestAlgorithm(
	algorithm string,
	options AlgorithmValidationOptions,
) error {
	if algorithm == "" {
		return newError("SAML_DIGEST_ALGORITHM_MISSING", "SAML digest algorithm is missing")
	}
	if options.AllowedDigestAlgorithms != nil {
		if !containsString(options.AllowedDigestAlgorithms, algorithm) {
			return newAlgorithmBadRequest(
				"SAML_ALGORITHM_NOT_ALLOWED",
				fmt.Sprintf("SAML digest algorithm not in allow-list: %s", algorithm),
			)
		}
		return nil
	}
	if algorithm == DigestSHA1 {
		return handleDeprecated(
			fmt.Sprintf(
				"SAML response uses deprecated digest algorithm: %s. Please configure your IdP to use SHA-256 or stronger.",
				algorithm,
			),
			"SAML_DEPRECATED_ALGORITHM",
			options,
		)
	}
	if _, ok := secureDigestAlgorithms[algorithm]; !ok {
		return newAlgorithmBadRequest(
			"SAML_UNKNOWN_ALGORITHM",
			fmt.Sprintf("SAML digest algorithm not recognized: %s", algorithm),
		)
	}
	return nil
}

// ValidateResponseAlgorithms applies the reference implementation's response algorithm policy
// and inspects encrypted assertions for deprecated key/data algorithms.
func ValidateResponseAlgorithms(
	signatureAlgorithm string,
	xmlData []byte,
	options AlgorithmValidationOptions,
) error {
	if err := ValidateSignatureAlgorithm(signatureAlgorithm, options); err != nil {
		return err
	}
	document, err := parseXML(xmlData, 0)
	if err != nil {
		// the reference implementation skips encryption inspection when XML parsing fails; the
		// structural/parser stage remains responsible for rejecting the XML.
		return nil
	}
	if len(descendantsByTag(document.Root(), "EncryptedAssertion")) == 0 {
		return nil
	}

	var keyAlgorithm string
	if encryptedKeys := descendantsByTag(document.Root(), "EncryptedKey"); len(encryptedKeys) > 0 {
		if method := firstDirectAlgorithmChild(encryptedKeys[0], "EncryptionMethod"); method != nil {
			keyAlgorithm = method.SelectAttrValue("Algorithm", "")
		}
	}
	var dataAlgorithm string
	if encryptedData := descendantsByTag(document.Root(), "EncryptedData"); len(encryptedData) > 0 {
		if method := firstDirectAlgorithmChild(encryptedData[0], "EncryptionMethod"); method != nil {
			dataAlgorithm = method.SelectAttrValue("Algorithm", "")
		}
	}
	return ValidateEncryptionAlgorithms(keyAlgorithm, dataAlgorithm, options)
}

// ValidateEncryptionAlgorithms applies the reference implementation's allow-list and legacy
// algorithm policy to the exact key/data algorithm pair selected for
// decryption. Keeping this separate from the loose response scanner prevents
// an unrelated EncryptedKey node from bypassing a configured allow-list.
func ValidateEncryptionAlgorithms(
	keyAlgorithm string,
	dataAlgorithm string,
	options AlgorithmValidationOptions,
) error {
	if err := validateEncryptionAlgorithm(
		"key",
		keyAlgorithm,
		options.AllowedKeyEncryptionAlgorithms,
		KeyEncryptionRSA15,
		"SAML response uses deprecated key encryption algorithm: %s. Please configure your IdP to use RSA-OAEP.",
		options,
	); err != nil {
		return err
	}
	return validateEncryptionAlgorithm(
		"data",
		dataAlgorithm,
		options.AllowedDataEncryptionAlgorithms,
		DataEncryptionTripleDESCBC,
		"SAML response uses deprecated data encryption algorithm: %s. Please configure your IdP to use AES-GCM.",
		options,
	)
}

func firstDirectAlgorithmChild(parent *etree.Element, tag string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}
	return nil
}

func validateEncryptionAlgorithm(
	kind string,
	algorithm string,
	allowList []string,
	deprecated string,
	deprecatedMessage string,
	options AlgorithmValidationOptions,
) error {
	if algorithm == "" {
		return nil
	}
	if allowList != nil && !containsString(allowList, algorithm) {
		return newAlgorithmBadRequest(
			"SAML_ALGORITHM_NOT_ALLOWED",
			fmt.Sprintf("SAML %s encryption algorithm not in allow-list: %s", kind, algorithm),
		)
	}
	if allowList == nil && algorithm == deprecated {
		return handleDeprecated(
			fmt.Sprintf(deprecatedMessage, algorithm),
			"SAML_DEPRECATED_ALGORITHM",
			options,
		)
	}
	return nil
}

// ConfigAlgorithms are the signature and digest algorithms selected for an
// outgoing Service Provider configuration.
type ConfigAlgorithms struct {
	SignatureAlgorithm string
	DigestAlgorithm    string
}

// ValidateConfigAlgorithms accepts the reference implementation's short algorithm names and
// applies its exact allow-list/deprecation semantics.
func ValidateConfigAlgorithms(
	config ConfigAlgorithms,
	options AlgorithmValidationOptions,
) error {
	if config.SignatureAlgorithm != "" {
		normalized := normalizeSignatureAlgorithm(config.SignatureAlgorithm)
		if options.AllowedSignatureAlgorithms != nil {
			allowed := false
			for _, candidate := range options.AllowedSignatureAlgorithms {
				if normalizeSignatureAlgorithm(candidate) == normalized {
					allowed = true
					break
				}
			}
			if !allowed {
				return newAlgorithmBadRequest(
					"SAML_ALGORITHM_NOT_ALLOWED",
					fmt.Sprintf(
						"SAML signature algorithm not in allow-list: %s",
						config.SignatureAlgorithm,
					),
				)
			}
		} else if normalized == SignatureRSASHA1 {
			if err := handleDeprecated(
				fmt.Sprintf(
					"SAML config uses deprecated signature algorithm: %s. Consider using SHA-256 or stronger.",
					config.SignatureAlgorithm,
				),
				"SAML_DEPRECATED_CONFIG_ALGORITHM",
				options,
			); err != nil {
				return err
			}
		} else if _, ok := secureSignatureAlgorithms[normalized]; !ok {
			return newAlgorithmBadRequest(
				"SAML_UNKNOWN_ALGORITHM",
				fmt.Sprintf(
					"SAML signature algorithm not recognized: %s",
					config.SignatureAlgorithm,
				),
			)
		}
	}

	if config.DigestAlgorithm == "" {
		return nil
	}
	normalized := normalizeDigestAlgorithm(config.DigestAlgorithm)
	if options.AllowedDigestAlgorithms != nil {
		allowed := false
		for _, candidate := range options.AllowedDigestAlgorithms {
			if normalizeDigestAlgorithm(candidate) == normalized {
				allowed = true
				break
			}
		}
		if !allowed {
			return newAlgorithmBadRequest(
				"SAML_ALGORITHM_NOT_ALLOWED",
				fmt.Sprintf(
					"SAML digest algorithm not in allow-list: %s",
					config.DigestAlgorithm,
				),
			)
		}
		return nil
	}
	if normalized == DigestSHA1 {
		return handleDeprecated(
			fmt.Sprintf(
				"SAML config uses deprecated digest algorithm: %s. Consider using SHA-256 or stronger.",
				config.DigestAlgorithm,
			),
			"SAML_DEPRECATED_CONFIG_ALGORITHM",
			options,
		)
	}
	if _, ok := secureDigestAlgorithms[normalized]; !ok {
		return newAlgorithmBadRequest(
			"SAML_UNKNOWN_ALGORITHM",
			fmt.Sprintf(
				"SAML digest algorithm not recognized: %s",
				config.DigestAlgorithm,
			),
		)
	}
	return nil
}
