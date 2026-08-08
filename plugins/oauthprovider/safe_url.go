package oauthprovider

import "github.com/pers0na2dev/single-auth/internal/coreurl"

// ValidateSafeURL is the OAuth Provider export of single-auth's shared
// SafeUrlSchema policy. It permits HTTPS and custom application schemes,
// permits HTTP only on loopback hosts, and rejects executable schemes and
// fragments.
func ValidateSafeURL(value string) error {
	return coreurl.ValidateSafeURL(value)
}

// IsSafeURL is the boolean form of ValidateSafeURL.
func IsSafeURL(value string) bool {
	return ValidateSafeURL(value) == nil
}
