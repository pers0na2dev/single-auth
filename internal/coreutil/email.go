// Package coreutil contains transport-neutral helpers mirrored from the
// the reference implementation core package.
package coreutil

import (
	"errors"
	"regexp"
	"strings"
)

const PlaceholderEmailDomain = "placeholder.invalid"

// ErrInvalidPlaceholderEmail matches the error raised by the reference implementation when a
// generated placeholder address does not satisfy Zod's default email format.
var ErrInvalidPlaceholderEmail = errors.New("Invalid placeholder email")

// PlaceholderEmailOptions identifies a non-routable account email.
type PlaceholderEmailOptions struct {
	Identifier string
	Namespace  string
}

// This is Zod 4's default email expression without the two lookaheads, which
// are checked explicitly because Go's RE2 syntax intentionally omits them.
var zodEmailPattern = regexp.MustCompile(`(?i)^[a-z0-9_'+.\-]*[a-z0-9_+\-]@([a-z0-9][a-z0-9\-]*\.)+[a-z]{2,}$`)

// CreatePlaceholderEmail creates the stable, reserved-domain address used by
// the reference implementation for accounts whose identity provider supplies no email.
func CreatePlaceholderEmail(options PlaceholderEmailOptions) (string, error) {
	result := options.Identifier + "@" + options.Namespace + "." + PlaceholderEmailDomain
	local, _, found := strings.Cut(result, "@")
	if !found || strings.HasPrefix(local, ".") || strings.Contains(local, "..") || !zodEmailPattern.MatchString(result) {
		return "", ErrInvalidPlaceholderEmail
	}
	return result, nil
}
