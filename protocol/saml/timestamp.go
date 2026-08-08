package saml

import "time"

// Conditions are the temporal bounds extracted from an assertion.
type Conditions struct {
	NotBefore    string
	NotOnOrAfter string
}

// TimestampValidationOptions configures assertion time validation.
type TimestampValidationOptions struct {
	ClockSkew         *time.Duration
	RequireTimestamps bool
	Now               func() time.Time
	Warn              func(message string, fields map[string]any)
}

// ValidateTimestamp validates NotBefore and NotOnOrAfter with the reference implementation's
// inclusive clock-skew boundaries.
func ValidateTimestamp(conditions *Conditions, options TimestampValidationOptions) error {
	clockSkew := DefaultClockSkew
	if options.ClockSkew != nil {
		clockSkew = *options.ClockSkew
		if clockSkew < 0 {
			return newError("SAML_CLOCK_SKEW_INVALID", "SAML clock skew must not be negative")
		}
	}
	hasTimestamps := conditions != nil &&
		(conditions.NotBefore != "" || conditions.NotOnOrAfter != "")
	if !hasTimestamps {
		if options.RequireTimestamps {
			return newError(
				"SAML_TIMESTAMP_MISSING",
				"SAML assertion missing required timestamp conditions",
			)
		}
		if options.Warn != nil {
			options.Warn(
				"SAML assertion accepted without timestamp conditions",
				map[string]any{"hasConditions": conditions != nil},
			)
		}
		return nil
	}

	now := time.Now()
	if options.Now != nil {
		now = options.Now()
	}
	if conditions.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339Nano, conditions.NotBefore)
		if err != nil {
			return newError(
				"SAML_NOT_BEFORE_INVALID",
				"SAML assertion has invalid NotBefore timestamp",
				err,
			)
		}
		if now.Before(notBefore.Add(-clockSkew)) {
			return newError(
				"SAML_NOT_YET_VALID",
				"SAML assertion is not yet valid",
			)
		}
	}
	if conditions.NotOnOrAfter != "" {
		notOnOrAfter, err := time.Parse(time.RFC3339Nano, conditions.NotOnOrAfter)
		if err != nil {
			return newError(
				"SAML_NOT_ON_OR_AFTER_INVALID",
				"SAML assertion has invalid NotOnOrAfter timestamp",
				err,
			)
		}
		if now.After(notOnOrAfter.Add(clockSkew)) {
			return newError("SAML_EXPIRED", "SAML assertion has expired")
		}
	}
	return nil
}
