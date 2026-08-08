package saml

import (
	"testing"
	"time"
)

// Compatibility cases cover the frozen reference implementation timestamp behavior.
func TestValidateTimestampOracle(t *testing.T) {
	t.Parallel()
	now := func() time.Time { return fixtureNow }
	fiveMinutes := 5 * time.Minute
	zero := time.Duration(0)

	tests := []struct {
		name       string
		conditions *Conditions
		options    TimestampValidationOptions
		wantCode   string
	}{
		{
			name: "current and future",
			conditions: &Conditions{
				NotBefore:    fixtureNow.Format(time.RFC3339Nano),
				NotOnOrAfter: fixtureNow.Add(time.Minute).Format(time.RFC3339Nano),
			},
			options: TimestampValidationOptions{Now: now},
		},
		{
			name: "NotBefore exactly at skew boundary is inclusive",
			conditions: &Conditions{
				NotBefore: fixtureNow.Add(fiveMinutes).Format(time.RFC3339Nano),
			},
			options: TimestampValidationOptions{Now: now},
		},
		{
			name: "future beyond skew",
			conditions: &Conditions{
				NotBefore: fixtureNow.Add(fiveMinutes + time.Nanosecond).Format(time.RFC3339Nano),
			},
			options:  TimestampValidationOptions{Now: now},
			wantCode: "SAML_NOT_YET_VALID",
		},
		{
			name: "NotOnOrAfter exactly at skew boundary is inclusive",
			conditions: &Conditions{
				NotOnOrAfter: fixtureNow.Add(-fiveMinutes).Format(time.RFC3339Nano),
			},
			options: TimestampValidationOptions{Now: now},
		},
		{
			name: "expired beyond skew",
			conditions: &Conditions{
				NotOnOrAfter: fixtureNow.Add(-fiveMinutes - time.Nanosecond).Format(time.RFC3339Nano),
			},
			options:  TimestampValidationOptions{Now: now},
			wantCode: "SAML_EXPIRED",
		},
		{
			name: "explicit zero skew",
			conditions: &Conditions{
				NotBefore: fixtureNow.Add(time.Nanosecond).Format(time.RFC3339Nano),
			},
			options:  TimestampValidationOptions{Now: now, ClockSkew: &zero},
			wantCode: "SAML_NOT_YET_VALID",
		},
		{
			name:       "missing allowed",
			conditions: nil,
			options:    TimestampValidationOptions{Now: now},
		},
		{
			name:       "missing required",
			conditions: nil,
			options: TimestampValidationOptions{
				Now:               now,
				RequireTimestamps: true,
			},
			wantCode: "SAML_TIMESTAMP_MISSING",
		},
		{
			name:       "invalid NotBefore",
			conditions: &Conditions{NotBefore: "not-a-date"},
			options:    TimestampValidationOptions{Now: now},
			wantCode:   "SAML_NOT_BEFORE_INVALID",
		},
		{
			name:       "invalid NotOnOrAfter",
			conditions: &Conditions{NotOnOrAfter: "not-a-date"},
			options:    TimestampValidationOptions{Now: now},
			wantCode:   "SAML_NOT_ON_OR_AFTER_INVALID",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTimestamp(test.conditions, test.options)
			if test.wantCode == "" && err != nil {
				t.Fatalf("ValidateTimestamp() error = %v", err)
			}
			if test.wantCode != "" && !IsErrorCode(err, test.wantCode) {
				t.Fatalf("error = %v, want code %s", err, test.wantCode)
			}
		})
	}
}

func TestValidateTimestampWarningsAndClockSkew(t *testing.T) {
	t.Parallel()
	warned := false
	if err := ValidateTimestamp(&Conditions{}, TimestampValidationOptions{
		Warn: func(message string, fields map[string]any) {
			warned = message != "" && fields["hasConditions"] == true
		},
	}); err != nil {
		t.Fatal(err)
	}
	if !warned {
		t.Fatal("missing timestamps did not warn")
	}
	negative := -time.Second
	if err := ValidateTimestamp(&Conditions{}, TimestampValidationOptions{
		ClockSkew: &negative,
	}); !IsErrorCode(err, "SAML_CLOCK_SKEW_INVALID") {
		t.Fatalf("negative skew error = %v", err)
	}
}
