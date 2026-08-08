package emailotp

import (
	"context"
	"testing"
)

func TestPluginDescriptorMatchesReferenceSurface(t *testing.T) {
	harness := newEmailOTPHarness(t, nil)
	descriptor := harness.descriptor
	if descriptor.ID != "email-otp" || descriptor.Version != Version {
		t.Fatalf("descriptor identity: %q %q", descriptor.ID, descriptor.Version)
	}
	if len(descriptor.Endpoints) != 11 || len(descriptor.RateLimit) != 9 || len(descriptor.ErrorCodes) != 3 {
		t.Fatalf("descriptor surface: endpoints=%d rate=%d errors=%d", len(descriptor.Endpoints), len(descriptor.RateLimit), len(descriptor.ErrorCodes))
	}
	if len(descriptor.Schema.Models) != 0 {
		t.Fatalf("email-otp must not add plugin models: %#v", descriptor.Schema.Models)
	}
	for _, rule := range descriptor.RateLimit {
		if rule.Rule.Window != 60 || rule.Rule.Max != 3 {
			t.Fatalf("default rate rule: %#v", rule.Rule)
		}
	}
	for code, message := range errorMessages {
		if descriptor.ErrorCodes[code].Message != message {
			t.Fatalf("error %s: %#v", code, descriptor.ErrorCodes[code])
		}
	}
}

func TestOverrideDefaultVerificationUsesExplicitInstaller(t *testing.T) {
	var installed DefaultVerificationHandler
	harness := newEmailOTPHarness(t, func(options *Options, _ *emailOTPHarness) {
		options.OverrideDefaultEmailVerification = true
		options.SendVerificationOnSignUp = true
		options.Runtime.InstallDefaultVerification = func(handler DefaultVerificationHandler) error {
			installed = handler
			return nil
		}
	})
	if installed == nil {
		t.Fatal("default verification handler was not installed")
	}
	harness.seedUser(t, "override-user", "override@example.com", false)
	if err := installed(context.Background(), "OVERRIDE@EXAMPLE.COM"); err != nil {
		t.Fatal(err)
	}
	message := harness.latestMessage(t)
	if message.Email != "override@example.com" || message.Type != TypeEmailVerification {
		t.Fatalf("installed handler message: %#v", message)
	}
	if matched, err := harness.descriptor.Hooks.After[0].Matcher(nil); err != nil || matched {
		t.Fatalf("override must suppress sign-up hook: matched=%v err=%v", matched, err)
	}
}
