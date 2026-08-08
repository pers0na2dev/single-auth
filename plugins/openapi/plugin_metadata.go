package openapi

import "github.com/pers0na2dev/single-auth/core/engine"

func inputPointer(input Input) *Input { value := input; return &value }

func builtInPluginMetadata(endpoint engine.Endpoint) Metadata {
	if metadata, ok := emailOTPMetadata(endpoint); ok {
		return metadata
	}
	if metadata, ok := passkeyMetadata(endpoint); ok {
		return metadata
	}
	return Metadata{}
}

func emailOTPMetadata(endpoint engine.Endpoint) (Metadata, bool) {
	stringField := func(name, description string) Property { return Prop(name, String().Describe(description)) }
	typeField := Prop("type", Enum("sign-in", "email-verification", "forget-password", "change-email").Describe("Type of the OTP"))
	definitions := map[string]struct {
		operationID string
		description string
		body        Input
	}{
		"sendVerificationOTP": {
			"sendEmailVerificationOTP", "Send a verification OTP to an email",
			Object(stringField("email", "Email address to send the OTP"), typeField),
		},
		"checkVerificationOTP": {
			"verifyEmailWithOTP", "Verify an email with an OTP",
			Object(stringField("email", "Email address the OTP was sent to"), typeField, stringField("otp", "OTP to verify")),
		},
		"verifyEmailOTP": {
			"", "Verify email with OTP",
			Object(stringField("email", "Email address to verify"), stringField("otp", "OTP to verify")),
		},
		"signInEmailOTP": {
			"signInWithEmailOTP", "Sign in with email and OTP",
			Intersection(
				Object(
					stringField("email", "Email address to sign in"),
					stringField("otp", "OTP sent to the email"),
					Prop("name", String().Describe("User display name. Only used if the user is registering for the first time.").Optional()),
					Prop("image", String().Describe("User profile image URL. Only used if the user is registering for the first time.").Optional()),
				),
				Record(String(), Any()),
			),
		},
		"requestPasswordResetEmailOTP": {
			"requestPasswordResetWithEmailOTP", "Request password reset with email and OTP",
			Object(stringField("email", "Email address to send the OTP")),
		},
		"forgetPasswordEmailOTP": {
			"forgetPasswordWithEmailOTP", "Deprecated: Use /email-otp/request-password-reset instead.",
			Object(stringField("email", "Email address to send the OTP")),
		},
		"resetPasswordEmailOTP": {
			"resetPasswordWithEmailOTP", "Reset password with email and OTP",
			Object(
				stringField("email", "Email address to reset the password"),
				stringField("otp", "OTP sent to the email"),
				stringField("password", "New password"),
			),
		},
		"requestEmailChangeEmailOTP": {
			"requestEmailChangeWithEmailOTP", "Request email change with verification OTP sent to the new email",
			Object(
				stringField("newEmail", "New email address to send the OTP"),
				Prop("otp", String().Describe("OTP sent to the current email. This is required if changeEmail.verifyCurrentEmail option is set to true").Optional()),
			),
		},
		"changeEmailEmailOTP": {
			"changeEmailWithEmailOTP", "Verify new email with OTP and change the email if verification is successful",
			Object(
				stringField("newEmail", "New email address to verify and change to"),
				stringField("otp", "OTP sent to the new email"),
			),
		},
	}
	definition, exists := definitions[endpoint.Name]
	if !exists {
		return Metadata{}, false
	}
	return Metadata{
		Tags: []string{"Email-otp"}, OperationID: definition.operationID,
		Description: definition.description, Body: inputPointer(definition.body),
	}, true
}

func passkeyMetadata(endpoint engine.Endpoint) (Metadata, bool) {
	if endpoint.Name != "generatePasskeyRegistrationOptions" {
		return Metadata{}, false
	}
	optional := false
	stringSchema := func() *Schema { value := Schema{Type: "string"}; return &value }
	return Metadata{
		Tags: []string{"Passkey"}, OperationID: "generatePasskeyRegistrationOptions",
		Description: "Generate registration options for a new passkey",
		Parameters: []Parameter{
			{
				Name: "authenticatorAttachment", In: "query", Required: &optional,
				Description: "Type of authenticator to use for registration.\n                          \"platform\" for device-specific authenticators,\n                          \"cross-platform\" for authenticators that can be used across devices.",
				Schema:      stringSchema(),
			},
			{
				Name: "name", In: "query", Required: &optional,
				Description: "Optional custom name for the passkey.\n                          This can help identify the passkey when managing multiple credentials.",
				Schema:      stringSchema(),
			},
			{
				Name: "context", In: "query", Required: &optional,
				Description: "Optional context for passkey-first registration flows.", Schema: stringSchema(),
			},
		},
	}, true
}
