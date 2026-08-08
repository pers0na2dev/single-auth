package emailotp

import "testing"

func TestIdentifierSplitAndHashUtilities(t *testing.T) {
	for _, test := range []struct {
		kind OTPType
		want string
	}{
		{kind: TypeEmailVerification, want: "email-verification-otp-User@Example.COM"},
		{kind: TypeSignIn, want: "sign-in-otp-User@Example.COM"},
		{kind: TypeForgetPassword, want: "forget-password-otp-User@Example.COM"},
		{kind: TypeChangeEmail, want: "change-email-otp-User@Example.COM"},
	} {
		if got := Identifier(test.kind, "User@Example.COM"); got != test.want {
			t.Errorf("Identifier(%q) = %q, want %q", test.kind, got, test.want)
		}
	}

	for _, test := range []struct {
		input string
		left  string
		right string
	}{
		{input: "123456:0", left: "123456", right: "0"},
		{input: "cipher:with:colons:7", left: "cipher:with:colons", right: "7"},
		{input: "without-attempts", left: "without-attempts"},
		{input: ":3", right: "3"},
	} {
		left, right := SplitStoredValue(test.input)
		if left != test.left || right != test.right {
			t.Errorf("SplitStoredValue(%q) = (%q, %q), want (%q, %q)", test.input, left, right, test.left, test.right)
		}
	}

	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "123456", want: "jZae727K08KaOmKSgOaGzww_XVqGr_PKEgIMkjrcbJI"},
		{input: "000000", want: "kbTRQoI_fSDF8I32kSLeQ_NfBXqYjZYZ9tMThIXJogM"},
		{input: "otp-with-unicode-Ж", want: "P0ZHFnndHeDmmnYfPtCncAeUvAuqMrvabpzyIWtClBs"},
	} {
		if got := defaultHash(test.input); got != test.want {
			t.Errorf("defaultHash(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
