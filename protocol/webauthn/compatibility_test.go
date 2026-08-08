package webauthn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func boolPointer(value bool) *bool { return &value }

func TestGenerateRegistrationOptionsMatchesSimpleWebAuthn1323(t *testing.T) {
	options, err := GenerateRegistrationOptions(GenerateRegistrationOptionsInput{
		RPName: "SimpleWebAuthn", RPID: "not.real", UserName: "usernameHere",
		UserID: []byte("1234"), Challenge: "totallyrandomvalue",
		UserDisplayName: "userDisplayName", Timeout: 1, AttestationType: "direct",
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"challenge":"dG90YWxseXJhbmRvbXZhbHVl","rp":{"name":"SimpleWebAuthn","id":"not.real"},"user":{"id":"MTIzNA","name":"usernameHere","displayName":"userDisplayName"},"pubKeyCredParams":[{"alg":-8,"type":"public-key"},{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"}],"timeout":1,"attestation":"direct","excludeCredentials":[],"authenticatorSelection":{"residentKey":"preferred","requireResidentKey":false,"userVerification":"preferred"},"extensions":{"credProps":true},"hints":[]}`
	if string(encoded) != want {
		t.Fatalf("registration options mismatch\n got: %s\nwant: %s", encoded, want)
	}
}

func TestGenerateOptionsCases(t *testing.T) {
	t.Run("UTF-8 string challenge", func(t *testing.T) {
		options, err := GenerateAuthenticationOptions(GenerateAuthenticationOptionsInput{RPID: "simplewebauthn.dev", Challenge: "こんにちは"})
		if err != nil {
			t.Fatal(err)
		}
		if options.Challenge != "44GT44KT44Gr44Gh44Gv" || options.Timeout != 60000 || options.UserVerification != "preferred" {
			t.Fatalf("unexpected options: %#v", options)
		}
	})
	t.Run("credential padding trimmed", func(t *testing.T) {
		options, err := GenerateAuthenticationOptions(GenerateAuthenticationOptionsInput{RPID: "example.com", Challenge: []byte{1}, AllowCredentials: []CredentialDescriptor{{ID: "AQ==", Transports: []string{"usb"}}}})
		if err != nil {
			t.Fatal(err)
		}
		if got := options.AllowCredentials[0]; got.ID != "AQ" || got.Type != "public-key" {
			t.Fatalf("unexpected descriptor: %#v", got)
		}
	})
	t.Run("explicit zero timeout", func(t *testing.T) {
		zero := 0
		options, err := GenerateAuthenticationOptions(GenerateAuthenticationOptionsInput{RPID: "example.com", Challenge: []byte{1}, TimeoutMS: &zero})
		if err != nil {
			t.Fatal(err)
		}
		if options.Timeout != 0 {
			t.Fatalf("timeout = %d", options.Timeout)
		}
	})
	t.Run("invalid credential ID", func(t *testing.T) {
		_, err := GenerateAuthenticationOptions(GenerateAuthenticationOptionsInput{RPID: "example.com", Challenge: []byte{1}, AllowCredentials: []CredentialDescriptor{{ID: "not+base64url"}}})
		if err == nil || err.Error() != `allowCredential id "not+base64url" is not a valid base64url string` {
			t.Fatalf("error = %v", err)
		}
	})
	for _, test := range []struct {
		name      string
		selection AuthenticatorSelectionCriteria
		resident  string
		required  bool
	}{
		{"require infers resident", AuthenticatorSelectionCriteria{RequireResidentKey: boolPointer(true)}, "required", true},
		{"required infers require", AuthenticatorSelectionCriteria{ResidentKey: "required"}, "required", true},
		{"preferred clears require", AuthenticatorSelectionCriteria{ResidentKey: "preferred", RequireResidentKey: boolPointer(true)}, "preferred", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, err := GenerateRegistrationOptions(GenerateRegistrationOptionsInput{RPName: "rp", RPID: "example.com", UserName: "user", UserID: []byte{1}, Challenge: []byte{2}, AuthenticatorSelection: &test.selection})
			if err != nil {
				t.Fatal(err)
			}
			if options.AuthenticatorSelection.ResidentKey != test.resident || options.AuthenticatorSelection.RequireResidentKey == nil || *options.AuthenticatorSelection.RequireResidentKey != test.required {
				t.Fatalf("unexpected selection: %#v", options.AuthenticatorSelection)
			}
		})
	}
}

func TestParseAuthenticatorDataUpstreamVectors(t *testing.T) {
	withAT, err := base64.StdEncoding.DecodeString("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAJch83ZdWwUm4niTLNjZU81AAIHa7Ksm5br3hAh3UjxP9+4rqu8BEsD+7SZ2xWe1/yHv6pAEDAzkBACBZAQDcxA7Ehs9goWB2Hbl6e9v+aUub9rvy2M7Hkvf+iCzMGE63e3sCEW5Ru33KNy4um46s9jalcBHtZgtEnyeRoQvszis+ws5o4Da0vQfuzlpBmjWT1dV6LuP+vs9wrfObW4jlA5bKEIhv63+jAxOtdXGVzo75PxBlqxrmrr5IR9n8Fw7clwRsDkjgRHaNcQVbwq/qdNwU5H3hZKu9szTwBS5NGRq01EaDF2014YSTFjwtAmZ3PU1tcO/QD2U2zg6eB5grfWDeAJtRE8cbndDWc8aLL0aeC37Q36+TVsGe6AhBgHEw6eO3I3NW5r9v/26CqMPBDwmEundeq1iGyKfMloobIUMBAAE=")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthenticatorData(withAT)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Flags.AT || parsed.Counter != 37 || encodeBase64URL(parsed.CredentialID) != "drsqybluveECHdSPE_37iuq7wESwP7tJnbFZ7X_Ie_o" {
		t.Fatalf("unexpected parsed authenticator data: %#v", parsed)
	}
	if got := base64.StdEncoding.EncodeToString(parsed.AAGUID); got != "yHzdl1bBSbieJMs2NlTzUA==" {
		t.Fatalf("AAGUID = %s", got)
	}
	if got := base64.StdEncoding.EncodeToString(parsed.CredentialPublicKey); got != "pAEDAzkBACBZAQDcxA7Ehs9goWB2Hbl6e9v+aUub9rvy2M7Hkvf+iCzMGE63e3sCEW5Ru33KNy4um46s9jalcBHtZgtEnyeRoQvszis+ws5o4Da0vQfuzlpBmjWT1dV6LuP+vs9wrfObW4jlA5bKEIhv63+jAxOtdXGVzo75PxBlqxrmrr5IR9n8Fw7clwRsDkjgRHaNcQVbwq/qdNwU5H3hZKu9szTwBS5NGRq01EaDF2014YSTFjwtAmZ3PU1tcO/QD2U2zg6eB5grfWDeAJtRE8cbndDWc8aLL0aeC37Q36+TVsGe6AhBgHEw6eO3I3NW5r9v/26CqMPBDwmEundeq1iGyKfMloobIUMBAAE=" {
		t.Fatalf("credential public key = %s", got)
	}

	withED, err := base64.StdEncoding.DecodeString("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2OBAAAAjaFxZXhhbXBsZS5leHRlbnNpb254dlRoaXMgaXMgYW4gZXhhbXBsZSBleHRlbnNpb24hIElmIHlvdSByZWFkIHRoaXMgbWVzc2FnZSwgeW91IHByb2JhYmx5IHN1Y2Nlc3NmdWxseSBwYXNzaW5nIGNvbmZvcm1hbmNlIHRlc3RzLiBHb29kIGpvYiE=")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseAuthenticatorData(withED)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ExtensionsData["example.extension"] != "This is an example extension! If you read this message, you probably successfully passing conformance tests. Good job!" {
		t.Fatalf("extensions = %#v", parsed.ExtensionsData)
	}

	t.Run("Firefox 117 malformed EdDSA CBOR", func(t *testing.T) {
		const encoded = "b40499b0271a68957267de4ec40056a74c8758c6582e1e01fcf357d73101e7ba450000000400000000000000000000000000000000008072d3a1a3fa7cf32f44367df847585ff0850c7bd62c338ab45be1fda6fdb79982f96c20efc0bb6ed9347e8c1e77690e67b225b485a098f6f46fde3f2a85acd0177a04d6bb5c7566fb89881dfe48ea7abc361f7acaf86a5966adef557930fa5c045c636f50cf938e508a81b845134eb2988dc3af0ab6f98cfc615532684b4a6363a301634f4b50032720674564323535313921982018d51858187318e6188918eb18ab187e18fd18fd185d184b08184b187318e818e118f818c71518ff18f5183a18fd18a3186b185f1109183e183b14"
		authData, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		original := append([]byte(nil), authData...)
		parsed, err := ParseAuthenticatorData(authData)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.Flags.AT || !bytes.Equal(authData, original) {
			t.Fatalf("malformed Firefox data was not parsed without mutation: flags=%#v", parsed.Flags)
		}
	})
}

func TestVerifyNoneRegistrationUpstreamVector(t *testing.T) {
	response := upstreamNoneRegistration()
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:          response,
		ExpectedChallenge: "aEVjY1BXdXppUDAwSDBwNWd4aDJfdTVfUEM0TmVZZ2Q",
		ExpectedOrigins:   []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:     []string{"dev.dontneeda.pw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil {
		t.Fatalf("verification = %#v", verification)
	}
	info := verification.RegistrationInfo
	if info.Format != "none" || info.Credential.Counter != 0 || info.Credential.ID != response.ID || info.AAGUID != "00000000-0000-0000-0000-000000000000" || !info.UserVerified {
		t.Fatalf("registration info = %#v", info)
	}
}

func TestVerifyPackedSelfAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID: "bbb", RawID: "bbb", Type: "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhANvrPZMUFrl_rvlgRqz6lCPlF6B4y885FYUCCrhrzAYXAiAb4dQKXbP3IimsTTadkwXQlrRVdxzlbmPXt847-Oh6r2hhdXRoRGF0YVjhPdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KBFXsOO-a3OAAI1vMYKZIsLJfHwVQMAXQGE4WNXLCDWOCa2x8hpqk5dZy_xdc4wBd4UgCJ4M_JAHI7oJgDDVb8WUcKqRB_mzRxwCL9vdTl-ZKPXg3_-Zrt1Adgb7EnK9ivqaTOKMDqRrKsIObWYJaqpsSJtUKUBAgMmIAEhWCBKMVVaivqCBpqqAxMjuCo5jMeUdh3jDOC0EF4fLBNNTyJYILc7rqDDeX1pwCLrl3ZX7IThrtZNwKQVLQyfHiorqP-n",
			ClientDataJSON:    "eyJjaGFsbGVuZ2UiOiJjelpRU1dKQ2JsQlFibkpIVGxOQ2VFNWtkRVJ5VkRkVmNsWlpTa3M1U0UwIiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
		},
	}
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:          response,
		ExpectedChallenge: "czZQSWJCblBQbnJHTlNCeE5kdERyVDdVclZZSks5SE0",
		ExpectedOrigins:   []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:     []string{"dev.dontneeda.pw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "packed" || verification.RegistrationInfo.Credential.Counter != 1589874425 {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyFIDOU2FAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID:    "VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ",
		RawID: "VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ",
		Type:  "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgRYUftNUmhT0VWTZmIgDmrOoP26Pcre-kL3DLnCrXbegCIQCOu_x5gqp-Rej76zeBuXlk8e7J-9WM_i-wZmCIbIgCGmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAAAAAAAAAAAAAAAAAAAAAAAABAVHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUaUBAgMmIAEhWCDIkcsOaVKDIQYwq3EDQ-pST2kRwNH_l1nCgW-WcFpNXiJYIBSbummp-KO3qZeqmvZ_U_uirCDL2RNj3E5y4_KzefIr",
			ClientDataJSON:    "eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sQmRIUmxjM1JoZEdsdmJnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
		},
	}
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:                response,
		ExpectedChallenge:       "dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlBdHRlc3RhdGlvbg",
		ExpectedOrigins:         []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:           []string{"dev.dontneeda.pw"},
		RequireUserVerification: boolPointer(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "fido-u2f" || verification.RegistrationInfo.AAGUID != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyPackedX5CAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID: "aaa", RawID: "aaa", Type: "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIMt_hGMtdgpIVIwMOeKKw0IkUUFkXSY8arKh3Q0c5QQAiB9Sv9JavAEmppeH_XkZjB7TFM3jfxsgl97iIkvuJOUImN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAcbUS6m_bsLkm5MAyP6SDLcwBA4rrvMciHCkdLQ2HghazIp1sMc8TmV8W8RgoX-x8tqV_1AmlqWACqUK8mBGLandr-htduQKPzgb2yWxOFV56TlqUBAgMmIAEhWCBsJbGAjckW-AA_XMk8OnB-VUvrs35ZpjtVJXRhnvXiGiJYIL2ncyg_KesCi44GH8UcZXYwjBkVdGMjNd6LFmyiD6xf",
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEc5MFlXeHNlVlZ1YVhGMVpWWmhiSFZsUlhabGNubFVhVzFsIiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3In0=",
		},
	}
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:                response,
		ExpectedChallenge:       "dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlUaW1l",
		ExpectedOrigins:         []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:           []string{"dev.dontneeda.pw"},
		RequireUserVerification: boolPointer(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "packed" || verification.RegistrationInfo.Credential.Counter != 28 {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyAndroidKeyAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID:    "PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o",
		RawID: "PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o",
		Type:  "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBzpQmnQw6jn-V33XTmlvkw4wyUW-CbyYd5Bltvl_8oHwIgY05YGCJIawM1INNQg4cshJKi847UVUBURLNkTd-BC2hjeDVjglkDGjCCAxYwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEjCq7woGNN_42rbaqMgJvz0nuKTWNRrR29lMX3J239o6IcAXqPJPIjSrClHDAmbJv_EShYhYq0R9-G3k744n7ajggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIEwhPC-SlsMm-UdaXBdqAIDXqyRDtjXSeja589CMqyF2BAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDRwAwRAIgHl4jYMq7nEV6pcuXJFNOsZHSX5Zn1UDy6RI9zsDR-C4CICNfJrQW1jyEuRUM1xR8VmKjkjIa2W22Z7NdyZz1CQq-WQMYMIIDFDCCArqgAwIBAgIBAjAKBggqhkjOPQQDAjCB3DE9MDsGA1UEAww0RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTkwNDI1MDU0OTMyWhcNNDYwOTEwMDU0OTMyWjCB5DFFMEMGA1UEAww8RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBGQUtFMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKtQYStiTRe7w7UbBEk7BUkLjB-LnbzzebLe3KB8UqHXtg3TIXXcK37dvCbbCNVfhvZxtpTcME2kooqMTgOm9cejYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgKEMB0GA1UdDgQWBBSj0qos7w2M8iQC1Ry0YLy_alskFDAfBgNVHSMEGDAWgBRSmhsy4FaqzVEP71-ANwaL8pEjHTAKBggqhkjOPQQDAgNIADBFAiEAsW8uQC-0es5tOY3w_T7IshPj3o__B5IQRsHq8IlZKH0CIG75Q6isJ4twXhaLE4b0TkuLadd7i4zarqZsoaSWXy75aGF1dGhEYXRhWKQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAABsVQ5LVKpHQJ-alRq3bBMBMQAgPPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0qlAQIDJiABIVggSMKrvCgY03_jattqoyAm_PSe4pNY1GtHb2Uxfcnbf2giWCDohwBeo8k8iNKsKUcMCZsm_8RKFiFirRH34beTvjiftg",
			ClientDataJSON:    "eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiIxNGUwZDFiNi05YzM2LTQ4NDktYWVlYy1lYTY0Njc2NDQ5ZWYiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
		},
	}
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:                response,
		ExpectedChallenge:       "14e0d1b6-9c36-4849-aeec-ea64676449ef",
		ExpectedOrigins:         []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:           []string{"dev.dontneeda.pw"},
		RequireUserVerification: boolPointer(false),
		AttestationRoots:        map[string]*x509.CertPool{"android-key": nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "android-key" || verification.RegistrationInfo.Credential.Counter != 108 {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyAndroidKeyPixelUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID: "AYNe4CBKc8H30FuAb8uaht6JbEQfbSBnS0SX7B6MFg8ofI92oR5lheRDJCgwY-JqB_QSJtezdhMbf8Wzt_La5N0", RawID: "AYNe4CBKc8H30FuAb8uaht6JbEQfbSBnS0SX7B6MFg8ofI92oR5lheRDJCgwY-JqB_QSJtezdhMbf8Wzt_La5N0", Type: "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYSDBGAiEAs9Aufj5f5HyLKEFsgfmqyaXfAih-hGuTJqgmxZGijzYCIQDAMddAq1gwH3MtesYR6WE6IAockRz8ilR7CFw_kgdmv2N4NWOFWQLQMIICzDCCAnKgAwIBAgIBATAKBggqhkjOPQQDAjA5MSkwJwYDVQQDEyBkNjAyYTAzYTY3MmQ4NjViYTVhNDg1ZTMzYTIwN2M3MzEMMAoGA1UEChMDVEVFMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATXVi3-n-rBsrP3A4Pj9P8e6PNh3eNdC38PaFiCZyMWdUVA6PbE6985PSUDDcnk3Knnpyc66J_HFOu_geuqiWtAo4IBgzCCAX8wDgYDVR0PAQH_BAQDAgeAMIIBawYKKwYBBAHWeQIBEQSCAVswggFXAgIBLAoBAQICASwKAQEEIFZS4txFVJqW-Wr6IlUC-H-twIpgvAITksC-jFBi_V9eBAAwd7-FPQgCBgGUcHc4or-FRWcEZTBjMT0wGwQWY29tLmdvb2dsZS5hbmRyb2lkLmdzZgIBIzAeBBZjb20uZ29vZ2xlLmFuZHJvaWQuZ21zAgQO6jzjMSIEIPD9bFtBDyXLJcO1M0bIly-uMPjudBHfkQSArWstYNuDMIGpoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBA7-DeQMCAQq_hT4DAgEAv4VATDBKBCCd4l-wK7VTDUQUnRSEN8guJn5VcyJTCqbwOwrC6Skx2gEB_woBAAQg6y0px0ZXc5v2bsVb45w-6IiMbXzp3gyHIWKS1mbz6gu_hUEFAgMCSfC_hUIFAgMDFwW_hU4GAgQBNP35v4VPBgIEATT9-TAKBggqhkjOPQQDAgNIADBFAiEAzNz6wyTo4t5ixo9G4zXPwh4zSB9F854sU_KDGTf0dxYCICaQVSWzWgTZLQYv13MXJJee8S8_luQB3W5lPPzP0exsWQHjMIIB3zCCAYWgAwIBAgIRANYCoDpnLYZbpaSF4zogfHMwCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMB4XDTI1MDEwNzE3MDg0M1oXDTI1MDIwMjEwMzUyN1owOTEpMCcGA1UEAxMgZDYwMmEwM2E2NzJkODY1YmE1YTQ4NWUzM2EyMDdjNzMxDDAKBgNVBAoTA1RFRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFPbPYqm91rYvZVCBdFaHRMg0tw7U07JA1EcD9ZP4d0lK2NFM4A0wGKS4jbTR_bu7NTt_YyF388S0PWAJTluqnOjfjB8MB0GA1UdDgQWBBSXyrsZ_A1NnJGRq0sm2G9nm-NC5zAfBgNVHSMEGDAWgBTFUX4F2MtjWykYrAIa8sh9bBL-kjAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwICBDAZBgorBgEEAdZ5AgEeBAuiAQgDZkdvb2dsZTAKBggqhkjOPQQDAgNIADBFAiEAysd6JDoI8X4NEdrRwUwtIAy-hLxSEKUVS2XVWS2CP04CIFNQQzM4TkA_xaZj8KyiS61nb-aOBP35tlA34JCOlv9nWQHcMIIB2DCCAV2gAwIBAgIUAIUK9vrO5iIEbQx0izdwqlWwtk0wCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI0MTIwOTA2Mjg1M1oXDTI1MDIxNzA2Mjg1MlowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPjbr-yt9xhgcbKLXoN3RK-1FcCjwIpeMPJZjayW0dqNtFflHp2smO0DxN_6x7M7NAGbcC9lM1_E-N6z51ODv-6NjMGEwDgYDVR0PAQH_BAQDAgIEMA8GA1UdEwEB_wQFMAMBAf8wHQYDVR0OBBYEFMVRfgXYy2NbKRisAhryyH1sEv6SMB8GA1UdIwQYMBaAFKYLhqTwyH8ztWE5Ys0956c6QoNIMAoGCCqGSM49BAMDA2kAMGYCMQCuzU0wV_NkOQzgqzyqP66SJN6lilrU-NDVU6qNCnbFsUoZQOm4wBwUw7LqfoUhx7YCMQDFEvqHfc2hwN2J4I9Z4rTHiLlsy6gA33WvECzIZmVMpKcyEiHlm4c9XR0nVkAjQ_5ZA4QwggOAMIIBaKADAgECAgoDiCZnYGWJloYOMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMTI2MjI0OTQ1WhcNMzcwMTIyMjI0OTQ1WjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTIwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT72ZtYJ0I2etFhouvtVs0sBzvYsx8thNCZV1wsDPvsMDSTPij-M1wBFD00OUn2bfU5b7K2_t2NkXc2-_V9g--mdb6SoRGmJ_AG9ScY60LKSA7iPT7gZ_5-q0tnEPPZJCqjZjBkMB0GA1UdDgQWBBSmC4ak8Mh_M7VhOWLNPeenOkKDSDAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH_xpMyepPEjASBgNVHRMBAf8ECDAGAQH_AgECMA4GA1UdDwEB_wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEArpB2eLbKHNcS6Q3Td3N7ZCgVLN0qA7CboM-Ftu4YYAcHxh-e_sk7T7XOg5S4d9a_DD7mIXgENSBPB_fVqCnBaSDKNJ3nUuC1_9gcT95p4kKJo0tqcsWw8WgKVJhNuZCN7d_ziHLiRRcrKtaj944THzsy7vB-pSai7gTah_RJrDQI91bDUJgld8_p_QAbVnYA8o-msO0sRKxgF1V5QuBwBTfpdkqshqL3nwBm0sofqI_rM-JOQava3-IurHvfkzioiOJ0uFJnBGVjpZFwGwsmyKwzl-3qRKlkHggAOKt3lQQ4GiJnOCm10JrxPa2Za0K6_kyk6YyvvRcFNai5ej3nMKJPg-eeG2nST6N6ePFuaeoNQnD4XkagGFEQYzcqvsdFsmsbUFMghFl7zEVYdscuSgCG939wxW1JgKyG5ce7CI40328w9IuOf8mUS_W3i4jSfxqCJbegyo_SKDpDILnhJUBy0T3fN8mv9AyO0uoJBlvnogIVv2SdpYUt92vyOiGMy3Jx_ZRWjIRa7iIV3VnjLI__pgCrXQLMinZWEWsxVxg25nrk8u32nZd67DJN3k2FufRbsmHZly9CLo0P79lkIEC3rifLqqJeDyHQNaBMUC6BSDZ5RJCtMjSZw2xL5z0X9_zBsKVPkMW61hMhKzVmYNLe1DJQANRP-enru5i1oXlZBSAwggUcMIIDBKADAgECAgkA1Q_yW6Py1rMwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEBRMQZjkyMDA5ZTg1M2I2YjA0NTAeFw0xOTExMjIyMDM3NThaFw0zNDExMTgyMDM3NThaMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCvtseCK7GnAewrtC6LzFQWY6vvmC8yx391MQMMl1JLG1_oCfvHKqlFH3Q8vZpvEzV0SqVed_a2rDU17hfCXmOVF92ckuY3SlPL_iWPj_u2_RKTeKIqTKmcRS1HpZ8yAfRBl8oczX52L7L1MVG2_rL__Stv5P5bxr2ew0v-CCOdqvzrjrWo7Ss6zZxeOneQ4bUUQnkxWYWYEa2esqlrvdelfJOpHEH8zSfWf9b2caoLgVJhrThPo3lEhkYE3bPYxPkgoZsWVsLxStbQPFbsBgiZBBwe0aX-bTRAtVa60dChUlicU-VdNwdi8BIu75GGGxsObEyAknSZwOm-wLg-O8H5PHLASWBLvS8TReYsP44m2-wGyUdm88EoI51PQxL62BI4h-Br7PVnWDv4NVqB_uq6-ZqDyN8-KjIq_Gcr8SCxNRWLaCHOrzCbbu53-YgzsBjaoQ5FHwajdNUHgfNZCClmu3eLkwiUJpjnTgvNJGKKAcLMA-UfCz5bSsHk356vn_akkqd8FIOIKIUBW0Is5nuAuIybSOE7YHq1Rccj_4xE-PLTaLn2Ug0xFF6_noYq1x32o7_SRQlZ1lN0DZehLzaLE-9m1dClSm4vXZpv70RoMrxnhEclhh8JPdDm80BdqJZD7w9NabZCAFH9uTBJZz42lQWA0830-9CLxYSDlSYAYwIDAQABo2MwYTAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR_8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR_8aTMnqTxIwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAgQwDQYJKoZIhvcNAQELBQADggIBAE4xoFzyi6Zdva-hztcJae5cqEEErd7YowbPf23uUDdddF7ZkssCQsznLcnu1RGR_lrVK61907JcCZ4TpJGjzdSHpazOh2YyTErkYzgkaue3ikGKy7mKBcTJ1pbuqrYJ0LoM4aMb6YSQ3z9MDqndyegv-w_LPp692MuVJ4nysUEfrFbIhkJutylgQnNdpQ4RrHFfGBjPn9xOJUo3YzUbaiRAFQhhJjpuMQvhpQ3lx-juiA_dS-WISjcSjRiDC7NHa_QpHoLVxmpklJOeCEgL-8APfYp01D5zc36-XY5OxRUwLUaJaSeA3HU47X6Rdb5hOedNQ604izBQ_9Wp3lJiAAiYwB9jxT3-IiCRCPpPZboWxJzL3gg318WETVS3OYugEi5QWxVckxPP4m5y2H4iqhYW5r2_VH3f-T3ynjWmO0Vf4fwOyVWB8_T3u-O7goOWo3rjFXWCvDdkuXgKI578D3Wh4ubZQc6rrCfd6wHivYQhApvqNNUa7mxgJx1alevQBRWpwAE92Av4fuomC4HDT2iObrE0ivDY6hysMqy52T-iSv8DCoTI8rD1acyVCAsgrDWs4MbY29T2hHcZUZ0yRQFm60vxW4WQRFAa3q9DY4LDSxXjtUyS5htpwr_HJkWJFys8k9vjXOBtCP1cATIsoId7HRJ0OvH61ZQOobwC3YkcaGF1dGhEYXRhWMVJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAAuT_ZYfLmRi-xIoIAIkfeeABBAYNe4CBKc8H30FuAb8uaht6JbEQfbSBnS0SX7B6MFg8ofI92oR5lheRDJCgwY-JqB_QSJtezdhMbf8Wzt_La5N2lAQIDJiABIVgg11Yt_p_qwbKz9wOD4_T_HujzYd3jXQt_D2hYgmcjFnUiWCBFQOj2xOvfOT0lAw3J5Nyp56cnOuifxxTrv4HrqolrQA",
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidDRMV0kwaVlKU1RXUGw5V1hVZE5oZEhBbnJQRExGOWVXQVA5bEhnbUhQOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
		},
	}
	fixedNow := time.Date(2025, time.February, 2, 10, 0, 0, 0, time.UTC)
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response: response, ExpectedChallenge: "t4LWI0iYJSTWPl9WXUdNhdHAnrPDLF9eWAP9lHgmHP8",
		ExpectedOrigins: []string{"http://localhost:8000"}, ExpectedRPIDs: []string{"localhost"},
		RequireUserVerification: boolPointer(false),
		Now:                     func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "android-key" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyAndroidKeySamsungUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID: "AZNJEB2RcdcMJ0kZ1X1lyA6d7ENiKF5K945bpbZXxdVqoyjENSnHSZuxZz9sBMVyKAArpVBhwWr7WTutT_epNsk", RawID: "AZNJEB2RcdcMJ0kZ1X1lyA6d7ENiKF5K945bpbZXxdVqoyjENSnHSZuxZz9sBMVyKAArpVBhwWr7WTutT_epNsk", Type: "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRzBFAiBN6uMvi4Arrog6bM-EH_HHdcYowZb9AZ3OP8LF7BsOwQIhAIGMW51yybiu_p90i60qFilQ2NTBfNSKMxWSd-_ElLGGY3g1Y4RZAsAwggK8MIICYqADAgECAgEBMAoGCCqGSM49BAMCMCkxGTAXBgNVBAUTEDljZmFiZjY5ZWNjMzc0OWMxDDAKBgNVBAwMA1RFRTAgFw03MDAxMDEwMDAwMDBaGA8yMTA2MDIwNzA2MjgxNVowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARF-xUruvQrCRWHiRDV4Lsq4FjoEpLFf361IEQaaeBsGuz0zt29H0BKNbEIUpvWcuKBKwmcOvMH2wFAZ7tRHblHo4IBgTCCAX0wDgYDVR0PAQH_BAQDAgeAMIIBaQYKKwYBBAHWeQIBEQSCAVkwggFVAgEDCgEBAgEECgEBBCCtDPAKpMZ9hMbYOO1XIwN-v_gVMOTGAjDefrroBsj2-QQAMHe_hT0IAgYBl_krnvi_hUVnBGUwYzE9MBsEFmNvbS5nb29nbGUuYW5kcm9pZC5nc2YCAR4wHgQWY29tLmdvb2dsZS5hbmRyb2lkLmdtcwIEDwvKrjEiBCDw_WxbQQ8lyyXDtTNGyJcvrjD47nQR35EEgK1rLWDbgzCBqaEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb-DeAMCAQO_g3kDAgEKv4U-AwIBAL-FQEwwSgQg2O2bmq25z_lUP96p1NX4bjoeGqNeSEFetzrqoDDefYEBAf8KAQAEIG_Q-U6jhMM6Kdz7OeX58NCiyMveuzh_N9gbNCMAB8_rv4VBBQIDAa2wv4VCBQIDAxV_v4VOBgIEATRlnb-FTwYCBAE0ZZ0wCgYIKoZIzj0EAwIDSAAwRQIgLy0SGjDM7BDO9xLfOjfHkYMiKMeY0CZ1SBs-lsAPSqcCIQDpxwWdHetnjLhMJrd6HGw88aI5-GZlO9_7mpNWu94r7lkCKDCCAiQwggGroAMCAQICCgNwFmEVJQaTJJAwCgYIKoZIzj0EAwIwKTEZMBcGA1UEBRMQMjg1ZjdmYTllZWIxNDAxNDEMMAoGA1UEDAwDVEVFMB4XDTE5MDYxMzE5MzExOFoXDTI5MDYxMDE5MzExOFowKTEZMBcGA1UEBRMQOWNmYWJmNjllY2MzNzQ5YzEMMAoGA1UEDAwDVEVFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0ZjVvvE-xQefNwWt2g0fjCzKcCGErvUUla1Sy0YRXGTUPW_xZg7OpoWB1XFfFlgM-1xih8UmDGpFF77KX2WHtqOBujCBtzAdBgNVHQ4EFgQUQHGUFV40EuDlHb86QZ6X74Rv1GswHwYDVR0jBBgwFoAUZsclWZX-WiRVCJ2uL-JyioxCRzowDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAgQwVAYDVR0fBE0wSzBJoEegRYZDaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wMzcwMTY2MTE1MjUwNjkzMjQ5MDAKBggqhkjOPQQDAgNnADBkAjAay0bXweDTEiM5h3qEFZh0lvjfm7BrD6PdwSgHiMSoln9Lp1Y6dtdMifLSuqTSPp4CMASAp7BEH6DBT-B6S3MnpAz-pS_BPAZDgYr8rFH2tnlMM1WOEtjQIQ2KfodC4tJU81kD1TCCA9EwggG5oAMCAQICCgOIJmdgZYmWheIwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEBRMQZjkyMDA5ZTg1M2I2YjA0NTAeFw0xOTA2MTMxOTI1MjhaFw0yOTA2MTAxOTI1MjhaMCkxGTAXBgNVBAUTEDI4NWY3ZmE5ZWViMTQwMTQxDDAKBgNVBAwMA1RFRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABAUTSmkto8xjo3bsJ2VyoiU24xF1pA1wLmmqy6_rD60WMB4I3fU73p-NXVdQ720JSXel8O0-BH0kOQaGkQytYLXFnN7IcWfeQp1weEZpd8IbUPiN8gTUyl1Y0GCKSBL-kqOBtjCBszAdBgNVHQ4EFgQUZsclWZX-WiRVCJ2uL-JyioxCRzowHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR_8aTMnqTxIwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAgQwUAYDVR0fBEkwRzBFoEOgQYY_aHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC9FOEZBMTk2MzE0RDJGQTE4MA0GCSqGSIb3DQEBCwUAA4ICAQBsKTstdjFUeQ1dVLRyx9ecE5qQaZV26Bos7boyz-R2HJv4iJ492aii9FLVwLei2c-aVgHuAKIfht3kP25-0crEoFKc0AiBzX3LS9a7P3V4tt8z-kBiKQkJtcbEw9r2HlTDviEa7GCRvLbFoORFyTZjQTR5tJQQEhYrsB5qo-vVweHZ_uQ_KR_Ag5DzNGPh_KFXwz-qVh720Ca99wixT4wMgGFIgIZxTIAz8c3kDYXqQ5j4jplksQbghTSN5lnKPeVjZpc_dga4r09bpm61z2ylNybUnBwUnkpRyzNVRlpZRpd0yq7royq_QRI-zoZd4nx--1_AqC3XshBfmSz9Dxxx8aNQ0QR3WJtLtya9ECxmyLh9LqNbCgoRSLi4g8sDLkIy9yaY7goL7XVdFZfTDKiwne-BsjD6Fgl7yFmCkndJMvJjVD0r4WaoFB-Tomx0eg7Lgdy2sJs5T_Yo-woGvn2qPGFsbm1oib4MgnsK2JtjH9VmfB2oUQ16sLWSVaqMHtSx1ZB2FxyB1auRs-sNeNxhAkLw4D-6R8j7Rug3sXoV4p14UL7KvjL8p2th7CImGvgUHRJ_EUhpEl6Rc8XLPeHi64Qw7POnha8oSaZFpHkSR2oGDKkHVcqUBz3KFizVh15du40fpq2TYtH4of_hJlUzEtH2Uidou3WyNtSjhNQq7VkFZDCCBWAwggNIoAMCAQICCQDo-hljFNL6GDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE2MDUyNjE2Mjg1MloXDTI2MDUyNDE2Mjg1MlowGzEZMBcGA1UEBRMQZjkyMDA5ZTg1M2I2YjA0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK-2x4IrsacB7Cu0LovMVBZjq--YLzLHf3UxAwyXUksbX-gJ-8cqqUUfdDy9mm8TNXRKpV539rasNTXuF8JeY5UX3ZyS5jdKU8v-JY-P-7b9EpN4oipMqZxFLUelnzIB9EGXyhzNfnYvsvUxUbb-sv_9K2_k_lvGvZ7DS_4II52q_OuOtajtKzrNnF46d5DhtRRCeTFZhZgRrZ6yqWu916V8k6kcQfzNJ9Z_1vZxqguBUmGtOE-jeUSGRgTds9jE-SChmxZWwvFK1tA8VuwGCJkEHB7Rpf5tNEC1VrrR0KFSWJxT5V03B2LwEi7vkYYbGw5sTICSdJnA6b7AuD47wfk8csBJYEu9LxNF5iw_jibb7AbJR2bzwSgjnU9DEvrYEjiH4Gvs9WdYO_g1WoH-6rr5moPI3z4qMir8ZyvxILE1FYtoIc6vMJtu7nf5iDOwGNqhDkUfBqN01QeB81kIKWa7d4uTCJQmmOdOC80kYooBwswD5R8LPltKweTfnq-f9qSSp3wUg4gohQFbQizme4C4jJtI4TtgerVFxyP_jET48tNoufZSDTEUXr-ehirXHfajv9JFCVnWU3QNl6EvNosT72bV0KVKbi9dmm_vRGgyvGeERyWGHwk90ObzQF2olkPvD01ptkIAUf25MElnPjaVBYDTzfT70IvFhIOVJgBjAgMBAAGjgaYwgaMwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgGGMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHBzOi8vYW5kcm9pZC5nb29nbGVhcGlzLmNvbS9hdHRlc3RhdGlvbi9jcmwvMA0GCSqGSIb3DQEBCwUAA4ICAQAgyMONS9ypVxtGjIkv_3KqxvhEoR1BqPBzbMN9FtZCbY5-lAcETOo55osHwT2_FQPdXIW9r7LALV9s2076gSffiwTxgncPxOd0W3_OqocSmogBzo6bwMuWN5tNJqgtMP2cL47tbcG-L4S2ieTZFCWLFEu65iShxwZxEy4vBhaohLKk1qRv-om2Ar-62AwSQ3EfVutgVvY3yKAUHMVAlCaLjDx9uZSzXA3NbLKrwtr-4lICPS3qDNbDaL6j5kFIhvax5Ytb18cwsmjE48H7ZCS5H-u9uAxYbiroNoyE1dEJF72iVheJ1GhzkzQOLiVPVg72SyNY_NwPv8ZwCVLnCL_8xidQDB9m6B6hfAmNei6bGIAberSscVh9NF3MgwnVtipQQnqm0D3LBZlslroMXXHpIWLAFsqEn_NfDVLGXQVgWkfzrpF6zS35EO_SMmaIWW72mzv1_jFU9664gKCnPKBNlMLOgxfutD1e_1iD4zb18knarKSJkje_Jn5cQ6sC6kQWJANyO-aqaSxhva6e1AnUY8TJfGQwZXfu8rx1YLdXFcycfcZ8hggtt1GonDA0l2KweCOFh1zxo8YWbgrjwS03Ti1PGEbzGHRL2Hm1hzKb8BghemwMdyQaSHjkNcAwectFEonFd2IGBpovjWX4QOFEUoe-2HerriTiRDUWjVU85GhhdXRoRGF0YVjFT848GIB1YSy2AgqgP_bEoHGe74fBQecLAfr8oYF8zI5FAAAAALk_2WHy5kYvsSKCACJH3ngAQQGTSRAdkXHXDCdJGdV9ZcgOnexDYiheSveOW6W2V8XVaqMoxDUpx0mbsWc_bATFcigAK6VQYcFq-1k7rU_3qTbJpQECAyYgASFYIEX7FSu69CsJFYeJENXguyrgWOgSksV_frUgRBpp4GwaIlgg7PTO3b0fQEo1sQhSm9Zy4oErCZw68wfbAUBnu1EduUc",
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidkNMQVIzQUdoeGZQMFEtTDkyX0JzcHBraEFDYnkwSGp0TlpFQkZKMGdPayIsIm9yaWdpbiI6Imh0dHBzOi8vcG9ydGFsLmZ4b24uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
		},
	}
	fixedNow := time.Date(2025, time.July, 15, 10, 0, 0, 0, time.UTC)
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response: response, ExpectedChallenge: "vCLAR3AGhxfP0Q-L92_BsppkhACby0HjtNZEBFJ0gOk",
		ExpectedOrigins: []string{"https://portal.fxon.com"}, ExpectedRPIDs: []string{"portal.fxon.com"},
		Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "android-key" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyTPMAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID:    "lGkWHPe88VpnNYgVBxzon_MRR9-gmgODveQ16uM_bPM",
		RawID: "lGkWHPe88VpnNYgVBxzon_MRR9-gmgODveQ16uM_bPM",
		Type:  "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzkBAGNzaWdZAQBoZraUgitkw10bZI2MMWDECGf3LgbkX1XoSUhWhxawE8gX1oQdbYbIx-LjtFZkBqp7Nsq8qdeQBGhSJbSbE1wLfP5Xs3d110KmD4LzrCmt_rn3LYQDhDIonft8xJIpAHppEKCxziHMWCPXbntIeQ8pHEZmjBTIN5CJyxHQeUp1LniMQ0CGRknSlE4Av6aHrnoGUgnrsyXmzMn0BWxtdGIhsheAIiBanXGqMdLQ5cGc1HRmGh9U4NrVE-W7nJBLuA5H9K6-t9TfTySYInzr81XEsh6Ei5ijGT2Cc1MmaU4utbB-LyUG9v_oy9EpdOAu4v2jBOBkms0CxrErdWCKl7b5Y3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwS6zyQ0LwxSSoQYLc7HVjANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA-IYIfmLnyIHdgjwb2Y-KzMYI2HjN6WseCH8f9N7G3zZpSE9xZxrutKpgoE5wzV2STtkvgd5xikTdIrneWGcNeIW2xhdH2dAVnhL1OiRdLf1CneJHUO78t5-3pmCynqMlUW1VELC-mpaY_kbpNF0Fxn3MhV_-LwtinS5FCvsHpMdKJ_md2e9CDAiI7IqdeK9_sPA5hzDsq9nXsBn0MCcSEppWojwLG3pqmnBWsrLGJCyT5OBi2yNiD0pWMhgromksz6AfFraVDHX8d7E-GoDHedLujnZIm3fAiWDvmdgmZVxX6bxLSWZqWZoSNuJSRasoulVDzDOBHYBWGKLJGgPdMwIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUdOhwbuNi8U8_KoCvb3uGHTvHco0wHQYDVR0OBBYEFNiSs3HuWy41m937TQw7EyHG4L3_MHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QS5jcnQwDQYJKoZIhvcNAQELBQADggEBAHCSnX7NtGUl1gyIRsprAS1y4TfvEfxpmsrbTruacYBDQ4z5o2uoMYYV2txkvI_pH4kxOolSS9oTz7iNGpKv1yB3x40rMRsiUNs7EyhmH7RE73DOBxlMkr1vHJudiIircI1EifC7FKiDqssKKws8apYE1BZYj6swuG2LOx1LUHd-hP473u0XEv8WbRXY3Pr1I9DODhfMkJDLUKg_l7YI2oowgathLG5_ci0Ad2EHn9122Y1StwSr0r7-cfrTwNxt2bPnZ61hkI_Em7IlCsuol0wak1Ba-UqEWDuTMRmMn3AF59rmIQ2yPdj4ae0DBnSsP13DZj8ihPT68SsaY7HiURBZBgUwggYBMIID6aADAgECAg8EV2dM14jMuwRaKXATKH8wDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFHTocG7jYvFPPyqAr297hh07x3KNMB8GA1UdIwQYMBaAFEMRFpma7p1QN8JP_uJbFckJMz8yMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBI6GeuxIkeKcmRmFQnkPnkvSybRIJEkzWKa2f00vdBygxtzpkXF2WMHbvuMU3_K3WMFzg2xkSPjM3x_-UxOWGYgVIq8fXUdy2NhmLz4tPI65_nQXpS22rzmXFzsj4x9yS0JF2NnW5xm-O8UdckFdwIZx4Ew_zA-rIF3hqbY4Ejz2AdsbvHJo-WTpu-wWDbBQyR19eqNyYZ6vf9K8DB2JZviIDXdOpkuOJLA40MKMlnhv5K4BZs7mDZIaPzNA_MrcH3_dYXq4tIoGu5Pr1ZNCQ--93XYG1eRbvCgSDYUCRza5AgBGCIhmx2-tqLYeCd9qdy4O9R9c9qRjEThbjnGStYZ0DuB6VCaH1WjiRqyq4VNi9cv15-RoC4zswWwuHee97AAJ_Tx29w6S4Kw9DQR6A0vtw_OHLuOkGH63ns0DACf_h1MvsAMnXXX0Q0P8IpNdBQGvLvrRtRdBNx06NHY1HGZOZ9PdJ6J4mnroB2ln3cMGZG9kyRv2vbwq6sCrYZVYjo3tf4MUtkEY4FijoYbMEDK7VlbTiDPnobhkxI1-bz5DTFnR3IfVybYAeGrBCKSg2UUTPvVgM3WZ-oGlP8W9dg1347hqgxP0vLgDM6cV7rhaFC_ZAf2Et9KLRZSj7lNpJWxHxPyz9mM4w3qFwdgWKwlXl3OQtJRT4Kbs6r3gzB5WdwdWJBcmVhWQE2AAEACwAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEArcc8OfVrJfMVj_e8D07tk0g5brIcLIS_BnnRwBztUetpt5zcttYQiyZUGm3y3qUVEP7_ZqtzwplfNbQUqrURlOf2JStEdsnru-ekp09_XOoSgtzwT7f8XYy_3HM-B_-9w7p3wet0GTrXXgLLMFe1jy6jAEaH7jPi0Pyx5zYLgsqQ3MYQA7lKkLaIH8GbJJ01SD8cxnH6p0OxERfQ_QDliEPGIzrE4vwds0vEjskiiBVBsMGHDxuw4ghPkCXCPn6cnUQ5xKulMW5GIAe1yuAZZjypcLl5AQ1_XoJfzGuAe1tlib2Gynr7umfCnOcvjiE6TVQ2CmwSt6isoeMiFKQdTWhjZXJ0SW5mb1it_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTACBUXhu5udUi6GBvBBGsIF5MfQKIIDBdBStwWHfPWQx-FQAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgALjZ3k0w--c4p2uu7urgJWOfxm0k2XJW4x9EEu0o-HzrIAIgAL_U4kZaJRRPAELcp-Gp4lh_iSA_uUtdHNVhq5vjbJ0KVoYXV0aERhdGFZAWc93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAep9bZOooNEeialKbPcQcvcwAglGkWHPe88VpnNYgVBxzon_MRR9-gmgODveQ16uM_bPOkAQMDOQEAIFkBAK3HPDn1ayXzFY_3vA9O7ZNIOW6yHCyEvwZ50cAc7VHrabec3LbWEIsmVBpt8t6lFRD-_2arc8KZXzW0FKq1EZTn9iUrRHbJ67vnpKdPf1zqEoLc8E-3_F2Mv9xzPgf_vcO6d8HrdBk6114CyzBXtY8uowBGh-4z4tD8sec2C4LKkNzGEAO5SpC2iB_BmySdNUg_HMZx-qdDsREX0P0A5YhDxiM6xOL8HbNLxI7JIogVQbDBhw8bsOIIT5Alwj5-nJ1EOcSrpTFuRiAHtcrgGWY8qXC5eQENf16CX8xrgHtbZYm9hsp6-7pnwpznL44hOk1UNgpsEreorKHjIhSkHU0hQwEAAQ",
			ClientDataJSON:    "eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiIzYTA3Y2Y4NS1lN2I2LTQ0N2YtODI3MC1iMjU0MzNmNjAxOGUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
		},
	}
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:                response,
		ExpectedChallenge:       "3a07cf85-e7b6-447f-8270-b25433f6018e",
		ExpectedOrigins:         []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:           []string{"dev.dontneeda.pw"},
		RequireUserVerification: boolPointer(false),
		Now: func() time.Time {
			return time.Date(2025, time.January, 30, 23, 59, 59, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "tpm" || verification.RegistrationInfo.Credential.Counter != 30 {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyTPMSHA1AttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID:    "oELnad0f6-g2BtzEn_78iLNoubarlq0xFtOtAMXnflU",
		RawID: "oELnad0f6-g2BtzEn_78iLNoubarlq0xFtOtAMXnflU",
		Type:  "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQA7MkOLfnxF5Z0RsXHc0OoVV-wkR6gKW92FFuBU79qeu7bxzMONC0uJ1mLt4SmhKsKZss1UqEx37tjwhzRE3wgNFGEEwK274W6xDVsU2ZimAvW_hZZwQAK5I3b35oJcQQxoc2iTv6XHDfwmf1pDa3d35idsNrv_-wQttjapdycRmkt7POPFAVMvooIY1bW6xk4fNIdqhHN1X6E2eT9k7IHcnQfdpqo_PpxxHzH1sLm00D3GanqMQFO0RlfE6HUZmfrTh8WpnwPwRZ_AH7njRS_eNvFm_oPX-19YRgzY0GFJb_b7tsL_EejBbygnIh4SCXEj9XfV0mneXKZuh47HzC2sY3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwQzi_r9IpiaTHT5hcpSFTANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqFSXnyuWEwydvMZN8iP-HW-XnQ8thzSa0KbFr2JUdGN8ox4Re5VicuIW5uFn_0_l-lTvngIR5JTlyaSLr7VrXNqlv4fNax0ZBbaYqgXaBJMhXpBjVCvjSZuNvCxd-7vLbqXuCNdNPAkSU1RKXN4ATZJfOBeCLDBWh-puudODIGTaz6nG_q78Qh7oErN279BsP77DcfoR47Em1eZpWXe9ezyvXuV5bqS04CaG_AnN1KU3o5madqio3Xlf3OXTEEKhLNTEu4-Oay_sykWRd7iflPipE981PqXCw9bVJM089cg952Eyo8N94Uzjb6XT4zkRsBYonzoIywzqCYlvklAlQIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUdOhwbuNi8U8_KoCvb3uGHTvHco0wHQYDVR0OBBYEFE9_Zz1qQuzOlnNmLOEjQnzvQoj5MHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QS5jcnQwDQYJKoZIhvcNAQELBQADggEBAI-t9Opuc5rr7FrOUD0jJaXm-jg84L7QWeKoJ67znWGH09D0SBLsARPTAexUjDYQdoF7nWm4viw9NTXhUk3qLxd4G9602r8ht1FmgyqZz_jHLDnGJniXjJm5ILizCdwjlSDcN68lSkKcwAp5uScSorT9EDhB067Pexs4oJUo1-ZicdHyYsJu0i6wqhq2OVVufj2vifU82fw-xPzGkP4RXyWKWnxBfD2ofrLilL24GEIlrpB48y8EKeH8zsFGirsSM8wtT6pa0hBz2OBW4YWkGpOxNHIXTuafOS6ZLqeugg1P0KutUgGrdcQzZwcN6t9OwEV1imd3vmIgGD13qgCldN5ZBgUwggYBMIID6aADAgECAg8EV2dM14jMuwRaKXATKH8wDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFHTocG7jYvFPPyqAr297hh07x3KNMB8GA1UdIwQYMBaAFEMRFpma7p1QN8JP_uJbFckJMz8yMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBI6GeuxIkeKcmRmFQnkPnkvSybRIJEkzWKa2f00vdBygxtzpkXF2WMHbvuMU3_K3WMFzg2xkSPjM3x_-UxOWGYgVIq8fXUdy2NhmLz4tPI65_nQXpS22rzmXFzsj4x9yS0JF2NnW5xm-O8UdckFdwIZx4Ew_zA-rIF3hqbY4Ejz2AdsbvHJo-WTpu-wWDbBQyR19eqNyYZ6vf9K8DB2JZviIDXdOpkuOJLA40MKMlnhv5K4BZs7mDZIaPzNA_MrcH3_dYXq4tIoGu5Pr1ZNCQ--93XYG1eRbvCgSDYUCRza5AgBGCIhmx2-tqLYeCd9qdy4O9R9c9qRjEThbjnGStYZ0DuB6VCaH1WjiRqyq4VNi9cv15-RoC4zswWwuHee97AAJ_Tx29w6S4Kw9DQR6A0vtw_OHLuOkGH63ns0DACf_h1MvsAMnXXX0Q0P8IpNdBQGvLvrRtRdBNx06NHY1HGZOZ9PdJ6J4mnroB2ln3cMGZG9kyRv2vbwq6sCrYZVYjo3tf4MUtkEY4FijoYbMEDK7VlbTiDPnobhkxI1-bz5DTFnR3IfVybYAeGrBCKSg2UUTPvVgM3WZ-oGlP8W9dg1347hqgxP0vLgDM6cV7rhaFC_ZAf2Et9KLRZSj7lNpJWxHxPyz9mM4w3qFwdgWKwlXl3OQtJRT4Kbs6r3gzB5WdwdWJBcmVhWQE2AAEACwAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEAs5f8A9uD2ec_qaNha8KEFXXdd4KLfwpC_KeAfzbyQQuTsAGCg4pYov8I_tAgPDGp26UiJ8fU3Z8-rfdTobncFE9PlvwR0iyvzKhXI2Vq0eS2FZlac9RIB9w6zk62uAJaIBKtg9gmJLT6z3u46BPqE97wGFyvL80Ay0cmsSP2dakuCi5SwnWo1vDxqcNWEYzA8OrOvRmVPJl5IDTzAlIdU2dW5wryUzvX55i4w46nUBkVOG1qPLRYwi_INftlg_9p9PrcLep_lKMeVZ0dXUCRuGsDJWpwQpBhqTm91gQ0PCtdGCSdnrz4SShiWoQb7tg8ZquqSwgFwr9JmtxB4_j5g2hjZXJ0SW5mb1ih_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTABS0TKJrlCTTWAOuZgxyOOh4sQ-ftQAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgAL9vygl2NWFPZdCG3U1TrQ6RqfwNj7JxfCS5KpKXX44JEAIgAL4hZ6iGIhUFHeo5Tst6Kcwm-Nfh0I366P3MLYgbSPuhxoYXV0aERhdGFZAWc93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAABh8kS2flNkT9WfkMOWInMX2wAgoELnad0f6-g2BtzEn_78iLNoubarlq0xFtOtAMXnflWkAQMDOf_-IFkBALOX_APbg9nnP6mjYWvChBV13XeCi38KQvyngH828kELk7ABgoOKWKL_CP7QIDwxqdulIifH1N2fPq33U6G53BRPT5b8EdIsr8yoVyNlatHkthWZWnPUSAfcOs5OtrgCWiASrYPYJiS0-s97uOgT6hPe8Bhcry_NAMtHJrEj9nWpLgouUsJ1qNbw8anDVhGMwPDqzr0ZlTyZeSA08wJSHVNnVucK8lM71-eYuMOOp1AZFThtajy0WMIvyDX7ZYP_afT63C3qf5SjHlWdHV1AkbhrAyVqcEKQYak5vdYENDwrXRgknZ68-EkoYlqEG-7YPGarqksIBcK_SZrcQeP4-YMhQwEAAQ",
			ClientDataJSON:    "eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiJmNGU4ZDg3Yi1kMzYzLTQ3Y2MtYWI0ZC0xYTg0NjQ3YmYyNDUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
		},
	}
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:                response,
		ExpectedChallenge:       "f4e8d87b-d363-47cc-ab4d-1a84647bf245",
		ExpectedOrigins:         []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:           []string{"dev.dontneeda.pw"},
		RequireUserVerification: boolPointer(false),
		Now: func() time.Time {
			return time.Date(2025, time.January, 30, 23, 59, 59, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "tpm" || verification.RegistrationInfo.Credential.Counter != 97 {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyTPMECCAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID: "hsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnQ", RawID: "hsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnQ", Type: "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCqAcGoi2IFXCF5xxokjR5yOAwK_11iCOqt8hCkpHE9rW602J3KjhcRQzoFf1UxZvadwmYcHHMxDQDmVuOhH-yW-DfARVT7O3MzlhhzrGTNO_-jhGFsGeEdz0RgNsviDdaVP5lNsV6Pe4bMhgBv1aTkk0zx1T8sxK8B7gKT6x80RIWg89_aYY4gHR4n65SRDp2gOGI2IHDvqTwidyeaAHVPbDrF8iDbQ88O-GH_fheAtFtgjbIq-XQbwVdzQhYdWyL0XVUwGLSSuABuB4seRPkyZCKoOU6VuuQzfWNpH2Nl05ybdXi27HysUexgfPxihB3PbR8LJdi1j04tRg3JvBUvY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEGEZiaSlAkKpqaQOKDYmWPkwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLU5UQy1LRVlJRC1FNEE4NjY2RjhGNEM2RDlDMzkzMkE5NDg4NDc3ODBBNjgxMEM0MjEzMB4XDTIyMDExMjIyMTUxOFoXDTI3MDYxMDE4NTQzNlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKo-7DHdiipZTzfA9fpTaIMVK887zM0nXAVIvU0kmGAsPpTYbf7dn1DAl6BhcDkXs2WrwYP02K8RxXWOF4jf7esMAIkr65zPWqLys8WRNM60d7g9GOADwbN8qrY0hepSsaJwjhswbNJI6L8vJwnnrQ6UWVCm3xHqn8CB2iSWNSUnshgTQTkJ1ZEdToeD51sFXUE0fSxXjyIiSAAD4tCIZkmHFVqchzfqUgiiM_mbbKzUnxEZ6c6r39ccHzbm4Ir-u62repQnVXKTpzFBbJ-Eg15REvw6xuYaGtpItk27AXVcEodfAylf7pgQPfExWkoMZfb8faqbQAj5x29mBJvlzj0CAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMT4wEAYFZ4EFAgIMB05QQ1Q3NXgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMBQGBWeBBQIDDAtpZDowMDA3MDAwMjAfBgNVHSMEGDAWgBQ3yjAtSXrnaSNOtzy1PEXxOO1ZUDAdBgNVHQ4EFgQU1ml3H5Tzrs0Nev69tFNhPZnhaV0wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1udGMta2V5aWQtZTRhODY2NmY4ZjRjNmQ5YzM5MzJhOTQ4ODQ3NzgwYTY4MTBjNDIxMy9lMDFjMjA2Mi1mYmRjLTQwYTUtYTQwZi1jMzc3YzBmNzY1MWMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAz-YGrj0S841gyMZuit-qsKpKNdxbkaEhyB1baexHGcMzC2y1O1kpTrpaH3I80hrIZFtYoA2xKQ1j67uoC6vm1PhsJB6qhs9T7zmWZ1VtleJTYGNZ_bYY2wo65qJHFB5TXkevJUVe2G39kB_W1TKB6g_GSwb4a5e4D_Sjp7b7RZpyIKHT1_UE1H4RXgR9Qi68K4WVaJXJUS6T4PHrRc4PeGUoJLQFUGxYokWIf456G32GwGgvUSX76K77pVv4Y-kT3v5eEJdYxlS4EVT13a17KWd0DdLje0Ae69q_DQSlrHVLUrADvuZMeM8jxyPQvDb7ETKLsSUeHm73KOCGLStcGQ3pB49nt3d9XdWCcUwUrmbBF2G7HsRgTNbj16G6QUcWroQEqNrBG49aO9mMZ0NwSn5d3oNuXSXjLdGBXM1ukLZ-GNrZDYw5KXU102_5VpHpjIHrZh0dXg3Q9eucKe6EkFbH65-O5VaQWUnR5WJpt6-fl_l0iHqHnKXbgL6tjeerCqZWDvFsOak05R-hosAoQs_Ni0EsgZqHwR_VlG86fsSwCVU3_sDKTNs_Je08ewJ_bbMB5Tq6k1Sxs8Aw8R96EwjQLp3z-Zva1myU-KerYYVDl5BdvgPqbD8Xmst-z6vrP3CJbtr8jgqVS7RWy_cJOA8KCZ6IS_75QT7Gblq6UGFkG7zCCBuswggTToAMCAQICEzMAAAbTtnznKsOrB-gAAAAABtMwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MTAxODU0MzZaFw0yNzA2MTAxODU0MzZaMEExPzA9BgNVBAMTNkVVUy1OVEMtS0VZSUQtRTRBODY2NkY4RjRDNkQ5QzM5MzJBOTQ4ODQ3NzgwQTY4MTBDNDIxMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJA7GLwHWWbn2H8DRppxQfre4zll1sgE3Wxt9DTYWt5-v-xKwCQb6z_7F1py7LMe58qLqglAgVhS6nEvN2puZ1GzejdsFFxz2gyEfH1y-X3RGp0dxS6UKwEtmksaMEKIRQn2GgKdUkiuvkaxaoznuExoTPyu0aXk6yFsX5KEDu9UZCgt66bRy6m3KIRnn1VK2frZfqGYi8C8x9Q69oGG316tUwAIm3ypDtv3pREXsDLYE1U5Irdv32hzJ4CqqPyau-qJS18b8CsjvgOppwXRSwpOmU7S3xqo-F7h1eeFw2tgHc7PEPt8MSSKeba8Fz6QyiLhgFr8jFUvKRzk4B41HFUMqXYawbhAtfIBiGGsGrrdNKb7MxISnH1E6yLVCQGGhXiN9U7V0h8Gn56eKzopGlubw7yMmgu8Cu2wBX_a_jFmIBHnn8YgwcRm6NvT96KclDHnFqPVm3On12bG31F7EYkIRGLbaTT6avEu9rL6AJn7Xr245Sa6dC_OSMRKqLSufxp6O6f2TH2g4kvT0Go9SeyM2_acBjIiQ0rFeBOm49H4E4VcJepf79FkljovD68imeZ5MXjxepcCzS138374Jeh7k28JePwJnjDxS8n9Dr6xOU3_wxS1gN5cW6cXSoiPGe0JM4CEyAcUtKrvpUWoTajxxnylZuvS8ou2thfH2PQlAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBQ3yjAtSXrnaSNOtzy1PEXxOO1ZUDAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAFZTSitCISvll6i6rPUPd8Wt2mogRw6I_c-dWQzdc9-SY9iaIGXqVSPKKOlAYU2ju7nvN6AvrIba6sngHeU0AUTeg1UZ5-bDFOWdSgPaGyH_EN_l-vbV6SJPzOmZHJOHfw2WT8hjlFaTaKYRXxzFH7PUR4nxGRbWtdIGgQhUlWg5oo_FO4bvLKfssPSONn684qkAVierq-ly1WeqJzOYhd4EylgVJ9NL3YUhg8dYcHAieptDzF7OcDqffbuZLZUx6xcyibhWQcntAh7a3xPwqXxENsHhme_bqw_kqa-NVk-Wz4zdoiNNLRvUmCSL1WLc4JPsFJ08Ekn1kW7f9ZKnie5aw-29jEf6KIBt4lGDD3tXTfaOVvWcDbu92jMOO1dhEIj63AwQiDJgZhqnrpjlyWU_X0IVQlaPBg80AE0Y3sw1oMrY0XwdeQUjSpH6e5fTYKrNB6NMT1jXGjKIzVg8XbPWlnebP2wEhq8rYiDR31b9B9Sw_naK7Xb-Cqi-VQdUtknSjeljusrBpxGUx-EIJci0-dzeXRT5_376vyKSuYxA1Xd2jd4EknJLIAVLT3rb10DCuKGLDgafbsfTBxVoEa9hSjYOZUr_m3WV6t6I9WPYjVyhyi7fCEIG4JE7YbM4na4jg5q3DM8ibE8jyufAq0PfJZTJyi7c2Q2N_9NgnCNwZ3B1YkFyZWFYdgAjAAsABAByACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAAAwAQACAek7g2C8TeORRoKxuN7HrJ5OinVGuHzEgYODyUsF9D1wAggXPPXn-Pm_4IF0c4XVaJjmHO3EB2KBwdg_L60N0IL9xoY2VydEluZm9Yof9UQ0eAFwAiAAvQNGTLa2wT6u8SKDDdwkgaq5Cmh6jcD_6ULvM9ZmvdbwAUtMInD3WtGSdWHPWijMrW_TfYo-gAAAABPuBems3Sywu4aQsGAe85iOosjtXIACIAC5FPRiZSJzjYMNnAz9zFtM62o57FJwv8F5gNEcioqhHwACIACyVXxq1wZhDsqTqdYr7vQUUJ3vwWVrlN0ZQv5HFnHqWdaGF1dGhEYXRhWKR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EUAAAAACJhwWMrcS4G24TDeUNy-lgAghsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnSlAQIDJiABIVggHpO4NgvE3jkUaCsbjex6yeTop1Rrh8xIGDg8lLBfQ9ciWCCBc89ef4-b_ggXRzhdVomOYc7cQHYoHB2D8vrQ3Qgv3A",
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidXpuOXUwVHgtTEJkdEdnRVJzYmtIUkJqaVV0NWkycnZtMkJCVFpyV3FFbyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
		},
	}
	fixedNow := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response: response, ExpectedChallenge: "uzn9u0Tx-LBdtGgERsbkHRBjiUt5i2rvm2BBTZrWqEo",
		ExpectedOrigins: []string{"https://webauthn.io"}, ExpectedRPIDs: []string{"webauthn.io"},
		Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "tpm" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyRegistrationAuthenticatorExtensionsUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID: "E_Pko4wN1BXE23S0ftN3eQ", RawID: "E_Pko4wN1BXE23S0ftN3eQ", Type: "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBag11_MVj_ad52y40PupImIh1i3hUnUk6T9vqHNlqoxzExQAAAAAAAAAAAAAAAAAAAAAAAAAAABAT8-SjjA3UFcTbdLR-03d5pQECAyYgASFYIJIkX8fs9wjKUv5HWBUop--6ig4Szsxj8gBgJJmaX-_5IlggJ5XVdjUfCMlVlUZuHJRxCLFLzZCeK8Fg3l6OLfAIHnKhbGRldmljZVB1YktleaVjZHBrWE2lAQIDJiABIVggmRqr7Z3kJxqe3q2IBvncltbczQxHYlOlUQSJ7IN5vlsiWCCglzz97bt54n_vTudIFnP7MxJQTdylQ0z9I0MdatKe2mNzaWdYRzBFAiEA77OAdL0VuMgs8J-H-8b7PHFp6k8YBrfpCTc3QwI0W3oCICtxEwQHMaDnJ9M41IVChjzmWICqeeXqdArIzNlDR5iOZW5vbmNlQGVzY29wZUEAZmFhZ3VpZFAAAAAAAAAAAAAAAAAAAAAA",
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQXJrcmxfRnhfTXZjSl9lSXFDVFE3LXRiRVNJU1IxNC1weVBSaDBLLTFBOCIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9",
		},
	}
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response: response, ExpectedChallenge: "Arkrl_Fx_MvcJ_eIqCTQ7-tbESISR14-pyPRh0K-1A8",
		ExpectedOrigins: []string{"android:apk-key-hash:gx7sq_pxhxhrIQdLyfG0pxKwiJ7hOk2DJQ4xvKd438Q"}, ExpectedRPIDs: []string{"try-webauthn.appspot.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil {
		t.Fatalf("verification = %#v", verification)
	}
	devicePublicKey, ok := verification.RegistrationInfo.AuthenticatorExtensionResults["devicePubKey"].(map[string]any)
	if !ok {
		t.Fatalf("devicePubKey extension = %#v", verification.RegistrationInfo.AuthenticatorExtensionResults["devicePubKey"])
	}
	if scope, ok := devicePublicKey["scope"].([]byte); !ok || !bytes.Equal(scope, []byte{0}) {
		t.Fatalf("devicePubKey scope = %#v", devicePublicKey["scope"])
	}
	if aaguid, ok := devicePublicKey["aaguid"].([]byte); !ok || len(aaguid) != 16 {
		t.Fatalf("devicePubKey aaguid = %#v", devicePublicKey["aaguid"])
	}
}

func TestVerifyAuthenticationAuthenticatorExtensionsUpstreamVector(t *testing.T) {
	publicKey, err := base64.RawURLEncoding.DecodeString("pQECAyYgASFYILTrxTUQv3X4DRM6L_pk65FSMebenhCx3RMsTKoBm-AxIlggEf3qk5552QLNSh1T1oQs7_2C2qysDwN4r4fCp52Hsqs")
	if err != nil {
		t.Fatal(err)
	}
	response := AuthenticationResponseJSON{
		ID: "E_Pko4wN1BXE23S0ftN3eQ", RawID: "E_Pko4wN1BXE23S0ftN3eQ", Type: "public-key",
		Response: AssertionResponseJSON{
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVpzVkN6dHJEVzdEMlVfR0hDSWxZS0x3VjJiQ3NCVFJxVlFVbkpYbjlUayIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9",
			AuthenticatorData: "DXX8xWP9p3nbLjQ-6kiYiHWLeFSdSTpP2-oc2WqjHMSFAAAAAKFsZGV2aWNlUHViS2V5pWNkcGtYTaUBAgMmIAEhWCCZGqvtneQnGp7erYgG-dyW1tzNDEdiU6VRBInsg3m-WyJYIKCXPP3tu3nif-9O50gWc_szElBN3KVDTP0jQx1q0p7aY3NpZ1hHMEUCIElSbNKK72tOYhp9WTbStQSVL8CuIxOk8DV6r_-uqWR0AiEAnVE6yu-wsyx2Wq5v66jClGhe_2P_HL8R7PIQevT-uPhlbm9uY2VAZXNjb3BlQQBmYWFndWlkULk_2WHy5kYvsSKCACJH3ng",
			Signature:         "MEYCIQDlRuxY7cYre0sb3T6TovQdfYIUb72cRZYOQv_zS9wN_wIhAOvN-fwjtyIhWRceqJV4SX74-z6oALERbC7ohk8EdVPO",
		},
	}
	verification, err := VerifyAuthenticationResponse(VerifyAuthenticationOptions{
		Response: response, ExpectedChallenge: "iZsVCztrDW7D2U_GHCIlYKLwV2bCsBTRqVQUnJXn9Tk",
		ExpectedOrigins: []string{"android:apk-key-hash:gx7sq_pxhxhrIQdLyfG0pxKwiJ7hOk2DJQ4xvKd438Q"},
		ExpectedRPIDs:   []string{"try-webauthn.appspot.com"},
		Credential: Credential{
			ID:        "AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA",
			PublicKey: publicKey,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verification.Verified || verification.AuthenticationInfo.CredentialID == response.ID {
		t.Fatalf("verification = %#v", verification)
	}
	devicePublicKey, ok := verification.AuthenticationInfo.AuthenticatorExtensionResults["devicePubKey"].(map[string]any)
	if !ok {
		t.Fatalf("devicePubKey extension = %#v", verification.AuthenticationInfo.AuthenticatorExtensionResults["devicePubKey"])
	}
	if scope, ok := devicePublicKey["scope"].([]byte); !ok || !bytes.Equal(scope, []byte{0}) {
		t.Fatalf("devicePubKey scope = %#v", devicePublicKey["scope"])
	}
}

func TestVerifyAdditionalUpstreamAlgorithmVectors(t *testing.T) {
	tests := []struct {
		name, id, attestation, clientData, challenge, origin, rpID, format string
		disableUV                                                          bool
	}{
		{
			name:        "none RSA",
			id:          "kGXv4RJWLeXRw8Yf3T22K3Gq_GGeDv9OKYmAHLm0Ylo",
			attestation: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZz3cRxDpwIiyKduonVYyILs59yKa_0ZbCmVrGvuaivigRQAAAABgKLAXsdRMArSzr82vyWuyACCQZe_hElYt5dHDxh_dPbYrcar8YZ4O_04piYAcubRiWqQBAwM5AQAgWQEA8X6V649G2vwB99CSf_luwR0jj7oDg_GhA3TQSnNYIwfQJldxT5dmi9H8IjjCrTP28iNuKl29hc3Mowux1FZB0bc5AEJ2oV3JCOMGP9NZKGmOosF7iBN2GtGY7Nomcs-ruBv2mxp1nTm6mv5B8XNwh0e18uTA5AJCsl-k6lNLYB2XBIQ3fy2-TjSQ8IOMLypWQbWWBJXzLmepaJ6EWe6kf_NaxpA2chWsaekZcr8xG6OIo3iGh0Mpags_qBZtN4n2TDn0R2LheLk4yQ0R_oOAVtX963Yuw0x5NYSZyMNSMi_1RSEPTYn5AILmIzQskglDaWJYtnjKz4QLuXWCRRYyDSFDAQAB",
			clientData:  "eyJjaGFsbGVuZ2UiOiJwWVozVlgyeWI4ZFM5eXBsTnhKQ2hpWGhQR0JrOGdaelRBeUoyaVU1eDFrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
			challenge:   "pYZ3VX2yb8dS9yplNxJChiXhPGBk8gZzTAyJ2iU5x1k",
			origin:      "https://dev.dontneeda.pw",
			rpID:        "dev.dontneeda.pw",
			format:      "none",
			disableUV:   false,
		},
		{
			name:        "FIDO U2F SHA-1 certificate",
			id:          "7wQcUWO9gG6mi2IktoZUogs8opnghY01DPYwaerMZms",
			attestation: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAN2iKnT1qcZPVab9eiXw6kmMqAsCjR8FMdx8DWCfc6h1AiEA8Hp4Fv2eWsokC8g3sL3tEgNEpsopz-G7l30-czGkuvBjeDVjgVkELzCCBCswggIToAMCAQICAQEwDQYJKoZIhvcNAQEFBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODAzMTYxNDM1MjdaFw0yODAzMTMxNDM1MjdaMIGsMSMwIQYDVQQDDBpGSURPMiBCQVRDSCBLRVkgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBBQUAA4ICAQCPv4yN9RQfvCdl8cwVzLiOGIPrwLatOwARyap0KVJrfJaTs5rydAjinMLav-26bIElQSdus4Z8lnJtavFdGW8VLzdpB_De57XiBp_giTiZBwyCPiG4h-Pk1EAiY7ggednblFi9HxlcNkddyelfiu1Oa9Dlgc5rZsMIkVU4IFW4w6W8dqKhgMM7qRt0ZgRQ19TPdrN7YMsJy6_nujWWpecmXUvFW5SRo7MA2W3WPkKG6Ngwjer8b5-U1ZLpAB4gK46QQaQJrkHymudr6kgmEaUwpue30FGdXNZ9vTrLw8NcfXJMh_I__V4JNABvjJUPUXYN4Qm-y5Ej7wv82A3ktgo_8hcOjlmoZ5yEcDureFLS7kQJC64z9U-55NM7tcIcI-2BMLb2uOZ4lloeq3coP0mZX7KYd6PzGTeQ8Cmkq1GhDum_p7phCx-Rlo44j4H4DypCKH_g-NMWilBQaTSc6K0JAGQiVrh710aQWVhVYf1ITZRoV9Joc9shZQa7o2GvQYLyJHSfCnqJOqnwJ_q-RBBV3EiPLxmOzhBdNUCl1abvPhVtLksbUPfdQHBQ-io70edZe3utb4rFIHboWUSKvW2M3giMZyuSYZt6PzSRNmzqdjZlcFXuJI7iV_O8KNwWuNW14MCKXYi1sliYUhz5iSP9Ym0U2eVzvdsWzz0p55F6xWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAgAAAAAAAAAAAAAAAAAAAAAAIO8EHFFjvYBupotiJLaGVKILPKKZ4IWNNQz2MGnqzGZrpQECAyYgASFYIMmWvjddCcHDGxX5F8qRMl1FccFW5R8VQuZOTey6LqA8IlggZLJ8OVPsX-NPDEUjyjzkV1YLW8Nglp1Ea4qgb2n-O88",
			clientData:  "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwMDAiLCJjaGFsbGVuZ2UiOiJ3SjZtclpua2I2OUdENWQ5X2ZVejktTmdSSEUwejEwcXVYVUJTYTl4SzVvIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
			challenge:   "wJ6mrZnkb69GD5d9_fUz9-NgRHE0z10quXUBSa9xK5o",
			origin:      "http://localhost:8000",
			rpID:        "localhost",
			format:      "fido-u2f",
			disableUV:   true,
		},
		{
			name:        "packed RSA-PSS SHA-256",
			id:          "n_dmFmW9UL7678vS4A3XSQLXvxWjefEkYVzEB5cNc_Q",
			attestation: "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzgkY3NpZ1kBAEaJQ9f_DWVWGJMJrHymDCRP7v2cOzeEA8Z1IUsd4GTq65qqg2khO05tKe6QK_NvpWbiLCRJ2E9QiMUu3xGTl7RIrIRp4T2WCjk5tLbLNwsHuFAPyjcuvIlcX2ZsKNL27tTroIz_zbzDk07vf0jhghoS3ec-qKrSZQ-B0ULgyDJf0omzgDRlH6uon7mErtunes9hVDUTn9pG9UJSL-jDptoJyu87NnBFGnlpu-Iur1lMKIEW27m5E7wYxF7IqIF2lylZGqXxh7ji93Bs7Hhik6y1T9KiGmn58rrYMxmBXzprxNQMF7rJxXbSZ9ZfjaZYamMDaoKDyKEhfAiOHXCm8AVoYXV0aERhdGFZAWZJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAB1qWxJcH1fTWqB93Yyt64CQAAgn_dmFmW9UL7678vS4A3XSQLXvxWjefEkYVzEB5cNc_SkAQMDOCQgWQEArEwu_kUDitzDgKOTthwbNnBGfGeUEwv8ksLGvqyRbTNClHnrR9fpaffqQeNor3ndNSReFnZ_3i468d677NMJC4-qoLKu7JP2FIDpt2reDCxg7-XvsaCcDIOucvKR-KIKg9CGiNpkHMhq2auXc4aqYrRjRyuoNYkzpWGENn34govaQQqC5Gdc0yHSeFJLrc9rbQoxMiZY1Ujpe3p9me0VXL4QdNmH_NlnzRclt38Rl8HqQOhrLo6rJOuRc_Ws-BjT0xh8HL8STgTxwb9aKquFkPxylztEy4TAgmOsFv-ukfGwbGO4fszqQKtpsf5-ulO8mfszgY1VrCLmuDzBzdGsdSFDAQAB",
			clientData:  "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwMDAiLCJjaGFsbGVuZ2UiOiI0MHZfaXpNcHpYLUxPTklHekdxMFlieER3TUtNZmRfWHhRenBlNld2NjRZIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
			challenge:   "40v_izMpzX-LONIGzGq0YbxDwMKMfd_XxQzpe6Wv64Y",
			origin:      "http://localhost:8000",
			rpID:        "localhost",
			format:      "packed",
			disableUV:   true,
		},
		{
			name:        "packed RSA-PSS SHA-384",
			id:          "BCwirFmTkTdTUjVqn_uSy-UOSK-iMBgzpfFunE-Hnb0",
			attestation: "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzglY3NpZ1kBAB7Tn5jK2sn5U4SBuxYzmR-Rg6iU5nox23mUxw6c10RsWcCw0h3aSKaon3gcn_Sfy8cov1YSsJVeUy9jVYJSpfQSS9ZMZXD5btGPf_YKH34j9YSGyTyutquZRxJ01mou2krDIaiXJOGLFpCJfVUBe-ben68MESby_Q2VFA6u3pjayC6Tu_iUJKPwdWPPaJM2P2KwyYtPy2jGIKqn6UFekfHOKpIDInW7QmzZF6JKUXNWqmwddq0vfzBpHlcyCBRDKmbGv667lkOUz9d7h_Lw0ho2HBrqEQuXhfmog5viDsezgHjQ196JZTwIgAO20vWioXiDWwJKjXGUmQxt9OGlQ1doYXV0aERhdGFZAWZJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAABjBuy6aWZcQpm9f0NUYyTRzQAgBCwirFmTkTdTUjVqn_uSy-UOSK-iMBgzpfFunE-Hnb2kAQMDOCUgWQEApgFt6NaWotNSJIfFKOsdNlOtc7vdG7b78Rrnk7oCyUYg9PFVXRhgwSNAKBwimjeRILxcra5roznykpbcv3RIWNaej-tfxG2KYINh5ts8V2I3R2PgtlgwMfSSH9tv65gAzAFRk7tyizHelODhhNUbMVPMc-qTmnBzZANd06w0PN8xnWgCHPaG2MHZkFAOqiNkL4Kv0PPFbQTpy9HZd9ofdQhpKL71iXU4pMFJSSLG8jhY-HM2EwBM2HBTqb06qDjt6UOThCqCqd-ltNRllKWfstkUKQT0XOB-NpZ88037onupO2qDaMSudwolToh3-muuGAYCSANRS3TcNPuYP-s-6yFDAQAB",
			clientData:  "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwMDAiLCJjaGFsbGVuZ2UiOiJwLWphWEhmWUpkbGQ2eTVucklzYTZyblpmNnJnU0MtRm8xcTdBU01VN2s4IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
			challenge:   "p-jaXHfYJdld6y5nrIsa6rnZf6rgSC-Fo1q7ASMU7k8",
			origin:      "http://localhost:8000",
			rpID:        "localhost",
			format:      "packed",
			disableUV:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixedNow := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
			options := VerifyRegistrationOptions{
				Response: RegistrationResponseJSON{
					ID: test.id, RawID: test.id, Type: "public-key",
					Response: AttestationResponseJSON{
						AttestationObject: test.attestation,
						ClientDataJSON:    test.clientData,
					},
				},
				ExpectedChallenge: test.challenge,
				ExpectedOrigins:   []string{test.origin},
				ExpectedRPIDs:     []string{test.rpID},
				Now:               func() time.Time { return fixedNow },
			}
			if test.disableUV {
				options.RequireUserVerification = boolPointer(false)
			}
			verification, err := VerifyRegistrationResponse(options)
			if err != nil {
				t.Fatal(err)
			}
			if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != test.format {
				t.Fatalf("verification = %#v", verification)
			}
		})
	}
}

func TestVerifyAppleAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID:    "J4lAqPXhefDrUD7oh5LQMbBH5TE",
		RawID: "J4lAqPXhefDrUD7oh5LQMbBH5TE",
		Type:  "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXSFZw11MAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwOTEzMDI0OTE3WhcNMjAwOTE0MDI1OTE3WjCBkTFJMEcGA1UEAwxAMzI3ZWI1ODhmMTU3ZDZiYjY0NTRmOTdmNWU1NmM4NmY0NGI1MDdjODgxOGZmMjMwYmQwZjYyNWJkYjY1YmNiNjEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARiAlQ11YPbcpjmwM93iOefyu00h8-4BALNKnBDB5I9n17wD5wNqP0hYua340eB75Z1L_V6I7R4qraq7763zj9mo1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIPuwR1EQvcCtYCRahnJWisqz6YYLEAXH16p0WXbLfY6tMAoGCCqGSM49BAMCA2gAMGUCMDpEvt_ifVr8uu1rnLykezfrHBXwLL-D6DO73l_sX_DLRwXDmqTiPSx0WHiB554m5AIxAIAXIId3WdSC2B2zYFm4ZsJP_jAgjTL1GguZ-Ae78AN2AcjKblEabOdkbKr0aL_M9FkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmD3cRxDpwIiyKduonVYyILs59yKa_0ZbCmVrGvuaivigRQAAAAAAAAAAAAAAAAAAAAAAAAAAABQniUCo9eF58OtQPuiHktAxsEflMaUBAgMmIAEhWCBiAlQ11YPbcpjmwM93iOefyu00h8-4BALNKnBDB5I9nyJYIF7wD5wNqP0hYua340eB75Z1L_V6I7R4qraq7763zj9m",
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaDV4U3lJUk14MklRUHIxbVFrNkdEOThYU1FPQkhnTUhWcEpJa01WOU5rYyIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmRvbnRuZWVkYS5wdyJ9",
			Transports:        []string{"internal"},
		},
	}
	fixedNow := time.Date(2020, time.September, 13, 12, 0, 0, 0, time.UTC)
	verification, err := VerifyRegistrationResponse(VerifyRegistrationOptions{
		Response:          response,
		ExpectedChallenge: "h5xSyIRMx2IQPr1mQk6GD98XSQOBHgMHVpJIkMV9Nkc",
		ExpectedOrigins:   []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:     []string{"dev.dontneeda.pw"},
		Now:               func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "apple" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyAndroidSafetyNetAttestationUpstreamVector(t *testing.T) {
	response := RegistrationResponseJSON{
		ID:    "AS_TChPtwkqgPwDxkkF39yjfaPJtKiwMGIY69EV7udG2xaP8hYnjJsPS7VPnUA2xaUZc7dHot5WwYRRoavu7Ais",
		RawID: "AS_TChPtwkqgPwDxkkF39yjfaPJtKiwMGIY69EV7udG2xaP8hYnjJsPS7VPnUA2xaUZc7dHot5WwYRRoavu7Ais",
		Type:  "public-key",
		Response: AttestationResponseJSON{
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWjI5dloyeGxMVzloZFhSb01ud3hNREUyTVRFME1EUTVOREk1T0RRek56YzROak0iLCJvcmlnaW4iOiJodHRwczpcL1wvbG9naW4uYXV0aHJlc3MuaW8iLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uYW5kcm9pZC5jaHJvbWUifQ",
			AttestationObject: "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTI1MjAzNzAyOWhyZXNwb25zZVkf_WV5SmhiR2NpT2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR1RXcERRMEpDY1dkQmQwbENRV2RKVWtGTEswZFhaRGR0ZFRocE1rTjFNbGs0Tmk5dk1DOVZkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVDNwRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSWFrRmpRbWRPVmtKQmIxUkdWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM3BGVFUxQmIwZEJNVlZGUVhoTlJGWXhTVEJOUWpSWVJGUkpNVTFFVVhsUFZFRTBUVVJCTUU1R2IxaEVWRWt4VFVSamVVOUVRVFJOUkVFd1RURnZkMGhVUldKTlFtdEhRVEZWUlVGNFRWTlpXRkl3V2xoT01FeHRSblZhU0VwMllWZFJkVmt5T1hSTlNVbENTV3BCVGtKbmEzRm9hMmxIT1hjd1FrRlJSVVpCUVU5RFFWRTRRVTFKU1VKRFowdERRVkZGUVRGVFJrcE1aR0Y0TTNVcllYRmxaVkJPWWt4NFlqRjJUelEwTWxGRFN5OUROekZCUW5GcWVrNVNWVlp3ZUM5eFRIZ3pSMGhGZDAxTFpVdzNjVVpHVG1WTmVVcExSRW8xU0ZCVk5qQm5NRWw0Tm5BM1FtbFBkbXRFVlhvck1sRnFWalJ3V2pWMU5rMDRVekJtVGpkbGJuaFJjSGhJUWtrdkx6VnhNMUUxY2tGVk1UQkRZMWhZZHpoYVpYVlZRa3BTUW5kMVVscDJiVE0xYlZsWFJsVnZkRmQyWVVSRVNYcGFlWFV6TVdST1MyeExkREJUWWtWMVJubGpaVmRhT0dKaGIzUkNkVWRtYUZveE1HeElSMHRtV0VORFVqWXpkVnBOU0Uxa2NHVjVWa280ZHpkemIxZzJkMnRoZFZwd1lsRTFSMWs0VkRKUWJFbFBlRWxsV2tVeWNWcGtha3RLV2paVFdrOVhTalo0V1VNelduUmFOM2hhUldzMmFEbHlOSEZ0VlN0VVlXSkVOM00zVEhGSFZIWTRTRlF4YjJNNWQyRTRLMmhrTDNNNWRHZFpRbTB4UlROaWJIWTRiVFZZUlhrdlNHbFhTbEpJVVVsRVFWRkJRbTgwU1VOVVZFTkRRV3RyZDBSbldVUldVakJRUVZGSUwwSkJVVVJCWjFkblRVSk5SMEV4VldSS1VWRk5UVUZ2UjBORGMwZEJVVlZHUW5kTlFrMUJkMGRCTVZWa1JYZEZRaTkzVVVOTlFVRjNTRkZaUkZaU01FOUNRbGxGUmtoYU1HWm5OVXhVUTNSYU9HZEhkRmRzZDBkTU1sY3hSbmhRUzAxQ09FZEJNVlZrU1hkUldVMUNZVUZHU25aSlJXSjNPWEZxWVRWTldYaFBhakJVVmxaNlNYWjNPRUpvVFVZMFIwTkRjMGRCVVZWR1FuZEZRa0pHU1hkVlJFRnVRbWRuY2tKblJVWkNVV04zUVZsWlltRklVakJqUkc5MlRESTRkV05IZEhCTWJXUjJZakpqZG1ONU9UTmphbEYyWTJwU1drMURWVWREUTNOSFFWRlZSa0o2UVVOb2FHeHZaRWhTZDA5cE9IWmhVelYzWVRKcmRWb3lPWFphZVRrelkycFJkVmt6U2pCTlFqQkhRVEZWWkVWUlVWZE5RbE5EUlcxR01HUkhWbnBrUXpWb1ltMVNlV0l5Ykd0TWJVNTJZbFJCVkVKblRsWklVMEZGUkVSQlMwMUJaMGRDYldWQ1JFRkZRMEZVUVRKQ1owNVdTRkk0UlV4NlFYUk5RM1ZuUzJGQmJtaHBWbTlrU0ZKM1QyazRkbGw1TlhkaE1tdDFXakk1ZGxwNU9UTmphbEYyV1d0V1UxcHJNVWxSVlZrMVZEQlZkVmt6U25OTlNVbENRbWRaUzB0M1dVSkNRVWhYWlZGSlJVRm5VMEk1ZDFOQ09VRkVlVUZJWTBFelpIcExUa3BZV0RSU1dVWTFOVlY1SzNObFppdEVNR05WVGk5aVFVUnZWVVZ1V1V0TVMzazNlVU52UVVGQlIxZG5UV05PUW5kQlFVSkJUVUZUUkVKSFFXbEZRVGR4VGk5U1ExQk5ia3RLUkZCclIzbExkRUZtWjJVd1ExUmxkV2xHU1ZVM04yMDVLM2MyVTJJMGJqQkRTVkZEYjBZME0zRTNTV052U0hZMU1tZG5TR1l4VG01eE0zWnhVM1IzUWs4MlpHOHZkRkpsTkVGNWExTnRkMEl6UVUxNk4wUXljVVpqVVd4c0wzQlhZbFU0TjNCemJuZHBObGxXWTBSYVpVNTBjV3dyVmsxRUsxUkJNbmRCUVVGQ2JHOUVTRVZQT0VGQlFWRkVRVVZuZDFKblNXaEJTMnd5VFV0YWNVVlNjV1pNWkVwaEt6bERNemRXU0dWTk5rWjFSRlIyVmpkNGRHeDFTR2hWVTBkdFpFRnBSVUZ5VlRVMGRtdFVUR3A2VDI0NEwyODNVVkkwZUN0ek9FWmlkV1JMV1M5a01VUXZiekI0YkZsNGJHVTRkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUZFWjJkRlFrRktOMDFwVVd4M2JqaHJiV1ppWVVKM1NUTmtWakI1Vm5RMWF6WkRMMjlIZUVWaldYQlpTRUZIU2pJMU5saG9lSFZtYTBoaFkzZGFVRkJ4VVdZNU5Fc3dWRWRRVkVKMGJGRmlRVFJoU0doME4wbExPVWRHYTBOdk5IbHVSbHBKTVN0NWNXUjVXbmh6ZW1aU1pVSTFRVXhJTTNoa2NqQnFMMmRhVG5OQlpDdFJSakUwUTBoUGJsWTVOV1pOVVc1dVNXaDFieXQxWWtoVFpVMTNlREJ0ZVcxdGJWUldRVGs0Wm5rMmRYaDBZWFZaVUZocVozZ3JPVGxQVm05U2FYaEtOWGg0VlVkVlRGcEpjaTlHZVRodE1tZEhRMGR0UlU5alMwcExUbmQxUWprMmNYRjJLMVpaZFM5QlZuUTJUMHh0V1RONGIydEdLMmgzWkVZMmNURXZWRkZwYTJGeVFuUjBWVmxSV25Bd1QwZDVhM1pJTVZGelIwMDNSRU12TmpORU0weEtRMFIwV1U0eUsxa3ZkRmdyWm14T2IzazVibXByTTNSSE1GcEplVzB4ZUhKNE1FcDVSSFF5VVRCb1dYUnFTRVpoTDI4M2RrVTlJaXdpVFVsSlJrTjZRME5CZGs5blFYZEpRa0ZuU1ZGbUwwRkdkRTV3TVhWSGNHRjRhQzlyVFVoalZIcFVRVTVDWjJ0eGFHdHBSemwzTUVKQlVYTkdRVVJDU0UxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtWcFRVTkJSMEV4VlVWRGFFMWFVakk1ZGxveWVHeEpSbEo1WkZoT01FbEdUbXhqYmxwd1dUSldla2xGZUUxUmVrVlZUVUpKUjBFeFZVVkJlRTFNVWpGU1ZFbEdTblppTTFGblZXcEZkMGhvWTA1TmFrMTRUV3BGZWsxRWEzZE5SRUYzVjJoalRrMXFhM2ROYWtsM1RWUlJkMDFFUVhkWGFrRTNUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWRjNkME5uV1VSV1VWRkVSWGRPV0ZWcVVYZG5aMFZwVFVFd1IwTlRjVWRUU1dJelJGRkZRa0ZSVlVGQk5FbENSSGRCZDJkblJVdEJiMGxDUVZGRGRsUnNSeTk2YkVOck5qUTBPV3RoVnk5RVEyOXBjVzl3TUhCSmQzbGhUamhMVVVkaWMxWXlNSE55TUdJME1qbEtjbEpOVVV4S1ZDODNjMGxTVEhOWVpISldZMEUxTnpjMVZqbFlVUzlHYkZaUVZYTjVSbEZoVjBoRmVHZGhVV0ZtTWxCYWVFNVdhMWxtVkRsVFZEVTNZVGxWWWxZclRsUnNaR051YlhoMmIyOU1iWEJvZHk5VVJuWnNibkJ4TW5KTk1UVjViRWhwY1Roc1IzRm5VWEJTT1M4MlFVeDFiMnh0VjBSV1QxQkdSV2RCYkZSa09WRnZSVmM1WjB4TmRVY3piRTh6TVd4MGMyVnVXbGRVTVd4RFVWTXlVbEpXVTNoWWFqZGpVak15YkZoblUwVnphekZhZWpVM1pWSnNaME5tZVdaQmRsVktWWFJOZERrNE1uTnZUbEl5WkhwUFZrOUxhamw2YkdsbFJuSmlaR1pDV21oNFdraFJiamRKU25WSFkyTmthVXB1UzFSVVpXSkNhbmhOYUZWalZVaHJOako1YkU4M1oyVk1kR0l6U2sxVlltSnVkbE5aUkRKVlFXTnNaM3B5ZDJ4QlowMUNRVUZIYW1kbU5IZG5abk4zUkdkWlJGWlNNRkJCVVVndlFrRlJSRUZuUjBkTlFqQkhRVEZWWkVwUlVWZE5RbEZIUTBOelIwRlJWVVpDZDAxQ1FtZG5ja0puUlVaQ1VXTkVRV3BCVTBKblRsWklVazFDUVdZNFJVTkVRVWRCVVVndlFXZEZRVTFDTUVkQk1WVmtSR2RSVjBKQ1UySjVRa2M0VUdGdk1uVlVSMDFVYnpsRk1WWmplVXc0VUVGWlZFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVWEzSjVjMjFqVW05eVUwTmxSa3d4U20xTVR5OTNhVkpPZUZCcVFUQkNaMmR5UW1kRlJrSlJZMEpCVVZGdlRVTlpkMHBCV1VsTGQxbENRbEZWU0UxQlMwZEhSMmd3WkVoQk5reDVPWEJNYmtKeVlWTTFibUl5T1c1TU0wbDRURzFPZVdSRVFYSkNaMDVXU0ZJNFJVcEVRV2xOUTBOblNIRkJZMmhvY0c5a1NGSjNUMms0ZGxsNU5YZGhNbXQxV2pJNWRscDVPWGxNTTBsNFRHMU9lV0pFUVZSQ1owNVdTRk5CUlVSRVFVdE5RV2RIUW0xbFFrUkJSVU5CVkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGQlQwTkJaMFZCYURKdVJEbFhSRFZ6YTNwVlRFRjRiVWxrZEhoV1dscEdPQzgxZDNRMWFXWkpUVlZCVlZKT1ZuZGFZMHc1ZFhWUGRuSk9WRGMxY0Zab2VUTlpOR1J4T1ZCMFFrUjVTVzFuVkdOSldISnhjRGhGVEd4UlNHSk5SMUl5YjI1RE1YazFhRkpwYjFJelIwY3hTamh4UjBKbE0wSXhSRkY2YmpCeGJ6VkhhM0o0TkdscGFpOWtOblI1YjBkNFpucGtRWFowVUZKUksyczJVR0ZZWVRoTVYyUm9hbkJUTHk5WFJtZFBOazFZVDB0bE5uRlVhV05XYldvMk5GaFpkMnB2UkZGWlRuVlpTSFJEVjFCR2NsYzRhVzFEWkROU01UVklLek5MYkVOdVRUZEdkbEY1WkU1eU1EUk1VRlYwTDB4WlRUaEhXa2hDU25sVmNURnZXSFpGTlZKTFYydHZkekZRZEVod2RXMHpPVGgxUjNsV2VtWXJkblVyTURGcEwyMWtSRkZ3YzJJdlNTOVFVVlk1UWtGS2FXNDVSVEpqWmxsTWJFRnpUbXc1Vm1GVmIxVnBaemx4ZFd4VEsycHJibVJvZEU5VFVXTlhkSGMyTWxsTWRVZHZMM2xKT1dOR05GVlpOSEU1YkZkblRrODNURGxKVmxaSVVXODVORzlEY2t3eFoxSk5TMEZPZEVacllXTk1SRVZEZDBGMVJsTkxkblZvWVRkRVlXNVpOMmhhTjFseFJqWklhMDVzU25wVVFUWlpPVlZTVG5FNVRYaHhTbWhOWlZSa2EyVm1laXR6TVVGa0wxRlpNR1V5VFVoSFoySkZLMjlPWkRSaGQxUmtja1Y0VXpKQ01rVndOM2RqVTJreGIwRXpOSEJKWVVwblVYVlhkVGhHY205alEzTjZjM0ZqSzI5S1YxUnlkekpXVVdkbE9YaG5WVnBWVFZwTVVsZGlSalJxTTBaTFVITldWbWRXS3pkbk9UVlNUa1ZxUjJoRE1VMDRUR0Z6T0hkM05WUXJkVUpRVFV4elUxRnJNa0pTU0dOM1pubEVVakl3T1RKS1JteGtSM1ZCT0UxVlFYSkhUaTl1U0ZSRVpsZGhXVXhKVUVOVmFIZENhSEJaVDJwTGJtazBaVkJNY21Ga2NUZEJSekpSYjBkV2MzcGFkMmRLWlhGTVdFcENaaXRKTm01NWVrWmtNbU0xVDFoTlJ6WTFUbU05SWl3aVRVbEpSbGxxUTBOQ1JYRm5RWGRKUWtGblNWRmtOekJPWWs1ek1pdFNjbkZKVVM5Rk9FWnFWRVJVUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVSQ1dFMVJjM2REVVZsRVZsRlJSMFYzU2tOU1ZFVmFUVUpqUjBFeFZVVkRhRTFSVWpKNGRsbHRSbk5WTW14dVltbENkV1JwTVhwWlZFVlJUVUUwUjBFeFZVVkRlRTFJVlcwNWRtUkRRa1JSVkVWaVRVSnJSMEV4VlVWQmVFMVRVako0ZGxsdFJuTlZNbXh1WW1sQ1UySXlPVEJKUlU1Q1RVSTBXRVJVU1hkTlJGbDRUMVJCZDAxRVFUQk5iRzlZUkZSSk5FMUVSWGxQUkVGM1RVUkJNRTFzYjNkU2VrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmVFbHFRV2RDWjA1V1FrRnZWRWRWWkhaaU1tUnpXbE5DVldOdVZucGtRMEpVV2xoS01tRlhUbXhqZVVKTlZFVk5lRVpFUVZOQ1owNVdRa0ZOVkVNd1pGVlZlVUpUWWpJNU1FbEdTWGhOU1VsRFNXcEJUa0puYTNGb2EybEhPWGN3UWtGUlJVWkJRVTlEUVdjNFFVMUpTVU5EWjB0RFFXZEZRWFJvUlVOcGVEZHFiMWhsWWs4NWVTOXNSRFl6YkdGa1FWQkxTRGxuZG13NVRXZGhRMk5tWWpKcVNDODNOazUxT0dGcE5saHNOazlOVXk5cmNqbHlTRFY2YjFGa2MyWnVSbXc1TjNaMVprdHFObUozVTJsV05tNXhiRXR5SzBOTmJuazJVM2h1UjFCaU1UVnNLemhCY0dVMk1tbHRPVTFhWVZKM01VNUZSRkJxVkhKRlZHODRaMWxpUlhaekwwRnRVVE0xTVd0TFUxVnFRalpITURCcU1IVlpUMFJRTUdkdFNIVTRNVWs0UlRORGQyNXhTV2x5ZFRaNk1XdGFNWEVyVUhOQlpYZHVha2g0WjNOSVFUTjVObTFpVjNkYVJISllXV1pwV1dGU1VVMDVjMGh0YTJ4RGFYUkVNemh0TldGblNTOXdZbTlRUjJsVlZTczJSRTl2WjNKR1dsbEtjM1ZDTm1wRE5URXhjSHB5Y0RGYWEybzFXbEJoU3pRNWJEaExSV280UXpoUlRVRk1XRXd6TW1nM1RURmlTM2RaVlVnclJUUkZlazVyZEUxbk5sUlBPRlZ3YlhaTmNsVndjM2xWY1hSRmFqVmpkVWhMV2xCbWJXZG9RMDQyU2pORGFXOXFOazlIWVVzdlIxQTFRV1pzTkM5WWRHTmtMM0F5YUM5eWN6TTNSVTlsV2xaWWRFd3diVGM1V1VJd1pYTlhRM0oxVDBNM1dFWjRXWEJXY1RsUGN6WndSa3hMWTNkYWNFUkpiRlJwY25oYVZWUlJRWE0yY1hwcmJUQTJjRGs0WnpkQ1FXVXJaRVJ4Tm1SemJ6UTVPV2xaU0RaVVMxZ3ZNVmszUkhwcmRtZDBaR2w2YW10WVVHUnpSSFJSUTNZNVZYY3JkM0E1VlRkRVlrZExiMmRRWlUxaE0wMWtLM0IyWlhvM1Z6TTFSV2xGZFdFckszUm5lUzlDUW1wR1JrWjVNMnd6VjBad1R6bExWMmQ2TjNwd2JUZEJaVXRLZERoVU1URmtiR1ZEWm1WWWEydFZRVXRKUVdZMWNXOUpZbUZ3YzFwWGQzQmlhMDVHYUVoaGVESjRTVkJGUkdkbVp6RmhlbFpaT0RCYVkwWjFZM1JNTjFSc1RHNU5VUzh3YkZWVVltbFRkekZ1U0RZNVRVYzJlazh3WWpsbU5rSlJaR2RCYlVRd05ubExOVFp0UkdOWlFscFZRMEYzUlVGQllVOURRVlJuZDJkblJUQk5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRbWhxUVZCQ1owNVdTRkpOUWtGbU9FVkNWRUZFUVZGSUwwMUNNRWRCTVZWa1JHZFJWMEpDVkd0eWVYTnRZMUp2Y2xORFpVWk1NVXB0VEU4dmQybFNUbmhRYWtGbVFtZE9Wa2hUVFVWSFJFRlhaMEpTWjJVeVdXRlNVVEpZZVc5c1VVd3pNRVY2VkZOdkx5OTZPVk42UW1kQ1oyZHlRbWRGUmtKUlkwSkJVVkpWVFVaSmQwcFJXVWxMZDFsQ1FsRlZTRTFCUjBkSFYyZ3daRWhCTmt4NU9YWlpNMDUzVEc1Q2NtRlROVzVpTWpsdVRESmtlbU5xUlhkTFVWbEpTM2RaUWtKUlZVaE5RVXRIU0Zkb01HUklRVFpNZVRsM1lUSnJkVm95T1haYWVUbHVZek5KZUV3eVpIcGpha1YxV1ROS01FMUVTVWRCTVZWa1NIZFJjazFEYTNkS05rRnNiME5QUjBsWGFEQmtTRUUyVEhrNWFtTnRkM1ZqUjNSd1RHMWtkbUl5WTNaYU0wNTVUVk01Ym1NelNYaE1iVTU1WWtSQk4wSm5UbFpJVTBGRlRrUkJlVTFCWjBkQ2JXVkNSRUZGUTBGVVFVbENaMXB1WjFGM1FrRm5TWGRFVVZsTVMzZFpRa0pCU0ZkbFVVbEdRWGRKZDBSUldVeExkMWxDUWtGSVYyVlJTVVpCZDAxM1JGRlpTa3R2V2tsb2RtTk9RVkZGVEVKUlFVUm5aMFZDUVVSVGEwaHlSVzl2T1VNd1pHaGxiVTFZYjJnMlpFWlRVSE5xWW1SQ1drSnBUR2M1VGxJemREVlFLMVEwVm5obWNUZDJjV1pOTDJJMVFUTlNhVEZtZVVwdE9XSjJhR1JIWVVwUk0ySXlkRFo1VFVGWlRpOXZiRlZoZW5OaFRDdDVlVVZ1T1Zkd2NrdEJVMDl6YUVsQmNrRnZlVnBzSzNSS1lXOTRNVEU0Wm1WemMyMVliakZvU1ZaM05ERnZaVkZoTVhZeGRtYzBSblkzTkhwUWJEWXZRV2hUY25jNVZUVndRMXBGZERSWGFUUjNVM1I2Tm1SVVdpOURURUZPZURoTVdtZ3hTamRSU2xacU1tWm9UWFJtVkVweU9YYzBlak13V2pJd09XWlBWVEJwVDAxNUszRmtkVUp0Y0haMldYVlNOMmhhVERaRWRYQnplbVp1ZHpCVGEyWjBhSE14T0dSSE9WcExZalU1VldoMmJXRlRSMXBTVm1KT1VYQnpaek5DV214MmFXUXdiRWxMVHpKa01YaHZlbU5zVDNwbmFsaFFXVzkyU2twSmRXeDBlbXROZFRNMGNWRmlPVk42TDNscGJISmlRMmRxT0QwaVhYMC5leUp1YjI1alpTSTZJblpvUmxadE5UbG9NR1JCWVZwNWJVTlZVMnBPZGtJNWJFdHZPSGRVV2t0REsybDVWbWhYZW5kYUwwazlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTNORGsxTURFMk5ESTVPRGtzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJazlyU2tscWVHeDBhbVpYY1hsMEwwYzVTamRrTVZkblREUjBVUzg0WlRoSlNITTJja1UzWTNGWlkzYzlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanBtWVd4elpTd2lZWEJyUTJWeWRHbG1hV05oZEdWRWFXZGxjM1JUYUdFeU5UWWlPbHNpT0ZBeGMxY3dSVkJLWTNOc2R6ZFZlbEp6YVZoTU5qUjNLMDgxTUVWa0sxSkNTVU4wWVhreFp6STBUVDBpWFN3aVltRnphV05KYm5SbFozSnBkSGtpT25SeWRXVXNJbVYyWVd4MVlYUnBiMjVVZVhCbElqb2lRa0ZUU1VNaUxDSmtaWEJ5WldOaGRHbHZia2x1Wm05eWJXRjBhVzl1SWpvaVZHaGxJRk5oWm1WMGVVNWxkQ0JCZEhSbGMzUmhkR2x2YmlCQlVFa2dhWE1nWkdWd2NtVmpZWFJsWkM0Z1NYUWdhWE1nY21WamIyMXRaVzVrWldRZ2RHOGdkWE5sSUhSb1pTQlFiR0Y1SUVsdWRHVm5jbWwwZVNCQlVFazZJR2gwZEhCek9pOHZaeTVqYnk5d2JHRjVMM05oWm1WMGVXNWxkQzEwYVcxbGJHbHVaUzRpZlEuUnpfZklvRjM3SE5CV05Db2NtckdxLXpsVDMtbUZJZkZvand5YUxiWXJ4dVpwcldxZ0RmNFo4SDBvMVY1WllmcWdXckw2bHNkVVlnZkxmTGRrRjFTQUhiT1U1cEVhYlQzVzdNRUdLLVBiNkZsRlg4NWpMYllSNmVSY3BFV2lVeTVvci1FMVhNSTIwand1Qk10UkJOVnVuV2JqV2gtVkJwWjZTcWRfZURfN3hiSnd0NFdXNW5kZDdZRHB1U3FETThiVldFRHRMOF9yTjRacUhndzJ1ZDI5NUswNHlaTmVTNkdKb0JDdFNzYVAyTjhRdmIwcXl3UlFlWWd6Vi1pVDlkREpnSnVfS1ExWWxmN0N3Nm9nOG56b3l5c1pvMFZXc3BnUnV2eUFFQTFjVFhVSXhISC1nQTVvRWtsTlZJbmtudHNoZWlBc1AtTlFhR25ITUVRVkhYMlNnaGF1dGhEYXRhWMVohwRhK0KVlcdgFyyI6dEhDIutzOO6c9Ae1qAfEXAiQkUAAAAAuT_ZYfLmRi-xIoIAIkfeeABBAS_TChPtwkqgPwDxkkF39yjfaPJtKiwMGIY69EV7udG2xaP8hYnjJsPS7VPnUA2xaUZc7dHot5WwYRRoavu7AiulAQIDJiABIVgg2nChB8Re-aOqUtqbEDUD6BE18yvs5eixZ5gOA5O3Q14iWCDf6BSjMgCAznWaVDQsxx7PdxJFvRwEqqUqA4D7EmNQWQ",
		},
	}
	fixedNow := time.Date(2025, time.June, 9, 20, 40, 42, 989_000_000, time.UTC)
	options := VerifyRegistrationOptions{
		Response:                response,
		ExpectedChallenge:       "Z29vZ2xlLW9hdXRoMnwxMDE2MTE0MDQ5NDI5ODQzNzc4NjM",
		ExpectedOrigins:         []string{"https://login.authress.io"},
		ExpectedRPIDs:           []string{"authress.io"},
		RequireUserVerification: boolPointer(false),
		RequireUserPresence:     boolPointer(false),
		Now:                     func() time.Time { return fixedNow },
	}

	_, err := VerifyRegistrationResponse(options)
	if err == nil || !strings.Contains(err.Error(), "device integrity") {
		t.Fatalf("default CTS enforcement error = %v", err)
	}

	options.AttestationSafetyNetEnforceCTSCheck = boolPointer(false)
	verification, err := VerifyRegistrationResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.Format != "android-safetynet" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyAuthenticationUpstreamVector(t *testing.T) {
	publicKey, err := base64.RawURLEncoding.DecodeString("pQECAyYgASFYIIheFp-u6GvFT2LNGovf3ZrT0iFVBsA_76rRysxRG9A1Ilgg8WGeA6hPmnab0HAViUYVRkwTNcN77QBf_RR0dv3lIvQ")
	if err != nil {
		t.Fatal(err)
	}
	response := upstreamAssertion()
	credential := Credential{ID: response.ID, PublicKey: publicKey, Counter: 143}
	verification, err := VerifyAuthenticationResponse(VerifyAuthenticationOptions{
		Response:                response,
		ExpectedChallenge:       "dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlUaW1l",
		ExpectedOrigins:         []string{"https://dev.dontneeda.pw"},
		ExpectedRPIDs:           []string{"dev.dontneeda.pw"},
		Credential:              credential,
		RequireUserVerification: boolPointer(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.AuthenticationInfo.NewCounter != 144 || verification.AuthenticationInfo.RPID != "dev.dontneeda.pw" {
		t.Fatalf("verification = %#v", verification)
	}

	t.Run("replay counter", func(t *testing.T) {
		credential.Counter = 144
		_, err := VerifyAuthenticationResponse(VerifyAuthenticationOptions{Response: response, ExpectedChallenge: "dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlUaW1l", ExpectedOrigins: []string{"https://dev.dontneeda.pw"}, ExpectedRPIDs: []string{"dev.dontneeda.pw"}, Credential: credential, RequireUserVerification: boolPointer(false)})
		if err == nil || !strings.Contains(err.Error(), "counter value") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("invalid signature is unverified", func(t *testing.T) {
		credential.Counter = 143
		changed := response
		signature, err := decodeBase64URL(changed.Response.Signature, "test signature", MaxSignatureBytes)
		if err != nil {
			t.Fatal(err)
		}
		signature[len(signature)-1] ^= 1
		changed.Response.Signature = encodeBase64URL(signature)
		verification, err := VerifyAuthenticationResponse(VerifyAuthenticationOptions{Response: changed, ExpectedChallenge: "dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlUaW1l", ExpectedOrigins: []string{"https://dev.dontneeda.pw"}, ExpectedRPIDs: []string{"dev.dontneeda.pw"}, Credential: credential, RequireUserVerification: boolPointer(false)})
		if err != nil || verification.Verified {
			t.Fatalf("verification=%#v err=%v", verification, err)
		}
	})
	t.Run("malformed signature is rejected", func(t *testing.T) {
		credential.Counter = 143
		changed := response
		changed.Response.Signature = "AA"
		if _, err := VerifyAuthenticationResponse(VerifyAuthenticationOptions{Response: changed, ExpectedChallenge: "dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlUaW1l", ExpectedOrigins: []string{"https://dev.dontneeda.pw"}, ExpectedRPIDs: []string{"dev.dontneeda.pw"}, Credential: credential, RequireUserVerification: boolPointer(false)}); err == nil {
			t.Fatal("expected malformed ECDSA signature error")
		}
	})
}

func TestVerificationBranches(t *testing.T) {
	const challenge = "aEVjY1BXdXppUDAwSDBwNWd4aDJfdTVfUEM0TmVZZ2Q"
	registration := upstreamNoneRegistration()
	options := VerifyRegistrationOptions{
		Response:          registration,
		ExpectedChallenge: "ignored-when-callback-is-present",
		ChallengeVerifier: func(value string) (bool, error) { return value == challenge, nil },
		ExpectedOrigins:   []string{"https://wrong.example", "https://dev.dontneeda.pw"},
		ExpectedRPIDs:     []string{"wrong.example", "dev.dontneeda.pw"},
		ExpectedTypes:     []string{"payment.create", "webauthn.create"},
	}
	verification, err := VerifyRegistrationResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.RegistrationInfo == nil || verification.RegistrationInfo.RPID != "dev.dontneeda.pw" {
		t.Fatalf("verification = %#v", verification)
	}

	options.ExpectedRPIDs = nil
	verification, err = VerifyRegistrationResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if verification.RegistrationInfo == nil || verification.RegistrationInfo.RPID != "" {
		t.Fatalf("omitted RP ID should remain absent: %#v", verification)
	}

	options.ExpectedRPIDs = []string{}
	if _, err := VerifyRegistrationResponse(options); err == nil {
		t.Fatal("an explicitly empty RP ID list must not behave like an omitted RP ID")
	}
	options.ExpectedRPIDs = []string{"dev.dontneeda.pw"}
	options.ExpectedTypes = []string{}
	if _, err := VerifyRegistrationResponse(options); err == nil {
		t.Fatal("an explicitly empty expected-type list must reject every ceremony type")
	}
}

func TestAdvancedFIDOUserVerificationSemantics(t *testing.T) {
	const (
		rpID      = "example.com"
		origin    = "https://example.com"
		challenge = "challenge"
	)
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	credentialPublicKey, err := encodeCBOR(map[int64]any{
		1: int64(COSEKTYOKP), 3: int64(COSEAlgEdDSA), -1: int64(COSECurveEd25519), -2: []byte(publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	clientData := []byte(`{"type":"webauthn.get","challenge":"challenge","origin":"https://example.com"}`)
	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData := append([]byte(nil), rpIDHash[:]...)
	authenticatorData = append(authenticatorData, 0x00, 0x00, 0x00, 0x00, 0x00) // No UP or UV, counter zero.
	clientDataHash := sha256.Sum256(clientData)
	signature := ed25519.Sign(privateKey, concatenate(authenticatorData, clientDataHash[:]))
	response := AuthenticationResponseJSON{
		ID: "AQ", RawID: "AQ", Type: "public-key",
		Response: AssertionResponseJSON{
			ClientDataJSON:    encodeBase64URL(clientData),
			AuthenticatorData: encodeBase64URL(authenticatorData),
			Signature:         encodeBase64URL(signature),
		},
	}
	base := VerifyAuthenticationOptions{
		Response: response, ExpectedChallenge: challenge, ExpectedOrigins: []string{origin}, ExpectedRPIDs: []string{rpID},
		Credential: Credential{ID: response.ID, PublicKey: credentialPublicKey},
	}
	if _, err := VerifyAuthenticationResponse(base); err == nil || !strings.Contains(err.Error(), "present") {
		t.Fatalf("default WebAuthn flag validation error = %v", err)
	}

	base.AdvancedFIDOConfig = &AdvancedFIDOConfig{}
	verificationAuth, err := VerifyAuthenticationResponse(base)
	if err != nil || !verificationAuth.Verified {
		t.Fatalf("empty advanced FIDO config should skip UP and UV: verification=%#v err=%v", verificationAuth, err)
	}
	base.AdvancedFIDOConfig = &AdvancedFIDOConfig{UserVerification: "required"}
	if _, err := VerifyAuthenticationResponse(base); err == nil || !strings.Contains(err.Error(), "verification required") {
		t.Fatalf("advanced required UV error = %v", err)
	}
	base.AdvancedFIDOConfig = &AdvancedFIDOConfig{UserVerification: "runtime-unknown"}
	verificationAuth, err = VerifyAuthenticationResponse(base)
	if err != nil || !verificationAuth.Verified {
		t.Fatalf("unknown runtime FIDO value mirrors upstream no-op: verification=%#v err=%v", verificationAuth, err)
	}
}

func TestVerificationNegativeVectors(t *testing.T) {
	registration := upstreamNoneRegistration()
	base := VerifyRegistrationOptions{Response: registration, ExpectedChallenge: "aEVjY1BXdXppUDAwSDBwNWd4aDJfdTVfUEM0TmVZZ2Q", ExpectedOrigins: []string{"https://dev.dontneeda.pw"}, ExpectedRPIDs: []string{"dev.dontneeda.pw"}}
	for _, test := range []struct {
		name     string
		change   func(*VerifyRegistrationOptions)
		contains string
	}{
		{"credential ID", func(value *VerifyRegistrationOptions) { value.Response.RawID = "different" }, "base64url"},
		{"credential type", func(value *VerifyRegistrationOptions) { value.Response.Type = "password" }, "credential type"},
		{"challenge", func(value *VerifyRegistrationOptions) { value.ExpectedChallenge = "wrong" }, "challenge"},
		{"origin", func(value *VerifyRegistrationOptions) { value.ExpectedOrigins = []string{"https://wrong.example"} }, "origin"},
		{"RP ID", func(value *VerifyRegistrationOptions) { value.ExpectedRPIDs = []string{"wrong.example"} }, "RP ID"},
		{"type", func(value *VerifyRegistrationOptions) { value.ExpectedTypes = []string{"webauthn.get"} }, "response type"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.change(&options)
			_, err := VerifyRegistrationResponse(options)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.contains)) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	t.Run("invalid backup flags", func(t *testing.T) {
		_, _, err := ParseBackupFlags(AuthenticatorFlags{BS: true})
		if err == nil {
			t.Fatal("expected invalid backup-state error")
		}
	})
	t.Run("authenticator data minimum", func(t *testing.T) {
		_, err := ParseAuthenticatorData(make([]byte, 36))
		if err == nil {
			t.Fatal("expected minimum-length error")
		}
	})
	t.Run("base64 limit", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, MaxSignatureBytes+1))
		_, err := decodeBase64URL(encoded, "signature", MaxSignatureBytes)
		if err == nil {
			t.Fatal("expected size limit error")
		}
	})
	t.Run("duplicate CBOR key", func(t *testing.T) {
		var decoded any
		err := decodeCBORExact([]byte{0xa2, 0x01, 0x02, 0x01, 0x03}, &decoded)
		if err == nil {
			t.Fatal("expected duplicate-key error")
		}
	})
	t.Run("CBOR nesting limit", func(t *testing.T) {
		data := append(bytes.Repeat([]byte{0x81}, maxCBORDepth+1), 0x00)
		var decoded any
		err := decodeCBORExact(data, &decoded)
		if err == nil {
			t.Fatal("expected nesting-limit error")
		}
	})
	t.Run("CBOR integer overflow", func(t *testing.T) {
		if _, err := integer(^uint64(0), "test integer"); err == nil {
			t.Fatal("expected integer overflow error")
		}
	})
	t.Run("sign count", func(t *testing.T) {
		cases := []struct {
			stored, reported uint32
			valid            bool
		}{{0, 0, true}, {0, 1, true}, {1, 2, true}, {1, 1, false}, {2, 1, false}, {1, 0, false}}
		for _, test := range cases {
			err := ValidateSignCount(test.stored, test.reported)
			if (err == nil) != test.valid {
				t.Fatalf("stored=%d reported=%d valid=%v err=%v", test.stored, test.reported, test.valid, err)
			}
		}
	})
}

func upstreamNoneRegistration() RegistrationResponseJSON {
	return RegistrationResponseJSON{
		ID:    "AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY",
		RawID: "AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY",
		Type:  "public-key",
		Response: AttestationResponseJSON{
			AttestationObject: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFPdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHSlyRHIdWleVqO24-6ix7JFWODqDWo_arvEz3Se5EgIFHkcVjZ4F5XDSBreIHsWRilRnKmaaqlqK3V2_4XtYs2pQECAyYgASFYID5PQTZQQg6haZFQWFzqfAOyQ_ENsMH8xxQ4GRiNPsqrIlggU8IVUOV8qpgk_Jh-OTaLuZL52KdX1fTht07X4DiQPow",
			ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYUVWalkxQlhkWHBwVURBd1NEQndOV2Q0YURKZmRUVmZVRU0wVG1WWloyUSIsIm9yaWdpbiI6Imh0dHBzOlwvXC9kZXYuZG9udG5lZWRhLnB3IiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoib3JnLm1vemlsbGEuZmlyZWZveCJ9",
			Transports:        []string{},
		},
	}
}

func upstreamAssertion() AuthenticationResponseJSON {
	return AuthenticationResponseJSON{
		ID:    "KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew",
		RawID: "KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew",
		Type:  "public-key",
		Response: AssertionResponseJSON{
			AuthenticatorData: "PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KABAAAAkA==",
			ClientDataJSON:    "eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sVWFXMWwiLCJjbGllbnRFeHRlbnNpb25zIjp7fSwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=",
			Signature:         "MEUCIQDYXBOpCWSWq2Ll4558GJKD2RoWg958lvJSB_GdeokxogIgWuEVQ7ee6AswQY0OsuQ6y8Ks6jhd45bDx92wjXKs900=",
		},
	}
}
