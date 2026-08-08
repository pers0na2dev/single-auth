package crypto

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

type passwordCase struct {
	Suite       string
	Title       string
	Observation map[string]any
}

var passwordCases = []passwordCase{
	{Suite: "legacy password hashes", Title: "rejects a wrong password", Observation: map[string]any{"passwordLength": float64(16), "valid": false}},
	{Suite: "legacy password hashes", Title: "verifies an existing hash", Observation: map[string]any{"passwordLength": float64(16), "valid": true}},
	{Suite: "legacy password hashes", Title: "verifies a Unicode password", Observation: map[string]any{"passwordLength": float64(15), "valid": true}},
	{Suite: "legacy password hashes", Title: "verifies an empty password", Observation: map[string]any{"passwordLength": float64(0), "valid": true}},
	{Suite: "legacy password hashes", Title: "verifies a very long password", Observation: map[string]any{"passwordLength": float64(10000), "valid": true}},
	{Suite: "password hashing and verification", Title: "is case-sensitive", Observation: map[string]any{"lower": false, "upper": false}},
	{Suite: "password hashing and verification", Title: "generates distinct salted hashes", Observation: map[string]any{"different": true}},
	{Suite: "password hashing and verification", Title: "handles Unicode characters", Observation: map[string]any{"valid": true}},
	{Suite: "password hashing and verification", Title: "handles long passwords", Observation: map[string]any{"passwordLength": float64(1000), "valid": true}},
	{Suite: "password hashing and verification", Title: "creates a password hash", Observation: map[string]any{"truthy": true, "parts": float64(2)}},
	{Suite: "password hashing and verification", Title: "rejects an incorrect password", Observation: map[string]any{"valid": false}},
	{Suite: "password hashing and verification", Title: "verifies a correct password", Observation: map[string]any{"valid": true}},
}

func TestPasswordBehavior(t *testing.T) {
	for _, vector := range passwordCases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			actual := runPasswordConformanceVector(t, vector.Suite, vector.Title)
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("password observation = %#v, want %#v", actual, vector.Observation)
			}
		})
	}
}

func runPasswordConformanceVector(t *testing.T, suite, title string) map[string]any {
	t.Helper()
	if suite == "password hashing and verification" {
		switch title {
		case "creates a password hash":
			hash, err := HashPassword("mySecurePassword123!")
			if err != nil {
				t.Fatal(err)
			}
			return map[string]any{
				"truthy": hash != "",
				"parts":  float64(len(strings.Split(hash, ":"))),
			}
		case "verifies a correct password":
			const password = "correctPassword123!"
			return map[string]any{"valid": VerifyPassword(passwordConformanceHash(t, password, 0), password)}
		case "rejects an incorrect password":
			return map[string]any{
				"valid": VerifyPassword(passwordConformanceHash(t, "correctPassword123!", 0), "wrongPassword456!"),
			}
		case "generates distinct salted hashes":
			first, err := HashPassword("samePassword123!")
			if err != nil {
				t.Fatal(err)
			}
			second, err := HashPassword("samePassword123!")
			if err != nil {
				t.Fatal(err)
			}
			return map[string]any{"different": first != second}
		case "handles long passwords":
			password := strings.Repeat("a", 1000)
			return map[string]any{
				"passwordLength": float64(utf16CodeUnitLength(password)),
				"valid":          VerifyPassword(passwordConformanceHash(t, password, 0), password),
			}
		case "is case-sensitive":
			const password = "CaseSensitivePassword123!"
			hash := passwordConformanceHash(t, password, 0)
			return map[string]any{
				"lower": VerifyPassword(hash, strings.ToLower(password)),
				"upper": VerifyPassword(hash, strings.ToUpper(password)),
			}
		case "handles Unicode characters":
			const password = "пароль123!"
			return map[string]any{"valid": VerifyPassword(passwordConformanceHash(t, password, 0), password)}
		}
	}

	if suite == "legacy password hashes" {
		password := "ExistingUser123!"
		candidate := password
		switch title {
		case "rejects a wrong password":
			candidate = "WrongPassword!"
		case "verifies an existing hash":
		case "verifies a Unicode password":
			password = "비밀번호🔑密码🔒パスワード"
			candidate = password
		case "verifies an empty password":
			password = ""
			candidate = password
		case "verifies a very long password":
			password = strings.Repeat("x", 10000)
			candidate = password
		default:
			t.Fatalf("unknown legacy password test %q", title)
		}
		return map[string]any{
			"passwordLength": float64(utf16CodeUnitLength(password)),
			"valid":          VerifyPassword(passwordConformanceHash(t, password, 0), candidate),
		}
	}

	t.Fatalf("unknown password conformance vector %q / %q", suite, title)
	return nil
}

func passwordConformanceHash(t *testing.T, password string, saltByte byte) string {
	t.Helper()
	hash, err := HashPasswordWithReader(password, bytes.NewReader(bytes.Repeat([]byte{saltByte}, passwordSaltSize)))
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func utf16CodeUnitLength(value string) int {
	return len(utf16.Encode([]rune(value)))
}
