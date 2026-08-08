package crypto_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

const (
	secretA    = "secret-a-at-least-32-chars-long!!"
	secretB    = "secret-b-at-least-32-chars-long!!"
	secretSalt = "test-salt"
)

func TestSecretRotationBehavior(t *testing.T) {
	for _, vector := range secretRotationCases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			actual := observeGoSecretRotation(t, vector.Mode)
			assertSecretRotationObservation(t, vector.Expected, actual)
		})
	}
}

func observeGoSecretRotation(t *testing.T, mode string) any {
	t.Helper()
	switch mode {
	case "envelope-bare":
		_, parsed := baCrypto.ParseEnvelope("abcdef1234567890")
		return map[string]any{"parsed": nilIfFalse(parsed, nil)}
	case "envelope-valid":
		envelope, parsed := baCrypto.ParseEnvelope("$ba$2$abcdef1234567890")
		if !parsed {
			return map[string]any{"parsed": nil}
		}
		return map[string]any{"parsed": map[string]any{
			"version": envelope.Version, "ciphertext": envelope.Ciphertext,
		}}
	case "envelope-negative":
		_, parsed := baCrypto.ParseEnvelope("$ba$-1$abcdef")
		return map[string]any{"parsed": nilIfFalse(parsed, nil)}
	case "envelope-non-integer":
		_, parsed := baCrypto.ParseEnvelope("$ba$abc$abcdef")
		return map[string]any{"parsed": nilIfFalse(parsed, nil)}
	case "envelope-format":
		return map[string]any{"formatted": baCrypto.FormatEnvelope(3, "deadbeef")}
	case "symmetric-single":
		encrypted := mustEncrypt(t, secretA, "hello world")
		return map[string]any{
			"encryptedContainsEnvelope": strings.Contains(encrypted, "$ba$"),
			"decrypted":                 mustDecrypt(t, secretA, encrypted),
		}
	case "symmetric-config-one":
		key := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 1, Value: secretA}}, "")
		encrypted := mustEncryptConfig(t, key, "hello world")
		return map[string]any{
			"envelopeVersion": envelopeVersion(t, encrypted),
			"decrypted":       mustDecryptConfig(t, key, encrypted),
		}
	case "symmetric-rotation":
		key := mustSecretConfig(t, []baCrypto.SecretEntry{
			{Version: 2, Value: secretB}, {Version: 1, Value: secretA},
		}, "")
		encrypted := mustEncryptConfig(t, key, "rotated data")
		return map[string]any{
			"envelopeVersion": envelopeVersion(t, encrypted),
			"decrypted":       mustDecryptConfig(t, key, encrypted),
		}
	case "symmetric-old-key":
		oldKey := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 1, Value: secretA}}, "")
		encrypted := mustEncryptConfig(t, oldKey, "old data")
		newKey := mustSecretConfig(t, []baCrypto.SecretEntry{
			{Version: 2, Value: secretB}, {Version: 1, Value: secretA},
		}, "")
		return map[string]any{"decrypted": mustDecryptConfig(t, newKey, encrypted)}
	case "symmetric-legacy":
		encrypted := mustEncrypt(t, secretA, "legacy data")
		key := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 2, Value: secretB}}, secretA)
		return map[string]any{"decrypted": mustDecryptConfig(t, key, encrypted)}
	case "symmetric-legacy-missing":
		encrypted := mustEncrypt(t, secretA, "legacy data")
		key := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 2, Value: secretB}}, "")
		_, err := baCrypto.DecryptWithConfig(key, encrypted)
		return errorIncludes(err, "no legacy secret available")
	case "symmetric-unknown-version":
		oldKey := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 1, Value: secretA}}, "")
		encrypted := mustEncryptConfig(t, oldKey, "test")
		retiredKey := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 2, Value: secretB}}, "")
		_, err := baCrypto.DecryptWithConfig(retiredKey, encrypted)
		return errorIncludes(err, "key may have been retired")
	case "symmetric-version-gap":
		key := mustSecretConfig(t, []baCrypto.SecretEntry{
			{Version: 3, Value: secretB}, {Version: 1, Value: secretA},
		}, "")
		encrypted := mustEncryptConfig(t, key, "gapped")
		return map[string]any{
			"envelopeVersion": envelopeVersion(t, encrypted),
			"decrypted":       mustDecryptConfig(t, key, encrypted),
		}
	case "jwe-single":
		token := mustEncodeJWE(t, map[string]any{"foo": "bar"}, secretA)
		claims, err := baCrypto.DecodeJWE(token, secretA, secretSalt)
		return decodedFoo(t, claims, err)
	case "jwe-config":
		key := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 1, Value: secretA}}, "")
		token := mustEncodeJWEConfig(t, map[string]any{"foo": "bar"}, key)
		claims, err := baCrypto.DecodeJWEWithConfig(token, key, secretSalt)
		return decodedFoo(t, claims, err)
	case "jwe-rotated":
		oldKey := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 1, Value: secretA}}, "")
		token := mustEncodeJWEConfig(t, map[string]any{"foo": "bar"}, oldKey)
		newKey := mustSecretConfig(t, []baCrypto.SecretEntry{
			{Version: 2, Value: secretB}, {Version: 1, Value: secretA},
		}, "")
		claims, err := baCrypto.DecodeJWEWithConfig(token, newKey, secretSalt)
		return decodedFoo(t, claims, err)
	case "jwe-fallback":
		token := mustEncodeJWE(t, map[string]any{"foo": "bar"}, secretA)
		key := mustSecretConfig(t, []baCrypto.SecretEntry{
			{Version: 2, Value: secretB}, {Version: 1, Value: secretA},
		}, secretA)
		claims, err := baCrypto.DecodeJWEWithConfig(token, key, secretSalt)
		return decodedFoo(t, claims, err)
	case "jwe-legacy":
		token := mustEncodeJWE(t, map[string]any{"foo": "bar"}, secretA)
		key := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 2, Value: secretB}}, secretA)
		claims, err := baCrypto.DecodeJWEWithConfig(token, key, secretSalt)
		return decodedFoo(t, claims, err)
	case "jwe-mismatched-kid":
		keyA := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 1, Value: secretA}}, "")
		token := mustEncodeJWEConfig(t, map[string]any{"foo": "bar"}, keyA)
		keyB := mustSecretConfig(t, []baCrypto.SecretEntry{{Version: 2, Value: secretB}}, "")
		claims, err := baCrypto.DecodeJWEWithConfig(token, keyB, secretSalt)
		return map[string]any{"decoded": err == nil && claims != nil}
	case "parse-empty":
		undefinedResult, undefinedErr := baCrypto.ParseSecretsEnv("")
		emptyResult, emptyErr := baCrypto.ParseSecretsEnv("")
		if undefinedErr != nil || emptyErr != nil {
			t.Fatalf("parse empty secrets: undefined=%v empty=%v", undefinedErr, emptyErr)
		}
		return map[string]any{
			"undefinedResult": undefinedResult,
			"emptyResult":     emptyResult,
		}
	case "parse-trim":
		entries, err := baCrypto.ParseSecretsEnv("1: foo , 2:bar ")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"entries": entries}
	case "parse-no-colon":
		_, err := baCrypto.ParseSecretsEnv("noseparator")
		return errorIncludes(err, "Expected format")
	case "parse-negative":
		_, err := baCrypto.ParseSecretsEnv("-1:secret")
		return errorIncludes(err, "non-negative integer")
	case "parse-non-integer":
		_, err := baCrypto.ParseSecretsEnv("abc:secret")
		return errorIncludes(err, "non-negative integer")
	case "parse-empty-value":
		_, err := baCrypto.ParseSecretsEnv("1:")
		return errorIncludes(err, "Empty secret value")
	case "validate-empty":
		return errorIncludes(baCrypto.ValidateSecretInputs(nil), "at least one entry")
	case "validate-duplicate":
		return errorIncludes(baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: 1, Value: secretA}, {Version: 1, Value: secretB},
		}), "Duplicate version")
	case "validate-negative":
		return errorIncludes(baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: -1, Value: secretA},
		}), "non-negative integer")
	case "validate-empty-value":
		return errorIncludes(baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: 1, Value: ""},
		}), "Empty secret value")
	case "validate-valid":
		err := baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: 2, Value: secretB}, {Version: 1, Value: secretA},
		})
		return map[string]any{"accepted": err == nil}
	case "validate-string":
		err := baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: "1", Value: secretA}, {Version: "2", Value: secretB},
		})
		return map[string]any{"accepted": err == nil}
	case "validate-hex":
		return errorIncludes(baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: "0x10", Value: secretA},
		}), "non-negative integer")
	case "validate-scientific":
		return errorIncludes(baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: "1e2", Value: secretA},
		}), "non-negative integer")
	case "validate-coerced-duplicate":
		return errorIncludes(baCrypto.ValidateSecretInputs([]baCrypto.SecretInputEntry{
			{Version: "1", Value: secretA}, {Version: 1, Value: secretB},
		}), "Duplicate version")
	case "build-map":
		built := mustBuildSecretConfig(t, []baCrypto.SecretInputEntry{
			{Version: 2, Value: secretB}, {Version: 1, Value: secretA},
		}, "")
		return map[string]any{
			"currentVersion":      built.CurrentVersion,
			"key1":                built.Keys[1],
			"key2":                built.Keys[2],
			"legacySecretDefined": built.LegacySecret != "",
		}
	case "build-legacy":
		built := mustBuildSecretConfig(t, []baCrypto.SecretInputEntry{{Version: 1, Value: secretA}}, "legacy-secret-at-least-32-chars!!")
		return map[string]any{"legacySecret": built.LegacySecret}
	case "build-string":
		built := mustBuildSecretConfig(t, []baCrypto.SecretInputEntry{
			{Version: "2", Value: secretB}, {Version: "1", Value: secretA},
		}, "")
		versionType := "not-number"
		if reflect.TypeOf(built.CurrentVersion).Kind() >= reflect.Int &&
			reflect.TypeOf(built.CurrentVersion).Kind() <= reflect.Int64 {
			versionType = "number"
		}
		return map[string]any{
			"currentVersion":     built.CurrentVersion,
			"currentVersionType": versionType,
			"key1":               built.Keys[1],
			"key2":               built.Keys[2],
		}
	case "build-default":
		built := mustBuildSecretConfig(t, []baCrypto.SecretInputEntry{{Version: 1, Value: secretA}}, baCrypto.DefaultSecret)
		return map[string]any{"legacySecretDefined": built.LegacySecret != ""}
	default:
		t.Fatalf("unknown secret-rotation mode %q", mode)
		return nil
	}
}

func nilIfFalse(condition bool, value any) any {
	if !condition {
		return nil
	}
	return value
}

func errorIncludes(err error, expected string) map[string]any {
	return map[string]any{
		"threw":           err != nil,
		"messageIncludes": err != nil && strings.Contains(err.Error(), expected),
	}
}

func mustSecretConfig(t *testing.T, entries []baCrypto.SecretEntry, legacy string) baCrypto.SecretConfig {
	t.Helper()
	configuration, err := baCrypto.NewSecretConfig(entries, legacy)
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}

func mustBuildSecretConfig(t *testing.T, entries []baCrypto.SecretInputEntry, legacy string) baCrypto.SecretConfig {
	t.Helper()
	configuration, err := baCrypto.BuildSecretConfig(entries, legacy)
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}

func mustEncrypt(t *testing.T, secret, plaintext string) string {
	t.Helper()
	encrypted, err := baCrypto.Encrypt(secret, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func mustEncryptConfig(t *testing.T, key baCrypto.SecretConfig, plaintext string) string {
	t.Helper()
	encrypted, err := baCrypto.EncryptWithConfig(key, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func mustDecrypt(t *testing.T, secret, encrypted string) string {
	t.Helper()
	decrypted, err := baCrypto.Decrypt(secret, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	return string(decrypted)
}

func mustDecryptConfig(t *testing.T, key baCrypto.SecretConfig, encrypted string) string {
	t.Helper()
	decrypted, err := baCrypto.DecryptWithConfig(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	return string(decrypted)
}

func envelopeVersion(t *testing.T, encrypted string) int {
	t.Helper()
	envelope, ok := baCrypto.ParseEnvelope(encrypted)
	if !ok {
		t.Fatal("encrypted value has no versioned envelope")
	}
	return envelope.Version
}

func mustEncodeJWE(t *testing.T, payload map[string]any, secret string) string {
	t.Helper()
	token, err := baCrypto.EncodeJWE(payload, secret, secretSalt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func mustEncodeJWEConfig(t *testing.T, payload map[string]any, key baCrypto.SecretConfig) string {
	t.Helper()
	token, err := baCrypto.EncodeJWEWithConfig(payload, key, secretSalt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func decodedFoo(t *testing.T, claims map[string]any, err error) map[string]any {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"decodedFoo": claims["foo"]}
}

func assertSecretRotationObservation(t *testing.T, expected, actual any) {
	t.Helper()
	got := normalizeSecretRotationValue(reflect.ValueOf(actual))
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("secret-rotation observation=%#v, want %#v", got, expected)
	}
}

func normalizeSecretRotationValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Bool:
		return value.Bool()
	case reflect.String:
		return value.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(value.Uint())
	case reflect.Float32, reflect.Float64:
		return value.Float()
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return nil
		}
		result := make([]any, value.Len())
		for index := range result {
			result[index] = normalizeSecretRotationValue(value.Index(index))
		}
		return result
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		result := make(map[string]any, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			result[fmt.Sprint(iterator.Key().Interface())] = normalizeSecretRotationValue(iterator.Value())
		}
		return result
	case reflect.Struct:
		result := make(map[string]any)
		typeOfValue := value.Type()
		for index := 0; index < value.NumField(); index++ {
			field := typeOfValue.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = strings.ToLower(field.Name[:1]) + field.Name[1:]
			}
			result[name] = normalizeSecretRotationValue(value.Field(index))
		}
		return result
	default:
		return value.Interface()
	}
}

func ExampleBuildSecretConfig() {
	configuration, _ := baCrypto.BuildSecretConfig([]baCrypto.SecretInputEntry{
		{Version: "2", Value: secretB},
		{Version: 1, Value: secretA},
	}, baCrypto.DefaultSecret)
	fmt.Println(configuration.CurrentVersion, configuration.Keys[1], configuration.LegacySecret == "")
	// Output: 2 secret-a-at-least-32-chars-long!! true
}
