package crypto_test

type secretRotationCase struct {
	Suite    string
	Title    string
	Mode     string
	Expected any
}

var secretRotationCases = []secretRotationCase{
	{Suite: "secret rotation > JWE multi-secret", Title: "decode kid-less JWT tries all secrets (fallback)", Mode: "jwe-fallback", Expected: map[string]any{"decodedFoo": "bar"}},
	{Suite: "secret rotation > JWE multi-secret", Title: "decode legacy string-encoded JWT with SecretConfig legacySecret", Mode: "jwe-legacy", Expected: map[string]any{"decodedFoo": "bar"}},
	{Suite: "secret rotation > JWE multi-secret", Title: "decode with rotated config containing old key", Mode: "jwe-rotated", Expected: map[string]any{"decodedFoo": "bar"}},
	{Suite: "secret rotation > JWE multi-secret", Title: "encode and decode with single secret string", Mode: "jwe-single", Expected: map[string]any{"decodedFoo": "bar"}},
	{Suite: "secret rotation > JWE multi-secret", Title: "encode with SecretConfig, decode with same config", Mode: "jwe-config", Expected: map[string]any{"decodedFoo": "bar"}},
	{Suite: "secret rotation > JWE multi-secret", Title: "rejects token with mismatched kid (no fallback)", Mode: "jwe-mismatched-kid", Expected: map[string]any{"decoded": false}},
	{Suite: "secret rotation > context secret helpers > buildSecretConfig", Title: "builds config with keys map", Mode: "build-map", Expected: map[string]any{"currentVersion": 2, "key1": "secret-a-at-least-32-chars-long!!", "key2": "secret-b-at-least-32-chars-long!!", "legacySecretDefined": false}},
	{Suite: "secret rotation > context secret helpers > buildSecretConfig", Title: "excludes DEFAULT_SECRET as legacySecret", Mode: "build-default", Expected: map[string]any{"legacySecretDefined": false}},
	{Suite: "secret rotation > context secret helpers > buildSecretConfig", Title: "includes legacySecret when provided", Mode: "build-legacy", Expected: map[string]any{"legacySecret": "legacy-secret-at-least-32-chars!!"}},
	{Suite: "secret rotation > context secret helpers > buildSecretConfig", Title: "normalizes string versions to numbers in output", Mode: "build-string", Expected: map[string]any{"currentVersion": 2, "currentVersionType": "number", "key1": "secret-a-at-least-32-chars-long!!", "key2": "secret-b-at-least-32-chars-long!!"}},
	{Suite: "secret rotation > context secret helpers > parseSecretsEnv", Title: "rejects empty value", Mode: "parse-empty-value", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > parseSecretsEnv", Title: "rejects entry without colon", Mode: "parse-no-colon", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > parseSecretsEnv", Title: "rejects negative version", Mode: "parse-negative", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > parseSecretsEnv", Title: "rejects non-integer version", Mode: "parse-non-integer", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > parseSecretsEnv", Title: "returns null for undefined/empty", Mode: "parse-empty", Expected: map[string]any{"undefinedResult": nil, "emptyResult": nil}},
	{Suite: "secret rotation > context secret helpers > parseSecretsEnv", Title: "trims whitespace around entries and values", Mode: "parse-trim", Expected: map[string]any{"entries": []any{map[string]any{"version": 1, "value": "foo"}, map[string]any{"version": 2, "value": "bar"}}}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "accepts string versions that are valid integers", Mode: "validate-string", Expected: map[string]any{"accepted": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "accepts valid config", Mode: "validate-valid", Expected: map[string]any{"accepted": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "detects duplicates after coercion", Mode: "validate-coerced-duplicate", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "rejects hex string versions", Mode: "validate-hex", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "rejects scientific notation versions", Mode: "validate-scientific", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "throws on duplicate versions", Mode: "validate-duplicate", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "throws on empty array", Mode: "validate-empty", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "throws on empty value", Mode: "validate-empty-value", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > context secret helpers > validateSecretsArray", Title: "throws on negative version", Mode: "validate-negative", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > envelope format", Title: "formatEnvelope produces correct format", Mode: "envelope-format", Expected: map[string]any{"formatted": "$ba$3$deadbeef"}},
	{Suite: "secret rotation > envelope format", Title: "parseEnvelope parses valid envelope", Mode: "envelope-valid", Expected: map[string]any{"parsed": map[string]any{"version": 2, "ciphertext": "abcdef1234567890"}}},
	{Suite: "secret rotation > envelope format", Title: "parseEnvelope rejects negative version", Mode: "envelope-negative", Expected: map[string]any{"parsed": nil}},
	{Suite: "secret rotation > envelope format", Title: "parseEnvelope rejects non-integer version", Mode: "envelope-non-integer", Expected: map[string]any{"parsed": nil}},
	{Suite: "secret rotation > envelope format", Title: "parseEnvelope returns null for bare hex", Mode: "envelope-bare", Expected: map[string]any{"parsed": nil}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "SecretConfig with one key - produces envelope", Mode: "symmetric-config-one", Expected: map[string]any{"envelopeVersion": 1, "decrypted": "hello world"}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "decrypt old key - data encrypted with v1, config now on v2", Mode: "symmetric-old-key", Expected: map[string]any{"decrypted": "old data"}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "legacy bare hex + SecretConfig with legacySecret", Mode: "symmetric-legacy", Expected: map[string]any{"decrypted": "legacy data"}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "legacy bare hex without legacySecret - throws", Mode: "symmetric-legacy-missing", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "rotation - encrypt with version 2, decrypt with both keys", Mode: "symmetric-rotation", Expected: map[string]any{"envelopeVersion": 2, "decrypted": "rotated data"}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "single secret string - bare hex, no envelope", Mode: "symmetric-single", Expected: map[string]any{"encryptedContainsEnvelope": false, "decrypted": "hello world"}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "unknown version in envelope - throws", Mode: "symmetric-unknown-version", Expected: map[string]any{"threw": true, "messageIncludes": true}},
	{Suite: "secret rotation > symmetricEncrypt / symmetricDecrypt", Title: "version gaps work fine", Mode: "symmetric-version-gap", Expected: map[string]any{"envelopeVersion": 3, "decrypted": "gapped"}},
}
