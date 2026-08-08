package core

import (
	"fmt"
	"math"
	"os"
	"strings"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/observability/logger"
)

func resolveSecretConfiguration(options *Options, log *logger.Logger) (baCrypto.SecretConfig, error) {
	legacySecret := options.Secret
	if legacySecret == "" {
		legacySecret = os.Getenv("SINGLE_AUTH_SECRET")
	}
	if legacySecret == "" {
		legacySecret = os.Getenv("AUTH_SECRET")
	}

	entries := options.Secrets
	if len(entries) == 0 {
		parsed, err := baCrypto.ParseSecretsEnv(os.Getenv("SINGLE_AUTH_SECRETS"))
		if err != nil {
			return baCrypto.SecretConfig{}, err
		}
		entries = parsed
	}
	if len(entries) > 0 {
		if err := warnSecretQuality(entries[0].Value, true, entries[0].Version, log, options.Environment); err != nil {
			return baCrypto.SecretConfig{}, err
		}
		legacyForConfig := legacySecret
		if legacyForConfig == defaultSecret {
			legacyForConfig = ""
		}
		configuration, err := baCrypto.NewSecretConfig(entries, legacyForConfig)
		if err != nil {
			return baCrypto.SecretConfig{}, err
		}
		options.Secret = entries[0].Value
		return configuration, nil
	}

	if legacySecret == "" {
		legacySecret = defaultSecret
	}
	if err := warnSecretQuality(legacySecret, false, 0, log, options.Environment); err != nil {
		return baCrypto.SecretConfig{}, err
	}
	options.Secret = legacySecret
	return baCrypto.SecretConfig{LegacySecret: legacySecret}, nil
}

func warnSecretQuality(value string, versioned bool, version int, log *logger.Logger, environment string) error {
	environment = strings.ToLower(strings.TrimSpace(environment))
	if value == defaultSecret && environment == "production" {
		return fmt.Errorf("You are using the default secret. Please set `SINGLE_AUTH_SECRET` in your environment variables or pass `secret` in your auth config.")
	}
	// upstream implementation skips secret-quality diagnostics under its test runtime. An
	// explicit non-test environment retains production/development behavior.
	if environment == "test" || (environment == "" && strings.HasSuffix(os.Args[0], ".test")) {
		return nil
	}
	if len(value) < 32 && log != nil {
		if versioned {
			log.Warn(fmt.Sprintf("[single-auth] Warning: the current secret (version %d) should be at least 32 characters long for adequate security.", version))
		} else {
			log.Warn("[single-auth] Warning: your SINGLE_AUTH_SECRET should be at least 32 characters long for adequate security. Generate one with `npx auth secret` or `openssl rand -base64 32`.")
		}
	}
	if estimateSecretEntropy(value) < 120 && log != nil {
		if versioned {
			log.Warn("[single-auth] Warning: the current secret appears low-entropy. Use a randomly generated secret for production.")
		} else {
			log.Warn("[single-auth] Warning: your SINGLE_AUTH_SECRET appears low-entropy. Use a randomly generated secret for production.")
		}
	}
	return nil
}

func estimateSecretEntropy(value string) float64 {
	unique := make(map[rune]struct{})
	for _, character := range value {
		unique[character] = struct{}{}
	}
	if len(unique) == 0 {
		return 0
	}
	return float64(len([]rune(value))) * math.Log2(float64(len(unique)))
}
