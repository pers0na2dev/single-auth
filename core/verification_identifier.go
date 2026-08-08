package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

type verificationIdentifierRule struct {
	strategy VerificationIdentifierStrategy
	hash     VerificationIdentifierHasher
}

func validateVerificationIdentifierStorage(config VerificationIdentifierStorage) error {
	if err := validateVerificationIdentifierRule("default", config.Strategy, config.Hash); err != nil {
		return err
	}
	for index, override := range config.Overrides {
		if err := validateVerificationIdentifierRule(
			fmt.Sprintf("override %d", index), override.Strategy, override.Hash,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateVerificationIdentifierRule(
	label string,
	strategy VerificationIdentifierStrategy,
	hash VerificationIdentifierHasher,
) error {
	if hash != nil && strategy != "" {
		return fmt.Errorf(
			"single-auth: verification store identifier %s cannot set both strategy and hash",
			label,
		)
	}
	switch strategy {
	case "", VerificationIdentifierPlain, VerificationIdentifierHashed:
		return nil
	default:
		return fmt.Errorf(
			"single-auth: verification store identifier %s strategy must be plain or hashed",
			label,
		)
	}
}

func (a *Auth) processVerificationIdentifier(identifier string) (string, bool, error) {
	config := a.options.Verification.StoreIdentifier
	rule := verificationIdentifierRule{strategy: config.Strategy, hash: config.Hash}
	for _, override := range config.Overrides {
		if strings.HasPrefix(identifier, override.Prefix) {
			rule = verificationIdentifierRule{strategy: override.Strategy, hash: override.Hash}
			break
		}
	}

	if rule.hash != nil {
		stored, err := rule.hash(identifier)
		if err != nil {
			return "", true, fmt.Errorf("single-auth: hash verification identifier: %w", err)
		}
		return stored, true, nil
	}
	if rule.strategy != VerificationIdentifierHashed {
		return identifier, false, nil
	}
	digest := sha256.Sum256([]byte(identifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), true, nil
}

func (a *Auth) verificationIdentifiersToTry(identifier string) ([]string, error) {
	stored, nonPlain, err := a.processVerificationIdentifier(identifier)
	if err != nil {
		return nil, err
	}
	if nonPlain && stored != identifier {
		return []string{stored, identifier}, nil
	}
	return []string{stored}, nil
}

func (a *Auth) consumeSecondaryVerifications(
	ctx context.Context,
	identifiers []string,
) (storage.Record, error) {
	for _, identifier := range identifiers {
		consumed, err := a.consumeSecondaryVerification(ctx, identifier)
		if err != nil {
			return nil, err
		}
		if consumed == nil {
			continue
		}
		for _, alternative := range identifiers {
			if alternative == identifier {
				continue
			}
			if err := a.secondary.Delete(ctx, verificationPrefix+alternative); err != nil {
				return nil, err
			}
		}
		return consumed, nil
	}
	return nil, nil
}
