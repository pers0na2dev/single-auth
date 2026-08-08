package oidcprovider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) findClient(ctx *engine.Context, clientID string) (*Client, error) {
	for _, trusted := range p.options.TrustedClients {
		if trusted.ClientID == clientID {
			client := cloneClient(trusted)
			return &client, nil
		}
	}
	record, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthApplication", Where: []storage.Where{{Field: "clientId", Value: clientID}},
	})
	if err != nil {
		return nil, internalError(err)
	}
	if record == nil {
		return nil, nil
	}
	client, err := clientFromRecord(record)
	if err != nil {
		return nil, internalError(err)
	}
	return &client, nil
}

func defaultClientSecretHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (p *plugin) storeClientSecret(ctx context.Context, value string) (string, error) {
	switch p.options.StoreClientSecret {
	case ClientSecretPlain:
		return value, nil
	case ClientSecretHashed:
		return defaultClientSecretHash(value), nil
	case ClientSecretEncrypted:
		if p.options.Runtime.EncryptSecret == nil {
			return "", errors.New("oidcprovider: EncryptSecret is not configured")
		}
		return p.options.Runtime.EncryptSecret([]byte(value))
	case ClientSecretCustomHash:
		return p.options.HashClientSecret(ctx, value)
	case ClientSecretCustomEncryption:
		return p.options.EncryptClientSecret(ctx, value)
	default:
		return "", errors.New("oidcprovider: invalid client-secret storage mode")
	}
}

func (p *plugin) verifyClientSecret(ctx context.Context, stored, provided string) (bool, error) {
	switch p.options.StoreClientSecret {
	case ClientSecretPlain:
		return constantTimeEqual(stored, provided), nil
	case ClientSecretHashed:
		return constantTimeEqual(stored, defaultClientSecretHash(provided)), nil
	case ClientSecretEncrypted:
		if p.options.Runtime.DecryptSecret == nil {
			return false, errors.New("oidcprovider: DecryptSecret is not configured")
		}
		decrypted, err := p.options.Runtime.DecryptSecret(stored)
		if err != nil {
			return false, err
		}
		return constantTimeEqual(string(decrypted), provided), nil
	case ClientSecretCustomHash:
		hashed, err := p.options.HashClientSecret(ctx, provided)
		if err != nil {
			return false, err
		}
		return constantTimeEqual(stored, hashed), nil
	case ClientSecretCustomEncryption:
		decrypted, err := p.options.DecryptClientSecret(ctx, stored)
		if err != nil {
			return false, err
		}
		return constantTimeEqual(decrypted, provided), nil
	default:
		return false, errors.New("oidcprovider: invalid client-secret storage mode")
	}
}
