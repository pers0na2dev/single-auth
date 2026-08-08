package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
)

// CreateJWK generates and persists one signing key using single-auth's
// private-key encryption representation.
func CreateJWK(ctx *engine.Context, options Options) (JWK, error) {
	compiled, err := normalize(options, false)
	if err != nil {
		return JWK{}, err
	}
	return compiled.createJWK(ctx)
}

func (plugin *compiledPlugin) createJWK(ctx *engine.Context) (JWK, error) {
	pair, err := generateExportedKeyPair(plugin.options, plugin.random)
	if err != nil {
		return JWK{}, err
	}
	publicKey, err := marshalJWK(pair.PublicKey)
	if err != nil {
		return JWK{}, err
	}
	privateJSON, err := marshalJWK(pair.PrivateKey)
	if err != nil {
		return JWK{}, err
	}
	privateKey := privateJSON
	if !plugin.options.JWKS.DisablePrivateKeyEncryption {
		ciphertext, err := plugin.encryptPrivateKey(ctx, []byte(privateJSON))
		if err != nil {
			return JWK{}, err
		}
		encoded, err := json.Marshal(ciphertext)
		if err != nil {
			return JWK{}, err
		}
		privateKey = string(encoded)
	}
	now := plugin.clock().UTC()
	key := JWK{
		PublicKey: publicKey, PrivateKey: privateKey, CreatedAt: now,
		Algorithm: pair.Algorithm,
	}
	if plugin.options.JWKS.KeyPair == nil {
		key.Curve = pair.Curve
	} else if plugin.options.JWKS.KeyPair.Curve != "" {
		key.Curve = plugin.options.JWKS.KeyPair.Curve
	}
	if interval := plugin.options.JWKS.RotationInterval; interval != nil && *interval != 0 {
		expiresAt := now.Add(*interval)
		key.ExpiresAt = &expiresAt
	}
	return plugin.adapter.create(ctx, key)
}

func (plugin *compiledPlugin) encryptPrivateKey(ctx *engine.Context, value []byte) (string, error) {
	goContext := context.Background()
	if ctx != nil {
		goContext = ctx.GoContext()
	}
	if plugin.options.Runtime.EncryptPrivateKey != nil {
		plugin.secretMu.Lock()
		defer plugin.secretMu.Unlock()
		return plugin.options.Runtime.EncryptPrivateKey(goContext, value)
	}
	return baCrypto.EncryptWithReader(plugin.options.Runtime.Secret, value, plugin.random)
}

func (plugin *compiledPlugin) decryptPrivateKey(ctx *engine.Context, value string) ([]byte, error) {
	var ciphertext string
	if err := json.Unmarshal([]byte(value), &ciphertext); err != nil {
		return nil, fmt.Errorf(privateKeyDecryptMessage)
	}
	goContext := context.Background()
	if ctx != nil {
		goContext = ctx.GoContext()
	}
	var (
		plaintext []byte
		err       error
	)
	if plugin.options.Runtime.DecryptPrivateKey != nil {
		plaintext, err = plugin.options.Runtime.DecryptPrivateKey(goContext, ciphertext)
	} else {
		plaintext, err = baCrypto.Decrypt(plugin.options.Runtime.Secret, ciphertext)
	}
	if err != nil {
		return nil, fmt.Errorf(privateKeyDecryptMessage)
	}
	return plaintext, nil
}

func (plugin *compiledPlugin) signingKey(ctx *engine.Context) (JWK, error) {
	key, err := plugin.adapter.getLatest(ctx)
	if err != nil {
		return JWK{}, err
	}
	now := plugin.clock()
	if key == nil || (key.ExpiresAt != nil && key.ExpiresAt.Before(now)) {
		return plugin.createJWK(ctx)
	}
	return *key, nil
}

func gracePeriod(options Options) time.Duration {
	if options.JWKS.GracePeriod != nil {
		return *options.JWKS.GracePeriod
	}
	return 30 * 24 * time.Hour
}
