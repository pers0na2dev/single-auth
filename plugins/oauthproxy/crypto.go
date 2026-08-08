package oauthproxy

import (
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

func (p *plugin) encryptProxy(value []byte) (string, error) {
	if p.options.SecretConfig != nil {
		return baCrypto.EncryptWithConfigAndReader(*p.options.SecretConfig, value, p.runtime.Random)
	}
	if p.options.Secret != "" {
		return baCrypto.EncryptWithReader(p.options.Secret, value, p.runtime.Random)
	}
	return p.runtime.EncryptSecret(value)
}

func (p *plugin) decryptProxy(value string) ([]byte, error) {
	if p.options.SecretConfig != nil {
		return baCrypto.DecryptWithConfig(*p.options.SecretConfig, value)
	}
	if p.options.Secret != "" {
		return baCrypto.Decrypt(p.options.Secret, value)
	}
	return p.runtime.DecryptSecret(value)
}
