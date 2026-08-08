package core

// EncodeOAuthToken applies the configured account token-storage policy.
// A nil token remains nil, matching upstream implementation's null/undefined behavior,
// while an empty string remains an empty string.
func (a *Auth) EncodeOAuthToken(token *string) (*string, error) {
	if token == nil {
		return nil, nil
	}
	encoded, err := a.storeOAuthToken(*token)
	if err != nil {
		return nil, err
	}
	return &encoded, nil
}

// DecodeOAuthToken returns an OAuth token in plaintext. When encryption is
// enabled, legacy plaintext tokens are deliberately returned unchanged so an
// installation can enable encryption without invalidating existing accounts.
func (a *Auth) DecodeOAuthToken(token string) (string, error) {
	return a.loadOAuthToken(token)
}
