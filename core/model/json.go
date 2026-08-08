package model

import (
	"bytes"
	"encoding/json"
)

func (u User) MarshalJSON() ([]byte, error)         { return json.Marshal(u.Record()) }
func (s Session) MarshalJSON() ([]byte, error)      { return json.Marshal(s.Record()) }
func (a Account) MarshalJSON() ([]byte, error)      { return json.Marshal(a.Record()) }
func (v Verification) MarshalJSON() ([]byte, error) { return json.Marshal(v.Record()) }
func (r RateLimit) MarshalJSON() ([]byte, error)    { return json.Marshal(r.Record()) }

func (u *User) UnmarshalJSON(data []byte) error {
	object, err := decodeObject(data)
	if err != nil {
		return err
	}
	if err := decodeCore(object, &u.Core); err != nil {
		return err
	}
	if err := decodeRequired(object, "name", &u.Name); err != nil {
		return err
	}
	if err := decodeRequired(object, "email", &u.Email); err != nil {
		return err
	}
	if err := decodeRequired(object, "emailVerified", &u.EmailVerified); err != nil {
		return err
	}
	if err := decodeOptional(object, "image", &u.Image); err != nil {
		return err
	}
	u.AdditionalFields, err = decodeAdditional(object, "id", "createdAt", "updatedAt", "name", "email", "emailVerified", "image")
	return err
}

func (s *Session) UnmarshalJSON(data []byte) error {
	object, err := decodeObject(data)
	if err != nil {
		return err
	}
	if err := decodeCore(object, &s.Core); err != nil {
		return err
	}
	if err := decodeRequired(object, "userId", &s.UserID); err != nil {
		return err
	}
	if err := decodeRequired(object, "expiresAt", &s.ExpiresAt); err != nil {
		return err
	}
	if err := decodeRequired(object, "token", &s.Token); err != nil {
		return err
	}
	if err := decodeOptional(object, "ipAddress", &s.IPAddress); err != nil {
		return err
	}
	if err := decodeOptional(object, "userAgent", &s.UserAgent); err != nil {
		return err
	}
	s.AdditionalFields, err = decodeAdditional(object, "id", "createdAt", "updatedAt", "userId", "expiresAt", "token", "ipAddress", "userAgent")
	return err
}

func (a *Account) UnmarshalJSON(data []byte) error {
	object, err := decodeObject(data)
	if err != nil {
		return err
	}
	if err := decodeCore(object, &a.Core); err != nil {
		return err
	}
	for name, target := range map[string]*string{
		"providerId": &a.ProviderID,
		"accountId":  &a.AccountID,
		"userId":     &a.UserID,
	} {
		if err := decodeRequired(object, name, target); err != nil {
			return err
		}
	}
	for name, target := range map[string]*Value[string]{
		"accessToken":  &a.AccessToken,
		"refreshToken": &a.RefreshToken,
		"idToken":      &a.IDToken,
		"scope":        &a.Scope,
		"password":     &a.Password,
	} {
		if err := decodeOptional(object, name, target); err != nil {
			return err
		}
	}
	if err := decodeOptional(object, "accessTokenExpiresAt", &a.AccessTokenExpiresAt); err != nil {
		return err
	}
	if err := decodeOptional(object, "refreshTokenExpiresAt", &a.RefreshTokenExpiresAt); err != nil {
		return err
	}
	a.AdditionalFields, err = decodeAdditional(object,
		"id", "createdAt", "updatedAt", "providerId", "accountId", "userId",
		"accessToken", "refreshToken", "idToken", "accessTokenExpiresAt",
		"refreshTokenExpiresAt", "scope", "password",
	)
	return err
}

func (v *Verification) UnmarshalJSON(data []byte) error {
	object, err := decodeObject(data)
	if err != nil {
		return err
	}
	if err := decodeCore(object, &v.Core); err != nil {
		return err
	}
	if err := decodeRequired(object, "identifier", &v.Identifier); err != nil {
		return err
	}
	if err := decodeRequired(object, "value", &v.Value); err != nil {
		return err
	}
	if err := decodeRequired(object, "expiresAt", &v.ExpiresAt); err != nil {
		return err
	}
	v.AdditionalFields, err = decodeAdditional(object, "id", "createdAt", "updatedAt", "identifier", "value", "expiresAt")
	return err
}

func (r *RateLimit) UnmarshalJSON(data []byte) error {
	object, err := decodeObject(data)
	if err != nil {
		return err
	}
	if err := decodeRequired(object, "key", &r.Key); err != nil {
		return err
	}
	if err := decodeRequired(object, "count", &r.Count); err != nil {
		return err
	}
	if err := decodeRequired(object, "lastRequest", &r.LastRequest); err != nil {
		return err
	}
	r.AdditionalFields, err = decodeAdditional(object, "key", "count", "lastRequest")
	return err
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	return object, nil
}

func decodeCore(object map[string]json.RawMessage, core *Core) error {
	if err := decodeRequired(object, "id", &core.ID); err != nil {
		return err
	}
	if err := decodeRequired(object, "createdAt", &core.CreatedAt); err != nil {
		return err
	}
	return decodeRequired(object, "updatedAt", &core.UpdatedAt)
}

func decodeRequired[T any](object map[string]json.RawMessage, name string, target *T) error {
	data, exists := object[name]
	if !exists {
		return nil
	}
	return json.Unmarshal(data, target)
}

func decodeOptional[T any](object map[string]json.RawMessage, name string, target *Value[T]) error {
	data, exists := object[name]
	if !exists {
		*target = Absent[T]()
		return nil
	}
	return target.UnmarshalJSON(data)
}

func decodeAdditional(object map[string]json.RawMessage, coreFields ...string) (Fields, error) {
	known := make(map[string]struct{}, len(coreFields))
	for _, field := range coreFields {
		known[field] = struct{}{}
	}
	additional := make(Fields)
	for name, data := range object {
		if _, exists := known[name]; exists {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			additional[name] = Null[any]()
			continue
		}
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			return nil, err
		}
		additional[name] = Present(value)
	}
	return additional, nil
}
