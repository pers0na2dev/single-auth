package model

import "time"

// Core contains the columns shared by the reference implementation's user, session, account,
// and verification models.
type Core struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// User is the reference implementation's base user model. AdditionalFields holds configured or
// plugin-contributed fields without losing absent/null/value semantics.
type User struct {
	Core
	Name             string        `json:"name"`
	Email            string        `json:"email"`
	EmailVerified    bool          `json:"emailVerified"`
	Image            Value[string] `json:"image,omitzero"`
	AdditionalFields Fields        `json:"-"`
}

// Record converts a user to the canonical dynamic storage representation.
func (u User) Record() Record {
	record := u.Core.record()
	record["name"] = u.Name
	record["email"] = u.Email
	record["emailVerified"] = u.EmailVerified
	applyValue(record, "image", u.Image)
	u.AdditionalFields.Apply(record)
	return record
}

// Session is the reference implementation's base session model.
type Session struct {
	Core
	UserID           string        `json:"userId"`
	ExpiresAt        time.Time     `json:"expiresAt"`
	Token            string        `json:"token"`
	IPAddress        Value[string] `json:"ipAddress,omitzero"`
	UserAgent        Value[string] `json:"userAgent,omitzero"`
	AdditionalFields Fields        `json:"-"`
}

// Record converts a session to the canonical dynamic storage representation.
func (s Session) Record() Record {
	record := s.Core.record()
	record["userId"] = s.UserID
	record["expiresAt"] = s.ExpiresAt
	record["token"] = s.Token
	applyValue(record, "ipAddress", s.IPAddress)
	applyValue(record, "userAgent", s.UserAgent)
	s.AdditionalFields.Apply(record)
	return record
}

// Account is the reference implementation's base account model.
type Account struct {
	Core
	ProviderID            string           `json:"providerId"`
	AccountID             string           `json:"accountId"`
	UserID                string           `json:"userId"`
	AccessToken           Value[string]    `json:"accessToken,omitzero"`
	RefreshToken          Value[string]    `json:"refreshToken,omitzero"`
	IDToken               Value[string]    `json:"idToken,omitzero"`
	AccessTokenExpiresAt  Value[time.Time] `json:"accessTokenExpiresAt,omitzero"`
	RefreshTokenExpiresAt Value[time.Time] `json:"refreshTokenExpiresAt,omitzero"`
	Scope                 Value[string]    `json:"scope,omitzero"`
	Password              Value[string]    `json:"password,omitzero"`
	AdditionalFields      Fields           `json:"-"`
}

// Record converts an account to the canonical dynamic storage representation.
func (a Account) Record() Record {
	record := a.Core.record()
	record["providerId"] = a.ProviderID
	record["accountId"] = a.AccountID
	record["userId"] = a.UserID
	applyValue(record, "accessToken", a.AccessToken)
	applyValue(record, "refreshToken", a.RefreshToken)
	applyValue(record, "idToken", a.IDToken)
	applyValue(record, "accessTokenExpiresAt", a.AccessTokenExpiresAt)
	applyValue(record, "refreshTokenExpiresAt", a.RefreshTokenExpiresAt)
	applyValue(record, "scope", a.Scope)
	applyValue(record, "password", a.Password)
	a.AdditionalFields.Apply(record)
	return record
}

// Verification is the reference implementation's single-use verification model.
type Verification struct {
	Core
	Identifier       string    `json:"identifier"`
	Value            string    `json:"value"`
	ExpiresAt        time.Time `json:"expiresAt"`
	AdditionalFields Fields    `json:"-"`
}

// Record converts a verification to the canonical dynamic storage representation.
func (v Verification) Record() Record {
	record := v.Core.record()
	record["identifier"] = v.Identifier
	record["value"] = v.Value
	record["expiresAt"] = v.ExpiresAt
	v.AdditionalFields.Apply(record)
	return record
}

// RateLimit is the reference implementation's optional database-backed rate-limit model.
type RateLimit struct {
	Key              string `json:"key"`
	Count            int64  `json:"count"`
	LastRequest      int64  `json:"lastRequest"`
	AdditionalFields Fields `json:"-"`
}

// Record converts a rate-limit value to the canonical dynamic storage representation.
func (r RateLimit) Record() Record {
	record := Record{
		"key":         r.Key,
		"count":       r.Count,
		"lastRequest": r.LastRequest,
	}
	r.AdditionalFields.Apply(record)
	return record
}

func (c Core) record() Record {
	return Record{
		"id":        c.ID,
		"createdAt": c.CreatedAt,
		"updatedAt": c.UpdatedAt,
	}
}

func applyValue[T any](record Record, name string, value Value[T]) {
	if dynamic, ok := value.Interface(); ok {
		record[name] = dynamic
	}
}
