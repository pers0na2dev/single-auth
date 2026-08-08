package core

import (
	"errors"
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/core/model"
)

// DBFieldsDecoder converts a model's lossless dynamic field map into the
// caller's static Go representation. upstream implementation's TypeScript definitions can
// intersect configured and plugin fields into the base model automatically;
// Go callers provide the corresponding concrete Additional type and decoder.
type DBFieldsDecoder[Additional any] func(model.Fields) (Additional, error)

// DecodeDBField reads an optional database field without collapsing the three
// states represented by upstream implementation output types: absent (undefined), explicit
// null, and present. A present value with the wrong Go type is rejected.
func DecodeDBField[Value any](fields model.Fields, name string) (model.Value[Value], error) {
	dynamic := fields.Lookup(name)
	if !dynamic.IsSet() {
		return model.Absent[Value](), nil
	}
	if dynamic.IsNull() {
		return model.Null[Value](), nil
	}
	value, present := dynamic.Get()
	if !present {
		return model.Absent[Value](), nil
	}
	typed, ok := value.(Value)
	if !ok {
		return model.Value[Value]{}, fmt.Errorf(
			"single-auth: database field %q has type %T", name, value,
		)
	}
	return model.Present(typed), nil
}

// RequireDBField reads a required configured or plugin database field. Missing,
// null, and wrong-typed values are errors rather than implicit zero values.
func RequireDBField[Value any](fields model.Fields, name string) (Value, error) {
	var zero Value
	value, err := DecodeDBField[Value](fields, name)
	if err != nil {
		return zero, err
	}
	if !value.IsSet() {
		return zero, fmt.Errorf("single-auth: required database field %q is absent", name)
	}
	if value.IsNull() {
		return zero, fmt.Errorf("single-auth: required database field %q is null", name)
	}
	result, present := value.Get()
	if !present {
		return zero, fmt.Errorf("single-auth: required database field %q has no value", name)
	}
	return result, nil
}

// TypedSession is the statically typed form of model.Session. Additional can
// contain fields contributed by both session.additionalFields and plugins.
type TypedSession[Additional any] struct {
	ID         string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	UserID     string
	ExpiresAt  time.Time
	Token      string
	IPAddress  model.Value[string]
	UserAgent  model.Value[string]
	Additional Additional
}

// TypedAccount is the statically typed form of model.Account.
type TypedAccount[Additional any] struct {
	ID                    string
	CreatedAt             time.Time
	UpdatedAt             time.Time
	ProviderID            string
	AccountID             string
	UserID                string
	AccessToken           model.Value[string]
	RefreshToken          model.Value[string]
	IDToken               model.Value[string]
	AccessTokenExpiresAt  model.Value[time.Time]
	RefreshTokenExpiresAt model.Value[time.Time]
	Scope                 model.Value[string]
	Password              model.Value[string]
	Additional            Additional
}

// TypedVerification is the statically typed form of model.Verification.
type TypedVerification[Additional any] struct {
	ID         string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Identifier string
	Value      string
	ExpiresAt  time.Time
	Additional Additional
}

// DecodeSession converts a production model.Session to its static form.
func DecodeSession[Additional any](
	session model.Session,
	decoder DBFieldsDecoder[Additional],
) (TypedSession[Additional], error) {
	if decoder == nil {
		return TypedSession[Additional]{}, errors.New("single-auth: session fields decoder is required")
	}
	additional, err := decoder(session.AdditionalFields)
	if err != nil {
		return TypedSession[Additional]{}, err
	}
	return TypedSession[Additional]{
		ID: session.ID, CreatedAt: session.CreatedAt, UpdatedAt: session.UpdatedAt,
		UserID: session.UserID, ExpiresAt: session.ExpiresAt, Token: session.Token,
		IPAddress: session.IPAddress, UserAgent: session.UserAgent,
		Additional: additional,
	}, nil
}

// DecodeAccount converts a production model.Account to its static form.
func DecodeAccount[Additional any](
	account model.Account,
	decoder DBFieldsDecoder[Additional],
) (TypedAccount[Additional], error) {
	if decoder == nil {
		return TypedAccount[Additional]{}, errors.New("single-auth: account fields decoder is required")
	}
	additional, err := decoder(account.AdditionalFields)
	if err != nil {
		return TypedAccount[Additional]{}, err
	}
	return TypedAccount[Additional]{
		ID: account.ID, CreatedAt: account.CreatedAt, UpdatedAt: account.UpdatedAt,
		ProviderID: account.ProviderID, AccountID: account.AccountID, UserID: account.UserID,
		AccessToken: account.AccessToken, RefreshToken: account.RefreshToken,
		IDToken: account.IDToken, AccessTokenExpiresAt: account.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: account.RefreshTokenExpiresAt, Scope: account.Scope,
		Password: account.Password, Additional: additional,
	}, nil
}

// DecodeVerification converts a production model.Verification to its static form.
func DecodeVerification[Additional any](
	verification model.Verification,
	decoder DBFieldsDecoder[Additional],
) (TypedVerification[Additional], error) {
	if decoder == nil {
		return TypedVerification[Additional]{}, errors.New("single-auth: verification fields decoder is required")
	}
	additional, err := decoder(verification.AdditionalFields)
	if err != nil {
		return TypedVerification[Additional]{}, err
	}
	return TypedVerification[Additional]{
		ID: verification.ID, CreatedAt: verification.CreatedAt,
		UpdatedAt: verification.UpdatedAt, Identifier: verification.Identifier,
		Value: verification.Value, ExpiresAt: verification.ExpiresAt,
		Additional: additional,
	}, nil
}
