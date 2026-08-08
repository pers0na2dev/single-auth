package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/model"
)

// TypedUser is the statically typed form of model.User. TypeScript can intersect
// configured additional fields directly into an object type; Go represents
// the same composition through Additional while retaining the exact base user
// field types.
type TypedUser[Additional any] struct {
	ID            string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Email         string
	EmailVerified bool
	Name          string
	Image         model.Value[string]
	Additional    Additional
}

// UserFieldsDecoder converts the lossless dynamic additional-field map into a
// caller-defined Go type. model.Value fields preserve absent, null, and present
// values, matching upstream implementation's optional nullable inferred output fields.
type UserFieldsDecoder[Additional any] func(model.Fields) (Additional, error)

// UserDecoder converts the production model.User into a caller-defined static
// output type. This is the Go analogue of upstream implementation inferring a complete user
// result from its configuration type.
type UserDecoder[Output any] func(model.User) (Output, error)

// DecodeUserField reads one configured user field without collapsing absent,
// null, and present values. A present value of the wrong Go type is rejected
// instead of being silently replaced by its zero value.
func DecodeUserField[Value any](fields model.Fields, name string) (model.Value[Value], error) {
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
			"single-auth: user field %q has type %T", name, value,
		)
	}
	return model.Present(typed), nil
}

// TypedAuth binds a concrete user output type to an Auth runtime. The embedded
// runtime retains the normal HTTP and dispatcher surface, while API returns
// that same output type from every user-bearing endpoint.
type TypedAuth[Output any] struct {
	*Auth
	decodeUser UserDecoder[Output]
}

// NewTypedAuth adds a compile-time user result type to an existing Auth.
func NewTypedAuth[Output any](
	auth *Auth,
	decoder UserDecoder[Output],
) (*TypedAuth[Output], error) {
	if auth == nil {
		return nil, errors.New("single-auth: typed auth requires an initialized Auth")
	}
	if decoder == nil {
		return nil, errors.New("single-auth: typed auth requires a user decoder")
	}
	return &TypedAuth[Output]{Auth: auth, decodeUser: decoder}, nil
}

// NewTypedUserAuth is a convenience binding for TypedUser plus an additional-
// fields decoder. NewTypedAuth can instead bind a completely flat caller type.
func NewTypedUserAuth[Additional any](
	auth *Auth,
	decoder UserFieldsDecoder[Additional],
) (*TypedAuth[TypedUser[Additional]], error) {
	if decoder == nil {
		return nil, errors.New("single-auth: typed auth requires a user fields decoder")
	}
	return NewTypedAuth(auth, func(user model.User) (TypedUser[Additional], error) {
		return DecodeUser(user, decoder)
	})
}

// API returns a typed façade over the production direct API. Calls still pass
// through Auth.Invoke and the same endpoint, middleware, and hook pipeline.
func (auth *TypedAuth[Output]) API() TypedDirectAPI[Output] {
	if auth == nil || auth.Auth == nil {
		return TypedDirectAPI[Output]{}
	}
	return TypedDirectAPI[Output]{
		direct:     auth.Auth.API(),
		decodeUser: auth.decodeUser,
	}
}

// TypedDirectAPI is the generic user-result counterpart of DirectAPI.
type TypedDirectAPI[Output any] struct {
	direct     DirectAPI
	decodeUser UserDecoder[Output]
}

// TypedSignUpEmailResult preserves the SignUpEmail result while exposing the
// configured static user type.
type TypedSignUpEmailResult[Output any] struct {
	Token   *string
	User    Output
	Headers contract.Headers
}

// TypedSignInEmailResult preserves the SignInEmail result while exposing the
// configured static user type.
type TypedSignInEmailResult[Output any] struct {
	Redirect bool
	Token    string
	URL      model.Value[string]
	User     Output
	Headers  contract.Headers
}

// TypedSessionResult is the statically typed user counterpart of SessionResult.
type TypedSessionResult[Output any] struct {
	Session model.Session
	User    Output
	Headers contract.Headers
}

// Call exposes the production direct-API escape hatch unchanged.
func (api TypedDirectAPI[Output]) Call(
	ctx context.Context,
	name string,
	input DirectCallInput,
) (DirectCallResult, error) {
	return api.direct.Call(ctx, name, input)
}

// SignUpEmail executes the production sign-up endpoint and decodes its user
// into the configured static output type.
func (api TypedDirectAPI[Output]) SignUpEmail(
	ctx context.Context,
	input SignUpEmailInput,
) (TypedSignUpEmailResult[Output], error) {
	result, err := api.direct.SignUpEmail(ctx, input)
	if err != nil {
		return TypedSignUpEmailResult[Output]{}, err
	}
	if api.decodeUser == nil {
		return TypedSignUpEmailResult[Output]{}, errors.New("single-auth: user decoder is required")
	}
	user, err := api.decodeUser(result.User)
	if err != nil {
		return TypedSignUpEmailResult[Output]{}, err
	}
	return TypedSignUpEmailResult[Output]{
		Token: result.Token, User: user, Headers: result.Headers,
	}, nil
}

// SignInEmail executes the production sign-in endpoint and returns the same
// configured User type as SignUpEmail.
func (api TypedDirectAPI[Output]) SignInEmail(
	ctx context.Context,
	input SignInEmailInput,
) (TypedSignInEmailResult[Output], error) {
	result, err := api.direct.SignInEmail(ctx, input)
	if err != nil {
		return TypedSignInEmailResult[Output]{}, err
	}
	if api.decodeUser == nil {
		return TypedSignInEmailResult[Output]{}, errors.New("single-auth: user decoder is required")
	}
	user, err := api.decodeUser(result.User)
	if err != nil {
		return TypedSignInEmailResult[Output]{}, err
	}
	return TypedSignInEmailResult[Output]{
		Redirect: result.Redirect,
		Token:    result.Token,
		URL:      result.URL,
		User:     user,
		Headers:  result.Headers,
	}, nil
}

// GetSession executes the production session endpoint and applies the same
// configured user decoder used by sign-up and sign-in.
func (api TypedDirectAPI[Output]) GetSession(
	ctx context.Context,
	input GetSessionInput,
) (*TypedSessionResult[Output], error) {
	result, err := api.direct.GetSession(ctx, input)
	if err != nil || result == nil {
		return nil, err
	}
	if api.decodeUser == nil {
		return nil, errors.New("single-auth: user decoder is required")
	}
	user, err := api.decodeUser(result.User)
	if err != nil {
		return nil, err
	}
	return &TypedSessionResult[Output]{
		Session: result.Session, User: user, Headers: result.Headers,
	}, nil
}

// SignOut delegates to the production direct API.
func (api TypedDirectAPI[Output]) SignOut(
	ctx context.Context,
	input SignOutInput,
) (SignOutResult, error) {
	return api.direct.SignOut(ctx, input)
}

// DecodeUser converts a model.User into its statically typed public form.
func DecodeUser[Additional any](
	user model.User,
	decoder UserFieldsDecoder[Additional],
) (TypedUser[Additional], error) {
	if decoder == nil {
		return TypedUser[Additional]{}, errors.New("single-auth: user fields decoder is required")
	}
	additional, err := decoder(user.AdditionalFields)
	if err != nil {
		return TypedUser[Additional]{}, err
	}
	return TypedUser[Additional]{
		ID:            user.ID,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		Image:         user.Image,
		Additional:    additional,
	}, nil
}

var _ http.Handler = (*TypedAuth[struct{}])(nil)
