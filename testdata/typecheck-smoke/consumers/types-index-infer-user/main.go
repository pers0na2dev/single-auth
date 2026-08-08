package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

type inferredUser struct {
	ID                  string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	Email               string
	EmailVerified       bool
	Name                string
	Image               model.Value[string]
	OnboardingCompleted model.Value[bool]
}

func decodeInferredUser(user singleauth.User) (inferredUser, error) {
	onboardingCompleted, err := singleauth.DecodeUserField[bool](
		user.AdditionalFields, "onboardingCompleted",
	)
	if err != nil {
		return inferredUser{}, err
	}
	return inferredUser{
		ID:                  user.ID,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
		Email:               user.Email,
		EmailVerified:       user.EmailVerified,
		Name:                user.Name,
		Image:               user.Image,
		OnboardingCompleted: onboardingCompleted,
	}, nil
}

func verifyUserFieldStates() {
	absent, err := decodeInferredUser(singleauth.User{})
	if err != nil || absent.OnboardingCompleted.IsSet() {
		panic("absent onboardingCompleted did not remain absent")
	}

	nullValue, err := decodeInferredUser(singleauth.User{
		AdditionalFields: model.Fields{
			"onboardingCompleted": model.Null[any](),
		},
	})
	if err != nil || !nullValue.OnboardingCompleted.IsNull() {
		panic("null onboardingCompleted did not remain null")
	}

	present, err := decodeInferredUser(singleauth.User{
		AdditionalFields: model.Fields{
			"onboardingCompleted": model.Present[any](false),
		},
	})
	value, ok := present.OnboardingCompleted.Get()
	if err != nil || !ok || value {
		panic("present false onboardingCompleted was not preserved")
	}

	_, err = decodeInferredUser(singleauth.User{
		AdditionalFields: model.Fields{
			"onboardingCompleted": model.Present[any]("false"),
		},
	})
	if err == nil || !strings.Contains(err.Error(), `user field "onboardingCompleted" has type string`) {
		panic("wrong-type onboardingCompleted was not rejected")
	}
}

func main() {
	auth, err := singleauth.New(singleauth.Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"onboardingCompleted": {
					Type:         storage.FieldBoolean,
					Required:     storage.Bool(false),
					Input:        storage.Bool(false),
					Returned:     storage.Bool(true),
					DefaultValue: storage.StaticValue(false),
				},
			}},
		}},
	})
	if err != nil {
		panic(err)
	}
	typedAuth, err := singleauth.NewTypedAuth(auth, decodeInferredUser)
	if err != nil {
		panic(err)
	}
	api := typedAuth.API()

	// Method-value assignments force both production endpoint wrappers to
	// expose exactly the same inferred user type at compile time.
	var signUpEmail func(context.Context, singleauth.SignUpEmailInput) (singleauth.TypedSignUpEmailResult[inferredUser], error) = api.SignUpEmail
	var signInEmail func(context.Context, singleauth.SignInEmailInput) (singleauth.TypedSignInEmailResult[inferredUser], error) = api.SignInEmail
	_ = signUpEmail
	_ = signInEmail

	ctx := context.Background()
	signUp, err := api.SignUpEmail(ctx, singleauth.SignUpEmailInput{
		Name: "Typed Consumer", Email: "typed-consumer@example.com", Password: "password123",
	})
	if err != nil {
		panic(err)
	}
	var signUpUser inferredUser = signUp.User
	signUpOnboarding, signUpPresent := signUpUser.OnboardingCompleted.Get()
	if !signUpPresent || signUpOnboarding {
		panic("production sign-up did not return the configured false default")
	}

	signIn, err := api.SignInEmail(ctx, singleauth.SignInEmailInput{
		Email: "typed-consumer@example.com", Password: "password123",
	})
	if err != nil {
		panic(err)
	}
	var signInUser inferredUser = signIn.User
	if signInUser.ID != signUpUser.ID {
		panic("production sign-in returned a different typed user")
	}
	cookieHeader := cookies.ApplySetCookies("", signIn.Headers.Values("Set-Cookie"))
	session, err := api.GetSession(ctx, singleauth.GetSessionInput{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
	})
	if err != nil || session == nil {
		panic("production typed get-session failed")
	}
	var sessionUser inferredUser = session.User
	if sessionUser.ID != signUpUser.ID {
		panic("production get-session returned a different typed user")
	}
	for _, user := range []inferredUser{signUpUser, signInUser, sessionUser} {
		value, present := user.OnboardingCompleted.Get()
		if !present || value {
			panic("typed production chain lost onboardingCompleted=false")
		}
	}

	verifyUserFieldStates()

	var exactUser inferredUser = sessionUser
	var id string = exactUser.ID
	var createdAt time.Time = exactUser.CreatedAt
	var updatedAt time.Time = exactUser.UpdatedAt
	var email string = exactUser.Email
	var emailVerified bool = exactUser.EmailVerified
	var name string = exactUser.Name
	var image model.Value[string] = exactUser.Image
	var optionalBoolean model.Value[bool] = exactUser.OnboardingCompleted
	_, _, _, _, _, _, _ = id, createdAt, updatedAt, email, emailVerified, name, image
	if value, present := optionalBoolean.Get(); !present || value {
		panic("typed session user lost its present false field")
	}
	fmt.Print("ok:types-index-infer-user")
}
