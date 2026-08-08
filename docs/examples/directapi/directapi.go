// Package directapi contains a compile-checked direct-server API example.
package directapi

import (
	"context"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
)

// CreateSession signs up a user, converts the response's Set-Cookie values to
// a request Cookie header, and resolves the resulting logical session without
// passing through an HTTP transport.
func CreateSession(ctx context.Context, secret string) (*singleauth.Auth, *singleauth.SessionResult, error) {
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "https://auth.example.com",
		Secret:  secret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	created, err := auth.API().SignUpEmail(ctx, singleauth.SignUpEmailInput{
		Name:     "Application Owner",
		Email:    "owner@example.com",
		Password: "correct-horse-battery-staple",
	})
	if err != nil {
		return nil, nil, err
	}
	cookieHeader := cookies.ApplySetCookies("", created.Headers.Values("Set-Cookie"))
	headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader})
	session, err := auth.API().GetSession(ctx, singleauth.GetSessionInput{Headers: headers})
	if err != nil {
		return nil, nil, err
	}
	return auth, session, nil
}
