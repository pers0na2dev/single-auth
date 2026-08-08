package oauthprovider

import (
	"errors"
	"reflect"
	"testing"
)

type basicAuthCase struct {
	Title       string
	Input       basicAuthInput
	Observation ClientCredentials
}

type basicAuthInput struct {
	Authorization string
}

func TestBasicAuthorizationRuntime(t *testing.T) {
	for _, vector := range basicAuthCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			actual, err := BasicToClientCredentials(vector.Input.Authorization)
			if err != nil {
				t.Fatal(err)
			}
			if actual == nil || !reflect.DeepEqual(*actual, vector.Observation) {
				t.Fatalf("Basic credentials = %#v, want %#v", actual, vector.Observation)
			}
		})
	}
}

func TestBasicAuthorizationRejectsMalformedData(t *testing.T) {
	for _, value := range []string{"Basic !!!", "Basic bm9jb2xvbg==", "Basic OmFiYw==", "Basic YWJjOg=="} {
		if credentials, err := BasicToClientCredentials(value); credentials != nil || !errors.Is(err, ErrInvalidBasicAuthorization) {
			t.Fatalf("BasicToClientCredentials(%q) = %#v, %v", value, credentials, err)
		}
	}
	if credentials, err := BasicToClientCredentials("Bearer token"); credentials != nil || err != nil {
		t.Fatalf("non-Basic credentials = %#v, %v", credentials, err)
	}
}
