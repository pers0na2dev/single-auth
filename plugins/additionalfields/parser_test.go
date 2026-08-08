package additionalfields

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestJavaScriptTruthinessForInputFalse(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		want  bool
	}{
		{name: "nil", value: nil, want: false},
		{name: "false", value: false, want: false},
		{name: "empty string", value: "", want: false},
		{name: "zero", value: 0, want: false},
		{name: "negative zero", value: math.Copysign(0, -1), want: false},
		{name: "nan", value: math.NaN(), want: false},
		{name: "json nan", value: json.Number("NaN"), want: false},
		{name: "non-zero", value: -1, want: true},
		{name: "text", value: "false", want: true},
		{name: "empty array", value: []any{}, want: true},
		{name: "empty object", value: map[string]any{}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := javascriptTruthy(test.value); got != test.want {
				t.Fatalf("javascriptTruthy(%#v) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestValidatorTransformAndErrorSemantics(t *testing.T) {
	var transformCalls atomic.Int32
	transform := func(value any) (any, error) {
		transformCalls.Add(1)
		return strings.ToUpper(value.(string)), nil
	}
	processor, err := Compile(Options{User: Fields{{
		Name: "handle",
		Attribute: storage.FieldAttribute{
			Type: storage.FieldString, Transform: storage.FieldTransform{Input: transform},
		},
		Validators: FieldValidators{Input: func(value any) (ValidationResult, error) {
			return ValidationResult{Value: strings.TrimSpace(value.(string))}, nil
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := processor.ParseUserInput(storage.Record{"handle": " alice "}, ActionCreate)
	if err != nil || parsed["handle"] != "alice" {
		t.Fatalf("parsed = %#v, err = %v", parsed, err)
	}
	if transformCalls.Load() != 0 {
		t.Fatalf("route parser ran transform after validator: %d", transformCalls.Load())
	}
	attribute := processor.Schema().Models["user"].Fields["handle"]
	transformed, err := attribute.Transform.Input(parsed["handle"])
	if err != nil || transformed != "ALICE" || transformCalls.Load() != 1 {
		t.Fatalf("adapter transform = %#v, calls = %d, err = %v", transformed, transformCalls.Load(), err)
	}

	for _, test := range []struct {
		name      string
		validator Validator
		status    int
		code      string
		message   string
	}{
		{
			name: "first issue",
			validator: func(any) (ValidationResult, error) {
				return ValidationResult{Issues: []Issue{{Message: "too short"}, {Message: "ignored"}}}, nil
			},
			status: 400, code: CodeValidation, message: "too short",
		},
		{
			name: "empty issue list remains an issue result",
			validator: func(any) (ValidationResult, error) {
				return ValidationResult{Issues: []Issue{}}, nil
			},
			status: 400, code: CodeValidation, message: "Validation Error",
		},
		{
			name: "async validator",
			validator: func(any) (ValidationResult, error) {
				return ValidationResult{Async: true}, nil
			},
			status: 500, code: CodeAsyncValidationNotSupported, message: "Async validation is not supported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			compiled, err := Compile(Options{User: Fields{{
				Name: "field", Attribute: storage.FieldAttribute{Type: storage.FieldString},
				Validators: FieldValidators{Input: test.validator},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			_, parseErr := compiled.ParseUserInput(storage.Record{"field": "value"}, ActionCreate)
			apiError, ok := contract.AsAPIError(parseErr)
			if !ok || apiError.Status != test.status || apiError.Code != test.code || apiError.Message != test.message {
				t.Fatalf("error = %#v", parseErr)
			}
		})
	}

	thrown := errors.New("validator threw")
	compiled, err := Compile(Options{User: Fields{{
		Name: "field", Attribute: storage.FieldAttribute{Type: storage.FieldString},
		Validators: FieldValidators{Input: func(any) (ValidationResult, error) {
			return ValidationResult{}, thrown
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiled.ParseUserInput(storage.Record{"field": "value"}, ActionCreate)
	if !errors.Is(err, thrown) {
		t.Fatalf("thrown validator error = %v", err)
	}
}

func TestProviderInputDefaultsAndOutputFiltering(t *testing.T) {
	optional := storage.Bool(false)
	blocked := storage.Bool(false)
	hidden := storage.Bool(false)
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	var defaults atomic.Int32
	processor, err := Compile(Options{
		User: Fields{
			{Name: "nickname", Attribute: storage.FieldAttribute{Type: storage.FieldString, Required: optional}},
			{Name: "authority", Attribute: storage.FieldAttribute{Type: storage.FieldString, Required: optional, Input: blocked}},
			{Name: "secret", Attribute: storage.FieldAttribute{Type: storage.FieldJSON, Required: optional, Returned: hidden}},
		},
		Session: Fields{{
			Name: "nonce", Attribute: storage.FieldAttribute{
				Type: storage.FieldNumber,
				DefaultValue: func(storage.ValueContext) (any, error) {
					return defaults.Add(1), nil
				},
			},
		}},
		Runtime: Runtime{Clock: func() time.Time { return now }},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := processor.ParseProviderUserInput(storage.Record{
		"nickname": "provider", "authority": "admin", "unknown": true,
	}, ActionCreate)
	if err != nil || len(profile) != 1 || profile["nickname"] != "provider" {
		t.Fatalf("provider input = %#v, err = %v", profile, err)
	}

	first, err := processor.SessionDefaults()
	if err != nil {
		t.Fatal(err)
	}
	second, err := processor.SessionDefaults()
	if err != nil || first["nonce"] != int32(1) || second["nonce"] != int32(2) {
		t.Fatalf("session defaults first=%#v second=%#v err=%v", first, second, err)
	}

	nested := map[string]any{"roles": []any{"reader"}}
	filtered, err := processor.FilterOutput(ModelUser, storage.Record{
		"nickname": "visible", "secret": nested,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := filtered["secret"]; exists || filtered["nickname"] != "visible" {
		t.Fatalf("filtered output = %#v", filtered)
	}

	visibleProcessor, err := Compile(Options{User: Fields{{
		Name: "metadata", Attribute: storage.FieldAttribute{Type: storage.FieldJSON, Required: optional},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := visibleProcessor.FilterOutput(ModelUser, storage.Record{"metadata": nested})
	if err != nil {
		t.Fatal(err)
	}
	clonedNested := cloned["metadata"].(map[string]any)
	clonedNested["roles"].([]any)[0] = "writer"
	if nested["roles"].([]any)[0] != "reader" {
		t.Fatal("FilterOutput did not structured-clone nested data")
	}
}

func TestSyntheticUserAndOutputValidator(t *testing.T) {
	optional := storage.Bool(false)
	required := storage.Bool(true)
	hidden := storage.Bool(false)
	outputCalls := 0
	processor, err := Compile(Options{User: Fields{
		{Name: "implicit", Attribute: storage.FieldAttribute{Type: storage.FieldString}},
		{Name: "optional", Attribute: storage.FieldAttribute{Type: storage.FieldString, Required: optional}},
		{Name: "strict", Attribute: storage.FieldAttribute{Type: storage.FieldString, Required: required}},
		{Name: "role", Attribute: storage.FieldAttribute{Type: storage.FieldString, DefaultValue: storage.StaticValue("user")}},
		{Name: "secret", Attribute: storage.FieldAttribute{Type: storage.FieldString, Returned: hidden}},
		{
			Name: "validated", Attribute: storage.FieldAttribute{Type: storage.FieldString, Required: optional},
			Validators: FieldValidators{Output: func(value any) (ValidationResult, error) {
				outputCalls++
				return ValidationResult{Value: strings.ToUpper(value.(string))}, nil
			}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	synthetic, err := processor.BuildSyntheticUserOutput(storage.Record{
		"id": "user-id", "name": "Name", "email": "a@example.com", "emailVerified": false,
		"createdAt": time.Unix(0, 0), "updatedAt": time.Unix(0, 0), "secret": "hidden",
	})
	if err != nil {
		t.Fatal(err)
	}
	if synthetic["id"] != "user-id" || synthetic["implicit"] != nil || synthetic["optional"] != nil || synthetic["role"] != "user" {
		t.Fatalf("synthetic = %#v", synthetic)
	}
	if _, exists := synthetic["strict"]; exists {
		t.Fatalf("explicit required field synthesized: %#v", synthetic)
	}
	if _, exists := synthetic["secret"]; exists {
		t.Fatalf("returned:false field synthesized: %#v", synthetic)
	}

	filtered, err := processor.FilterOutput(ModelUser, storage.Record{"validated": "lower"})
	if err != nil || filtered["validated"] != "lower" || outputCalls != 0 {
		t.Fatalf("automatic output validation = %#v calls=%d err=%v", filtered, outputCalls, err)
	}
	validated, err := processor.ValidateOutput(ModelUser, filtered)
	if err != nil || validated["validated"] != "LOWER" || outputCalls != 1 {
		t.Fatalf("explicit output validation = %#v calls=%d err=%v", validated, outputCalls, err)
	}
}

func TestAccountOutputAlwaysFiltersCoreSecrets(t *testing.T) {
	processor, err := Compile(Options{})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := processor.ParseAccountOutput(storage.Record{
		"id": "account", "providerId": "credential", "accountId": "user",
		"userId": "user", "accessToken": "access", "refreshToken": "refresh",
		"idToken": "id-token", "accessTokenExpiresAt": time.Now(),
		"refreshTokenExpiresAt": time.Now(), "password": "hash", "scope": "openid",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"accessToken", "refreshToken", "idToken", "accessTokenExpiresAt",
		"refreshTokenExpiresAt", "password",
	} {
		if _, leaked := parsed[field]; leaked {
			t.Fatalf("%s leaked from account output: %#v", field, parsed)
		}
	}
	if parsed["scope"] != "openid" || parsed["providerId"] != "credential" {
		t.Fatalf("public account fields = %#v", parsed)
	}

	// Runtime JavaScript can override a core key even though ReferenceDBOptions
	// excludes it at the type level; the later additional field wins.
	processor, err = Compile(Options{
		Account: Fields{{
			Name: "accessToken", Attribute: storage.FieldAttribute{
				Type: storage.FieldString, Required: storage.Bool(false), Returned: storage.Bool(true),
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = processor.ParseAccountOutput(storage.Record{"accessToken": "public"})
	if err != nil || parsed["accessToken"] != "public" {
		t.Fatalf("additional override = %#v, err=%v", parsed, err)
	}
}
