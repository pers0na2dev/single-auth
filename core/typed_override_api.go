package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// NoBody is the compile-time input for an endpoint override that deliberately
// removes the base endpoint's request body contract.
type NoBody struct{}

// DirectResultDecoder turns the production DirectCallResult into a concrete
// caller-facing output type.
type DirectResultDecoder[Output any] func(DirectCallResult) (Output, error)

// TypedDirectEndpoint binds a direct API name, method, input encoder, and
// output decoder without passing values through any at the public boundary.
type TypedDirectEndpoint[Input, Output any] struct {
	direct DirectAPI
	name   string
	method string
	encode func(Input) DirectCallInput
	decode DirectResultDecoder[Output]
}

// BindTypedDirectEndpoint constructs a typed façade over a production direct
// endpoint. Plugin overrides can bind the same name with a completely new
// Input and Output type.
func BindTypedDirectEndpoint[Input, Output any](
	auth *Auth,
	name,
	method string,
	encode func(Input) DirectCallInput,
	decode DirectResultDecoder[Output],
) (TypedDirectEndpoint[Input, Output], error) {
	if auth == nil {
		return TypedDirectEndpoint[Input, Output]{}, errors.New("single-auth: typed direct endpoint requires an initialized Auth")
	}
	if name == "" || method == "" {
		return TypedDirectEndpoint[Input, Output]{}, errors.New("single-auth: typed direct endpoint requires a name and method")
	}
	if encode == nil || decode == nil {
		return TypedDirectEndpoint[Input, Output]{}, errors.New("single-auth: typed direct endpoint requires encoders")
	}
	return TypedDirectEndpoint[Input, Output]{
		direct: auth.API(), name: name, method: method, encode: encode, decode: decode,
	}, nil
}

// Call invokes the real endpoint, preserving the statically selected input and
// output types across the plugin override.
func (endpoint TypedDirectEndpoint[Input, Output]) Call(
	ctx context.Context,
	input Input,
) (Output, error) {
	var zero Output
	if endpoint.decode == nil || endpoint.encode == nil {
		return zero, errors.New("single-auth: typed direct endpoint is not initialized")
	}
	call := endpoint.encode(input)
	if call.Method == "" {
		call.Method = endpoint.method
	}
	result, err := endpoint.direct.Call(ctx, endpoint.name, call)
	if err != nil {
		return zero, err
	}
	return endpoint.decode(result)
}

// DecodeDirectJSON decodes the exact response body into Output. It is useful
// for typed plugin endpoint façades and rejects malformed JSON.
func DecodeDirectJSON[Output any](result DirectCallResult) (Output, error) {
	var output Output
	if err := json.Unmarshal(result.Response.Body(), &output); err != nil {
		return output, err
	}
	return output, nil
}

// TypedSignInEmailOverrideAPI explicitly shadows DirectAPI.SignInEmail with a
// bodyless plugin result. Other base methods remain promoted through DirectAPI.
type TypedSignInEmailOverrideAPI[Output any] struct {
	DirectAPI
	override TypedDirectEndpoint[NoBody, Output]
}

// BindTypedSignInEmailOverrideAPI binds the canonical signInEmail endpoint
// name while retaining the plugin's replacement return type.
func BindTypedSignInEmailOverrideAPI[Output any](
	auth *Auth,
	decode DirectResultDecoder[Output],
) (TypedSignInEmailOverrideAPI[Output], error) {
	endpoint, err := BindTypedDirectEndpoint(
		auth,
		"signInEmail",
		http.MethodPost,
		func(NoBody) DirectCallInput { return DirectCallInput{Method: http.MethodPost} },
		decode,
	)
	if err != nil {
		return TypedSignInEmailOverrideAPI[Output]{}, err
	}
	return TypedSignInEmailOverrideAPI[Output]{DirectAPI: auth.API(), override: endpoint}, nil
}

// SignInEmail exposes only NoBody and the replacement Output; the base email
// body's metadata cannot leak into this method's static type.
func (api TypedSignInEmailOverrideAPI[Output]) SignInEmail(
	ctx context.Context,
	input NoBody,
) (Output, error) {
	return api.override.Call(ctx, input)
}
