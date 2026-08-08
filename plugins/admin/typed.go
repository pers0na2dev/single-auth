package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// ValueDecoder converts the lossless decoded direct-endpoint value into a
// caller-defined user type.
type ValueDecoder[Output any] func(any) (Output, error)

// TypedFactory preserves the configured admin user result type through factory
// functions and options indirection while delegating runtime setup to NewFactory.
type TypedFactory[Output any] struct {
	factory singleauth.PluginFactory
	decode  ValueDecoder[Output]
}

func NewTypedFactory[Output any](options Options, decode ValueDecoder[Output]) *TypedFactory[Output] {
	return &TypedFactory[Output]{factory: NewFactory(options), decode: decode}
}

func (*TypedFactory[Output]) PluginID() string { return PluginID }

func (factory *TypedFactory[Output]) Schema() (storage.Schema, error) {
	return factory.factory.Schema()
}

func (factory *TypedFactory[Output]) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	return factory.factory.Build(host)
}

// ErrorCodes is the concrete admin contribution to auth.$ERROR_CODES.
type ErrorCodes struct {
	UserAlreadyExists singleauth.ErrorCode
}

func (factory *TypedFactory[Output]) ErrorCodes() singleauth.TypedErrorCodes[ErrorCodes] {
	return singleauth.NewTypedErrorCodes(ErrorCodes{
		UserAlreadyExists: singleauth.ErrorCode(ErrorUserAlreadyExists),
	})
}

// TypedAuth binds an initialized runtime to the factory's concrete output.
type TypedAuth[Output any] struct {
	*singleauth.Auth
	decode ValueDecoder[Output]
}

func (factory *TypedFactory[Output]) BindAuth(auth *singleauth.Auth) (*TypedAuth[Output], error) {
	if factory == nil || auth == nil {
		return nil, errors.New("admin: typed auth requires an initialized auth")
	}
	if factory.decode == nil {
		return nil, errors.New("admin: typed auth requires a value decoder")
	}
	return &TypedAuth[Output]{Auth: auth, decode: factory.decode}, nil
}

func (auth *TypedAuth[Output]) API() TypedDirectAPI[Output] {
	if auth == nil || auth.Auth == nil {
		return TypedDirectAPI[Output]{}
	}
	return TypedDirectAPI[Output]{DirectAPI: auth.Auth.API(), decode: auth.decode}
}

// CreateUserInput is the typed server-side admin create-user contract.
type CreateUserInput struct {
	Name     string
	Email    string
	Password string
	Role     any
	Data     map[string]any
}

// ListUsersInput retains single-auth's search, filter, sort, limit, and offset
// query fields.
type ListUsersInput struct {
	SearchValue    string
	SearchField    string
	SearchOperator string
	FilterValue    []string
	FilterField    string
	FilterOperator string
	SortBy         string
	SortDirection  string
	Limit          *int
	Offset         *int
}

type ListUsersResult[Output any] struct {
	Users  []Output
	Total  int
	Limit  *int
	Offset *int
}

// TypedDirectAPI promotes the complete base API and adds concrete admin
// endpoint methods.
type TypedDirectAPI[Output any] struct {
	singleauth.DirectAPI
	decode ValueDecoder[Output]
}

func (api TypedDirectAPI[Output]) CreateUser(
	ctx context.Context,
	input CreateUserInput,
) (Output, error) {
	var zero Output
	if api.decode == nil {
		return zero, errors.New("admin: typed direct API is not initialized")
	}
	body := map[string]any{
		"name": input.Name, "email": input.Email,
	}
	if input.Password != "" {
		body["password"] = input.Password
	}
	if input.Role != nil {
		body["role"] = input.Role
	}
	if input.Data != nil {
		body["data"] = input.Data
	}
	result, err := api.DirectAPI.Call(ctx, "createUser", singleauth.DirectCallInput{
		Method: http.MethodPost, Body: body,
	})
	if err != nil {
		return zero, err
	}
	return api.decode(result.Value)
}

func (api TypedDirectAPI[Output]) ListUsers(
	ctx context.Context,
	input ListUsersInput,
) (ListUsersResult[Output], error) {
	if api.decode == nil {
		return ListUsersResult[Output]{}, errors.New("admin: typed direct API is not initialized")
	}
	query := encodeListUsersQuery(input)
	result, err := api.DirectAPI.Call(ctx, "listUsers", singleauth.DirectCallInput{
		Method: http.MethodGet, Query: query,
	})
	if err != nil {
		return ListUsersResult[Output]{}, err
	}
	object, ok := result.Value.(map[string]any)
	if !ok {
		return ListUsersResult[Output]{}, errors.New("admin: listUsers returned an invalid object")
	}
	rawUsers, ok := object["users"].([]any)
	if !ok {
		return ListUsersResult[Output]{}, errors.New("admin: listUsers returned invalid users")
	}
	users := make([]Output, len(rawUsers))
	for index, raw := range rawUsers {
		users[index], err = api.decode(raw)
		if err != nil {
			return ListUsersResult[Output]{}, err
		}
	}
	total, err := decodedInteger(object["total"])
	if err != nil {
		return ListUsersResult[Output]{}, err
	}
	return ListUsersResult[Output]{
		Users: users, Total: total, Limit: input.Limit, Offset: input.Offset,
	}, nil
}

func encodeListUsersQuery(input ListUsersInput) url.Values {
	query := make(url.Values)
	set := func(name, value string) {
		if value != "" {
			query.Set(name, value)
		}
	}
	set("searchValue", input.SearchValue)
	set("searchField", input.SearchField)
	set("searchOperator", input.SearchOperator)
	for _, value := range input.FilterValue {
		query.Add("filterValue", value)
	}
	set("filterField", input.FilterField)
	set("filterOperator", input.FilterOperator)
	set("sortBy", input.SortBy)
	set("sortDirection", input.SortDirection)
	if input.Limit != nil {
		query.Set("limit", strconv.Itoa(*input.Limit))
	}
	if input.Offset != nil {
		query.Set("offset", strconv.Itoa(*input.Offset))
	}
	return query
}

func decodedInteger(value any) (int, error) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		return int(parsed), err
	case float64:
		return int(typed), nil
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	default:
		return 0, errors.New("admin: expected numeric total")
	}
}

var _ singleauth.PluginFactory = (*TypedFactory[struct{}])(nil)
