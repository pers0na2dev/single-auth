package scim

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
)

const providerContextKey = "scim.provider"

var bearerPrefix = regexp.MustCompile(`(?i)^Bearer\s+`)

// Schema returns the storage contribution used by the SCIM token middleware.
func Schema(options Options) storage.Schema {
	optional := storage.Bool(false)
	fields := map[string]storage.FieldAttribute{
		"providerId":     {Type: storage.FieldString, Unique: true},
		"scimToken":      {Type: storage.FieldString, Unique: true},
		"organizationId": {Type: storage.FieldString, Required: optional},
	}
	if options.ProviderOwnership.Enabled {
		fields["userId"] = storage.FieldAttribute{Type: storage.FieldString, Required: optional}
	}
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"scimProvider": {ModelName: "scimProvider", Fields: fields},
	}}
}

// NewFactory binds SCIM persistence and user lifecycle operations to the root
// single-auth runtime.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

func (*rootFactory) PluginID() string { return "scim" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return Schema(factory.options), nil
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	if options.CreatorRole == "" {
		options.CreatorRole = "owner"
	}
	reserved := make(map[string]struct{})
	var removeOrganizationMember func(
		context.Context,
		string,
		string,
		func(context.Context, storage.TransactionAdapter) error,
	) error
	for _, providerID := range options.ReservedProviderIDs {
		reserved[providerID] = struct{}{}
	}
	for providerID := range host.Options.SocialProviders {
		reserved[providerID] = struct{}{}
	}
	for _, candidate := range host.Options.PluginFactories {
		if source, ok := candidate.(interface{ AccountProviderIDs() []string }); ok {
			for _, providerID := range source.AccountProviderIDs() {
				reserved[providerID] = struct{}{}
			}
		}
		if source, ok := candidate.(interface{ OrganizationCreatorRole() string }); ok && factory.options.RequiredRoles == nil {
			options.CreatorRole = source.OrganizationCreatorRole()
		}
		if source, ok := candidate.(interface {
			RemoveMember(context.Context, organization.RemoveMemberInput) (organization.Member, error)
		}); ok {
			remover := source
			removeOrganizationMember = func(
				ctx context.Context,
				organizationID string,
				userID string,
				transactionMutation func(context.Context, storage.TransactionAdapter) error,
			) error {
				_, err := remover.RemoveMember(ctx, organization.RemoveMemberInput{
					OrganizationID:      organizationID,
					UserID:              userID,
					TransactionMutation: transactionMutation,
				})
				return err
			}
		}
	}
	options.Runtime = Runtime{
		Adapter:           host.Adapter,
		AdapterForContext: host.AdapterForContext,
		Random:            host.Random,
		EncryptSecret:     host.EncryptSecret,
		DecryptSecret:     host.DecryptSecret,
		ReservedProviderID: func(providerID string) bool {
			if _, exists := reserved[providerID]; exists {
				return true
			}
			return host.SocialProvider != nil && host.SocialProvider(providerID) != nil
		},
		UpdateUser:               host.UpdateUser,
		CreateUser:               host.CreateUser,
		CreateAccount:            host.InternalAdapter.CreateAccount,
		DeleteUser:               host.DeleteUser,
		RevokeSessions:           host.RevokeSessions,
		RemoveOrganizationMember: removeOrganizationMember,
		HasPlugin:                host.HasPlugin,
		Clock:                    host.Clock,
	}
	return New(options)
}

// New constructs the transport-neutral SCIM plugin descriptor.
func New(options Options) (engine.Plugin, error) {
	options = snapshotOptions(options)
	if options.Runtime.Adapter == nil && options.Runtime.AdapterForContext == nil {
		return engine.Plugin{}, fmt.Errorf("scim: Runtime.Adapter or AdapterForContext is required")
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Random == nil {
		options.Runtime.Random = rand.Reader
	}
	if err := validateTokenStorage(options.StoreSCIMToken, options.Runtime); err != nil {
		return engine.Plugin{}, err
	}
	implementation := &plugin{options: options}
	return engine.Plugin{
		ID: "scim", Version: Version, Schema: Schema(options),
		Endpoints: []engine.Endpoint{
			{
				Name: EndpointGenerateSCIMToken, Path: "/scim/generate-token",
				Methods: []string{http.MethodPost}, OperationID: EndpointGenerateSCIMToken,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: implementation.generateToken,
			},
			{
				Name: EndpointListSCIMProviderConnections, Path: "/scim/list-provider-connections",
				Methods: []string{http.MethodGet}, OperationID: EndpointListSCIMProviderConnections,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: implementation.listProviderConnections,
			},
			{
				Name: EndpointGetSCIMProviderConnection, Path: "/scim/get-provider-connection",
				Methods: []string{http.MethodGet}, OperationID: EndpointGetSCIMProviderConnection,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: implementation.getProviderConnection,
			},
			{
				Name: EndpointDeleteSCIMProviderConnection, Path: "/scim/delete-provider-connection",
				Methods: []string{http.MethodPost}, OperationID: EndpointDeleteSCIMProviderConnection,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: implementation.deleteProviderConnection,
			},
			{
				Name: EndpointCreateSCIMUser, Path: "/scim/v2/Users",
				Methods: []string{http.MethodPost}, OperationID: EndpointCreateSCIMUser,
				Use: []engine.EndpointMiddlewareFunc{implementation.authenticate}, Handler: implementation.createUser,
				Metadata: map[string]any{"allowedMediaTypes": []string{"application/scim+json", "application/json"}},
			},
			{
				Name: EndpointListSCIMUsers, Path: "/scim/v2/Users",
				Methods: []string{http.MethodGet}, OperationID: EndpointListSCIMUsers,
				Use: []engine.EndpointMiddlewareFunc{implementation.authenticate}, Handler: implementation.listUsers,
				Metadata: map[string]any{"allowedMediaTypes": []string{"application/scim+json", "application/json"}},
			},
			{
				Name: EndpointGetSCIMUser, Path: "/scim/v2/Users/:userId",
				Methods: []string{http.MethodGet}, OperationID: EndpointGetSCIMUser,
				Use: []engine.EndpointMiddlewareFunc{implementation.authenticate}, Handler: implementation.getUser,
				Metadata: map[string]any{"allowedMediaTypes": []string{"application/scim+json", "application/json"}},
			},
			{
				Name: EndpointUpdateSCIMUser, Path: "/scim/v2/Users/:userId",
				Methods: []string{http.MethodPut}, OperationID: EndpointUpdateSCIMUser,
				Use: []engine.EndpointMiddlewareFunc{implementation.authenticate}, Handler: implementation.updateUser,
				Metadata: map[string]any{"allowedMediaTypes": []string{"application/scim+json", "application/json"}},
			},
			{
				Name:        EndpointPatchSCIMUser,
				Path:        "/scim/v2/Users/:userId",
				Methods:     []string{http.MethodPatch},
				OperationID: EndpointPatchSCIMUser,
				Use:         []engine.EndpointMiddlewareFunc{implementation.authenticate},
				Metadata: map[string]any{
					"allowedMediaTypes": []string{"application/scim+json", "application/json"},
					"openapi": map[string]any{
						"summary":     "Patch SCIM user",
						"description": "Updates fields on a SCIM user record",
					},
				},
				Handler: implementation.patchUser,
			},
			{
				Name: EndpointDeleteSCIMUser, Path: "/scim/v2/Users/:userId",
				Methods: []string{http.MethodDelete}, OperationID: EndpointDeleteSCIMUser,
				Use: []engine.EndpointMiddlewareFunc{implementation.authenticate}, Handler: implementation.deleteUser,
				Metadata: map[string]any{"allowedMediaTypes": []string{"application/scim+json", "application/json", ""}},
			},
		},
	}, nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

type plugin struct{ options Options }

func (p *plugin) authenticate(ctx *engine.Context) (engine.EndpointMiddlewareResult, error) {
	authorization, _ := ctx.Request().Headers().Get("Authorization")
	presented := bearerPrefix.ReplaceAllString(authorization, "")
	if presented == "" {
		return engine.EndpointMiddlewareResult{}, scimError(
			contract.StatusUnauthorized, "SCIM token is required", "",
		)
	}
	secret, providerID, organizationID, err := decodeBearerToken(presented)
	if err != nil || secret == "" || providerID == "" {
		return engine.EndpointMiddlewareResult{}, scimError(
			contract.StatusUnauthorized, "Invalid SCIM token", "",
		)
	}
	provider, isDefault, err := p.findProvider(ctx, providerID, organizationID)
	if err != nil {
		return engine.EndpointMiddlewareResult{}, err
	}
	if provider == nil {
		return engine.EndpointMiddlewareResult{}, scimError(
			contract.StatusUnauthorized, "Invalid SCIM token", "",
		)
	}
	valid := false
	if isDefault {
		valid, err = plainTokenVerifier(ctx.GoContext(), provider.SCIMToken, secret)
	} else {
		valid, err = p.verifyStoredToken(ctx.GoContext(), provider.SCIMToken, secret)
	}
	if err != nil {
		return engine.EndpointMiddlewareResult{}, err
	}
	if !valid {
		return engine.EndpointMiddlewareResult{}, scimError(
			contract.StatusUnauthorized, "Invalid SCIM token", "",
		)
	}
	return engine.EndpointMiddlewareResult{Values: map[string]any{
		providerContextKey: *provider,
	}}, nil
}

func (p *plugin) findProvider(
	ctx *engine.Context,
	providerID string,
	organizationID string,
) (*Provider, bool, error) {
	for _, candidate := range p.options.DefaultSCIM {
		if candidate.ProviderID == providerID &&
			(organizationID == "" || candidate.OrganizationID == organizationID) {
			provider := candidate
			return &provider, true, nil
		}
	}
	adapter := p.options.Runtime.Adapter
	if p.options.Runtime.AdapterForContext != nil {
		adapter = p.options.Runtime.AdapterForContext(ctx.GoContext())
	}
	where := []storage.Where{{Field: "providerId", Value: providerID}}
	if organizationID != "" {
		where = append(where, storage.Where{Field: "organizationId", Value: organizationID})
	}
	record, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "scimProvider", Where: where,
	})
	if err != nil || record == nil {
		return nil, false, err
	}
	return &Provider{
		ID:             recordString(record, "id"),
		ProviderID:     recordString(record, "providerId"),
		SCIMToken:      recordString(record, "scimToken"),
		OrganizationID: recordString(record, "organizationId"),
		UserID:         recordString(record, "userId"),
	}, false, nil
}

func (p *plugin) patchUser(ctx *engine.Context) (contract.Response, error) {
	providerValue, ok := ctx.Value(providerContextKey)
	provider, ok := providerValue.(Provider)
	if !ok {
		err := scimError(contract.StatusUnauthorized, "SCIM token is required", "")
		return contract.ResponseFromError(err), err
	}
	userID, _ := ctx.Param("userId")
	request, err := decodePatchRequest(ctx.Request().Body())
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	if err = patchUser(ctx, p.options.Runtime, provider, userID, request); err != nil {
		return contract.ResponseFromError(err), err
	}
	return contract.NewResponse(http.StatusNoContent, contract.Headers{}, nil), nil
}

type wirePatchRequest struct {
	Schemas    []string        `json:"schemas"`
	Operations []wireOperation `json:"Operations"`
}

type wireOperation struct {
	Op    *string `json:"op"`
	Path  string  `json:"path,omitempty"`
	Value any     `json:"value"`
}

func decodePatchRequest(body []byte) (PatchRequest, error) {
	var wire wirePatchRequest
	if err := json.Unmarshal(body, &wire); err != nil {
		return PatchRequest{}, validationError("Invalid request body").WithCause(err)
	}
	validSchema := false
	for _, schema := range wire.Schemas {
		if schema == PatchOpSchema {
			validSchema = true
			break
		}
	}
	if !validSchema {
		return PatchRequest{}, validationError("[body.schemas] Invalid schemas for PatchOp")
	}
	result := PatchRequest{Schemas: append([]string(nil), wire.Schemas...)}
	result.Operations = make([]Operation, 0, len(wire.Operations))
	for index, item := range wire.Operations {
		op := "replace"
		if item.Op != nil {
			op = strings.ToLower(*item.Op)
		}
		if op != "replace" && op != "add" && op != "remove" {
			return PatchRequest{}, validationError(fmt.Sprintf(
				"[body.Operations.%d.op] Invalid option: expected one of \"replace\"|\"add\"|\"remove\"",
				index,
			))
		}
		result.Operations = append(result.Operations, Operation{
			Op: op, Path: item.Path, Value: item.Value,
		})
	}
	return result, nil
}

// EncodeBearerToken returns the RFC 4648 base64url token accepted by the SCIM
// middleware. Organization IDs may contain colons.
func EncodeBearerToken(secret, providerID, organizationID string) string {
	value := secret + ":" + providerID
	if organizationID != "" {
		value += ":" + organizationID
	}
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeBearerToken(encoded string) (string, string, string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(encoded)
	}
	if err != nil {
		return "", "", "", err
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("scim: invalid bearer token")
	}
	return parts[0], parts[1], strings.Join(parts[2:], ":"), nil
}

func plainTokenVerifier(_ context.Context, stored, presented string) (bool, error) {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1, nil
}

func snapshotOptions(source Options) Options {
	result := source
	result.DefaultSCIM = append([]Provider(nil), source.DefaultSCIM...)
	result.ReservedProviderIDs = append([]string(nil), source.ReservedProviderIDs...)
	result.LinkExistingUsers.TrustedDomains = append([]string(nil), source.LinkExistingUsers.TrustedDomains...)
	if source.RequiredRoles != nil {
		result.RequiredRoles = append([]string{}, source.RequiredRoles...)
	}
	return result
}
