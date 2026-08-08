package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (plugin *compiledPlugin) getJWKs(ctx *engine.Context) (contract.Response, error) {
	if plugin.options.JWKS.RemoteURL != "" {
		return contract.Response{}, notFound()
	}
	keys, err := plugin.adapter.getAll(ctx)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if len(keys) == 0 {
		if _, err := plugin.createJWK(ctx); err != nil {
			return contract.Response{}, internalError(err)
		}
		keys, err = plugin.adapter.getAll(ctx)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	if len(keys) == 0 {
		return contract.Response{}, errors.New("No key sets found. Make sure you have a key in your database.")
	}
	now := plugin.clock()
	grace := gracePeriod(plugin.options)
	result := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		if key.ExpiresAt != nil && !key.ExpiresAt.Add(grace).After(now) {
			continue
		}
		publicKey, err := parseJWK(key.PublicKey)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		algorithm := key.Algorithm
		if algorithm == "" && plugin.options.JWKS.KeyPair != nil {
			algorithm = plugin.options.JWKS.KeyPair.Algorithm
		}
		if algorithm == "" {
			algorithm = EdDSA
		}
		entry := map[string]any{"alg": string(algorithm)}
		curve := key.Curve
		if curve == "" && plugin.options.JWKS.KeyPair != nil {
			curve = plugin.options.JWKS.KeyPair.Curve
		}
		if curve != "" {
			entry["crv"] = curve
		}
		for name, value := range publicKey {
			entry[name] = value
		}
		entry["kid"] = key.ID
		result = append(result, entry)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"keys": result})
}

func (plugin *compiledPlugin) getToken(ctx *engine.Context) (contract.Response, error) {
	state, err := plugin.options.Runtime.ResolveSession(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	if state == nil || state.Session == nil || state.User == nil {
		return contract.Response{}, unauthorized()
	}
	token, err := plugin.getJWTToken(ctx, *state)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"token": token})
}

func (plugin *compiledPlugin) signJWTEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, err
	}
	payload, ok := body["payload"].(map[string]any)
	if !ok {
		return contract.Response{}, badRequest("VALIDATION_ERROR", "Invalid request body", nil)
	}
	implementation := plugin
	if override, exists := body["overrideOptions"]; exists && override != nil {
		overrideMap, ok := override.(map[string]any)
		if !ok {
			return contract.Response{}, badRequest("VALIDATION_ERROR", "Invalid request body", nil)
		}
		merged, err := mergeJSONOptions(plugin.options, overrideMap)
		if err != nil {
			return contract.Response{}, badRequest("VALIDATION_ERROR", "Invalid request body", err)
		}
		implementation, err = normalize(merged, false)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	token, err := implementation.signJWT(ctx, payload)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"token": token})
}

func (plugin *compiledPlugin) verifyJWTEndpoint(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx.Request().Body())
	if err != nil {
		return contract.Response{}, err
	}
	token, ok := body["token"].(string)
	if !ok {
		return contract.Response{}, badRequest("VALIDATION_ERROR", "Invalid request body", nil)
	}
	implementation := plugin
	if issuerValue, exists := body["issuer"]; exists && issuerValue != nil {
		issuer, ok := issuerValue.(string)
		if !ok {
			return contract.Response{}, badRequest("VALIDATION_ERROR", "Invalid request body", nil)
		}
		options := plugin.options
		options.Token.Issuer = String(issuer)
		implementation, err = normalize(options, false)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"payload": implementation.verifyJWT(ctx, token),
	})
}

func (plugin *compiledPlugin) matchGetSession(ctx *engine.Context) (bool, error) {
	return ctx != nil && ctx.Path() == "/get-session", nil
}

func (plugin *compiledPlugin) afterGetSession(ctx *engine.Context, response contract.Response) (*contract.Response, error) {
	if plugin.options.DisableSettingJWTHeader {
		return nil, nil
	}
	state, err := plugin.options.Runtime.ResolveSession(ctx, false)
	if err != nil {
		return nil, err
	}
	if state == nil || state.Session == nil || state.User == nil {
		return nil, nil
	}
	token, err := plugin.getJWTToken(ctx, *state)
	if err != nil {
		return nil, err
	}
	exposed, _ := response.Headers().Get("Access-Control-Expose-Headers")
	ctx.SetResponseHeader("set-auth-jwt", token)
	ctx.SetResponseHeader("Access-Control-Expose-Headers", strings.Join(headerList(exposed), ", "))
	return nil, nil
}

func mergeJSONOptions(base Options, override map[string]any) (Options, error) {
	result := base
	if raw, exists := override["jwt"]; exists {
		object, ok := raw.(map[string]any)
		if !ok {
			return Options{}, fmt.Errorf("jwt override must be an object")
		}
		result.Token = TokenOptions{}
		if value, exists := object["issuer"]; exists {
			issuer, valid := value.(string)
			ok = valid
			if !ok {
				return Options{}, fmt.Errorf("jwt.issuer must be a string")
			}
			result.Token.Issuer = String(issuer)
		}
		if value, exists := object["audience"]; exists {
			normalized, normalizeErr := normalizeAudience(value)
			if normalizeErr != nil {
				return Options{}, normalizeErr
			}
			result.Token.Audience = normalized
		}
		if value, exists := object["expirationTime"]; exists {
			switch item := value.(type) {
			case string, json.Number, float64:
				result.Token.ExpirationTime = item
			default:
				return Options{}, fmt.Errorf("jwt.expirationTime is invalid")
			}
		}
	}
	if raw, exists := override["jwks"]; exists {
		object, ok := raw.(map[string]any)
		if !ok {
			return Options{}, fmt.Errorf("jwks override must be an object")
		}
		result.JWKS = JWKSOptions{}
		if value, exists := object["disablePrivateKeyEncryption"]; exists {
			result.JWKS.DisablePrivateKeyEncryption, ok = value.(bool)
			if !ok {
				return Options{}, fmt.Errorf("jwks.disablePrivateKeyEncryption must be a boolean")
			}
		}
	}
	return result, nil
}
