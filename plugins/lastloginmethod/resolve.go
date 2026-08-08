package lastloginmethod

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/engine"
)

func normalizeHookContext(endpoint *engine.Context) HookContext {
	result := HookContext{Endpoint: endpoint, Params: map[string]string{}}
	if endpoint == nil {
		return result
	}
	result.Request = endpoint.Request()
	result.Params = endpoint.Params()
	if declaration, ok := endpoint.Endpoint(); ok {
		result.Path = declaration.Path
	} else {
		result.Path = endpoint.RoutePath()
	}
	return result
}

func cloneHookContext(source HookContext) HookContext {
	result := source
	result.Request = source.Request.Clone()
	result.Params = make(map[string]string, len(source.Params))
	for key, value := range source.Params {
		result.Params[key] = value
	}
	return result
}

func (plugin *compiledPlugin) resolve(endpoint *engine.Context) (string, error) {
	ctx := normalizeHookContext(endpoint)
	if plugin.customResolve != nil {
		method, err := plugin.customResolve(cloneHookContext(ctx))
		if err != nil {
			return "", err
		}
		if method != nil {
			return *method, nil
		}
	}
	return resolveDefault(ctx), nil
}

func resolveDefault(ctx HookContext) string {
	path := ctx.Path
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "/callback/") ||
		strings.HasPrefix(path, "/oauth2/callback/") {
		if method := ctx.Params["id"]; method != "" {
			return method
		}
		if method := ctx.Params["providerId"]; method != "" {
			return method
		}
		parts := strings.Split(path, "/")
		return parts[len(parts)-1]
	}
	if path == "/sign-in/email" || path == "/sign-up/email" {
		return "email"
	}
	if strings.Contains(path, "siwe") {
		return "siwe"
	}
	if strings.Contains(path, "/passkey/verify-authentication") {
		return "passkey"
	}
	if strings.HasPrefix(path, "/magic-link/verify") {
		return "magic-link"
	}
	return ""
}
