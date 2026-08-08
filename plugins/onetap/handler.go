package onetap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

const (
	maxBodyBytes         = 4 << 20
	missingClientIDError = "Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google."
	invalidIDTokenError  = "invalid id token"
	missingEmailError    = "Email not available in token"
	oneTapOAuthScope     = "openid,profile,email"
)

func (p *plugin) callback(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	idToken, ok := body["idToken"].(string)
	if !ok || idToken == "" {
		return contract.Response{}, badRequest("idToken is required")
	}
	googleProvider := p.options.Runtime.SocialProvider("google")
	var audience any
	if p.options.ClientID != "" {
		audience = p.options.ClientID
	} else if googleProvider != nil {
		audience = googleProvider.Options.ClientID
	}
	if !audienceConfigured(audience) {
		return contract.Response{}, badRequest(missingClientIDError)
	}

	verify := p.options.VerifyIDToken
	if verify == nil {
		verify = func(ctx context.Context, input VerifyIDTokenInput) (map[string]any, error) {
			var client *http.Client
			if googleProvider != nil {
				client = googleProvider.Options.HTTPClient
			}
			return providers.VerifyGoogleIDToken(ctx, providers.VerifyGoogleIDTokenOptions{
				Token: input.Token, Audience: input.Audience, HTTPClient: client,
			})
		}
	}
	payload, err := verify(ctx.GoContext(), VerifyIDTokenInput{
		Token: idToken, Audience: audience,
	})
	if err != nil || payload == nil || stringClaim(payload, "sub") == "" {
		return contract.Response{}, badRequest(invalidIDTokenError)
	}

	configuredHostedDomain := ""
	if googleProvider != nil {
		configuredHostedDomain = googleProvider.Options.HostedDomain
	}
	if !providers.IsGoogleHostedDomainAllowed(configuredHostedDomain, payload["hd"]) {
		claim := "<missing>"
		if value, exists := payload["hd"]; exists && value != nil {
			claim = fmt.Sprint(value)
		}
		if p.options.Runtime.Logger != nil {
			p.options.Runtime.Logger.Error(fmt.Sprintf(
				"Google One Tap sign-in rejected: id token hosted domain (hd) %q does not satisfy the configured \"hd\" option %q.",
				claim, configuredHostedDomain,
			))
		}
		return contract.Response{}, badRequest(invalidIDTokenError)
	}

	rawEmail := stringClaim(payload, "email")
	if rawEmail == "" {
		return contract.JSONResponse(contract.StatusOK, map[string]any{
			"error": missingEmailError,
		})
	}
	email := strings.ToLower(rawEmail)
	emailVerified := payload["email_verified"] == true || payload["email_verified"] == "true"
	provider := googleProvider
	if provider == nil {
		provider, err = providers.Google(providers.Options{ClientID: audience})
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	disableSignup := p.options.DisableSignup || provider.Options.DisableSignUp
	result, err := p.options.Runtime.HandleOAuthUser(ctx, singleauth.PluginOAuthUserInput{
		Provider: provider, ProviderID: "google",
		User: oauth2.UserInfo{
			ID: stringClaim(payload, "sub"), Name: stringClaim(payload, "name"),
			Email: &email, Image: stringClaim(payload, "picture"),
			EmailVerified: emailVerified,
		},
		Tokens: oauth2.Tokens{
			IDToken: idToken, Scopes: strings.Split(oneTapOAuthScope, ","),
		},
		DisableSignUp: disableSignup,
	})
	if err != nil {
		return contract.Response{}, preserveError(err)
	}
	if result.LinkError != "" {
		apiErr := contract.NewAPIError(
			contract.StatusUnauthorized, "UNAUTHORIZED", result.LinkError,
		)
		return contract.Response{}, apiErr
	}
	if result.State.Session == nil || result.State.User == nil {
		return contract.Response{}, internalError(nil)
	}
	if err := p.options.Runtime.RefreshSession(ctx, result.State, false); err != nil {
		return contract.Response{}, preserveError(err)
	}
	token, _ := result.State.Session["token"].(string)
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"token": token,
		"user":  p.options.Runtime.SerializeUser(result.State.User),
	})
}

func decodeBody(ctx *engine.Context) (map[string]any, error) {
	body := ctx.Request().Body()
	if len(body) > maxBodyBytes {
		return nil, badRequest("Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, badRequest("Invalid request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, badRequest("Invalid request body")
	}
	return object, nil
}

func audienceConfigured(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return typed != ""
	case []string:
		return len(typed) != 0
	case []any:
		return len(typed) != 0
	default:
		return true
	}
}

func stringClaim(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return value
}

func badRequest(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", message)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error",
	).WithCause(err)
}

func preserveError(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return internalError(err)
}
