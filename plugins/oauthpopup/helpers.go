package oauthpopup

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
)

var missingBearerWarning sync.Once

func (p *plugin) renderCompletion(origin string, data completionData) contract.Response {
	data.Type = MessageType
	data.TargetOrigin = origin
	if data.Token != "" && !p.runtime.HasPlugin("bearer") {
		missingBearerWarning.Do(func() {
			if p.runtime.Logger != nil {
				p.runtime.Logger.Warn("OAuth popup hands the session token back via postMessage, but the `bearer` plugin is not registered, so an embedded (cross-site iframe) app cannot authenticate with it. Add bearer() to your auth `plugins`.")
			}
		})
	}
	encoded, _ := json.Marshal(data)
	// encoding/json additionally escapes > and &, while JSON.stringify only
	// escapes the characters replaced by inlineJSON. Restore those two escapes;
	// < and the JavaScript line separators stay escaped.
	encoded = []byte(strings.ReplaceAll(strings.ReplaceAll(
		string(encoded), `\u003e`, ">"), `\u0026`, "&"))
	html := "<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Completing sign-in</title></head>\n<body>\n" +
		"<script type=\"application/json\" id=\"" + DataElementID + "\">" + string(encoded) + "</script>\n" +
		"<script>" + CompleteScript + "</script>\n</body>\n</html>"
	return contract.NewResponse(contract.StatusOK, contract.NewHeaders(
		contract.HeaderField{Name: "content-type", Value: "text/html; charset=utf-8"},
		contract.HeaderField{Name: "content-security-policy", Value: "default-src 'none'; script-src '" + CompleteScriptCSPHash + "'; base-uri 'none'"},
		contract.HeaderField{Name: "cache-control", Value: "no-store"},
		contract.HeaderField{Name: "pragma", Value: "no-cache"},
	), []byte(html))
}

func popupFailure(origin, nonce, code, description string) completionData {
	errorValue := &PopupError{Code: code}
	if description != "" {
		errorValue.Description = &description
	}
	return completionData{TargetOrigin: origin, Nonce: nonce, Error: errorValue}
}

func signCookie(value, secret string) string {
	return value + "." + baCrypto.MakeSignature(value, secret)
}

func readSignedCookie(request contract.Request, name, secret string) (string, bool) {
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	value, ok := cookies.Parse(header).Get(name)
	if !ok {
		return "", false
	}
	index := strings.LastIndexByte(value, '.')
	if index < 1 || !baCrypto.VerifySignature(value[:index], value[index+1:], secret) {
		return "", false
	}
	return value[:index], true
}

func redirect(location string) contract.Response {
	return contract.NewResponse(contract.StatusFound, contract.NewHeaders(
		contract.HeaderField{Name: "Location", Value: location},
	), nil)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}

func badRequest(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", message)
}

func resolvedURL(raw, base string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.IsAbs() {
		return parsed, nil
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	return baseURL.ResolveReference(parsed), nil
}

func scriptDigest() string {
	digest := sha256.Sum256([]byte(CompleteScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
}

func (p *plugin) matchesCallback(ctx *engine.Context) (bool, error) {
	path := ctx.Path()
	return strings.HasPrefix(path, "/callback/") ||
		strings.HasPrefix(path, "/oauth2/callback/"), nil
}
