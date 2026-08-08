package oauthpopup

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/providers"

	singleauth "github.com/pers0na2dev/single-auth"
)

const (
	Version = "1.6.26"

	MessageType           = "single-auth:oauth-popup"
	DataElementID         = "single-auth-oauth-popup"
	MarkerCookie          = "oauth_popup"
	TokenStorageKey       = "single-auth.popup_token"
	CompleteScriptCSPHash = "sha256-s+yLgvEa6zmVvpZkoaPyaf0XlH5FrZn6IBLDhREDH/c="
)

const CompleteScript = `(function () {
	var el = document.getElementById("single-auth-oauth-popup");
	if (!el) return;
	var payload;
	try {
		payload = JSON.parse(el.textContent || "");
	} catch (e) {
		return;
	}
	var target = window.opener || window.parent;
	if (target && target !== window) {
		try {
			target.postMessage(
				{
					type: payload.type,
					nonce: payload.nonce,
					token: payload.token,
					redirectTo: payload.redirectTo,
					error: payload.error,
				},
				payload.targetOrigin,
			);
		} catch (e) {}
	}
	window.close();
})();
`

const (
	ErrorPopupSignInFailed = "POPUP_SIGN_IN_FAILED"
	ErrorPopupBlocked      = "POPUP_BLOCKED"
	ErrorPopupClosed       = "POPUP_CLOSED"
	ErrorPopupTimeout      = "POPUP_TIMEOUT"
)

var ErrorMessages = map[string]string{
	ErrorPopupSignInFailed: "Popup sign-in failed",
	ErrorPopupBlocked:      "Sign-in popup was blocked by the browser",
	ErrorPopupClosed:       "Sign-in popup was closed before completing",
	ErrorPopupTimeout:      "Sign-in popup timed out",
}

type CookieResolver func(contract.Request, string, string) (string, cookies.Options)
type OriginResolver func(contract.Request, string, bool) (bool, error)
type BaseURLResolver func(contract.Request) (string, error)
type ProviderResolver func(string) *providers.Provider
type StateCreator func(*engine.Context, singleauth.PluginOAuthStateInput) (singleauth.PluginOAuthState, error)

// Runtime contains the root services used by the server plugin. NewFactory
// binds every field to the final immutable Auth runtime.
type Runtime struct {
	Secret           string
	Logger           *logger.Logger
	Cookie           CookieResolver
	SessionCookie    func(contract.Request) (string, cookies.Options)
	IsTrustedOrigin  OriginResolver
	ResolveBaseURL   BaseURLResolver
	SocialProvider   ProviderResolver
	CreateOAuthState StateCreator
	HasPlugin        func(string) bool
}

type Options struct {
	Runtime Runtime
}

type PopupError struct {
	Code        string  `json:"code"`
	Description *string `json:"description,omitempty"`
}

type completionData struct {
	Type         string      `json:"type"`
	TargetOrigin string      `json:"targetOrigin"`
	Nonce        string      `json:"nonce"`
	Token        string      `json:"token,omitempty"`
	RedirectTo   string      `json:"redirectTo,omitempty"`
	Error        *PopupError `json:"error,omitempty"`
}

type markerData struct {
	PopupOrigin string `json:"popupOrigin"`
	PopupNonce  string `json:"popupNonce"`
}
