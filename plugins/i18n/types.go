package i18n

import (
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	// PluginID is the single-auth plugin registry identifier.
	PluginID = "i18n"
	// Version is the upstream package version implemented by this package.
	Version = "1.6.26"
)

// LocaleDetectionStrategy selects one request-local locale source. Strategies
// are evaluated in declaration order and the first available locale wins.
type LocaleDetectionStrategy string

const (
	DetectionHeader   LocaleDetectionStrategy = "header"
	DetectionCookie   LocaleDetectionStrategy = "cookie"
	DetectionSession  LocaleDetectionStrategy = "session"
	DetectionCallback LocaleDetectionStrategy = "callback"
)

// TranslationDictionary maps stable single-auth error codes to localized
// messages.
type TranslationDictionary map[string]string

// GetLocaleFunc resolves a locale from the live endpoint context. It runs for
// direct API calls too, including calls that carry no HTTP headers.
type GetLocaleFunc func(*engine.Context) (string, error)

// Options configures error translation and locale detection.
type Options struct {
	Translations    map[string]TranslationDictionary
	DefaultLocale   string
	Detection       []LocaleDetectionStrategy
	LocaleCookie    string
	UserLocaleField string
	GetLocale       GetLocaleFunc
}
