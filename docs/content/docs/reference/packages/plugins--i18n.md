---
title: "github.com/pers0na2dev/single-auth/plugins/i18n"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/i18n.

- Import path: `github.com/pers0na2dev/single-auth/plugins/i18n`
- Package name: `i18n`

Package i18n translates typed single-auth API errors according to a
request-local locale while leaving successful responses untouched.

## Constants

```go
const (
	PluginID = "i18n"

	Version = "1.6.26"
)
```

## Functions

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs a standalone i18n descriptor. Header, cookie, callback, and
session state already established by endpoint middleware are available.
NewFactory additionally enables lazy session resolution from the root auth.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds session locale detection to the final auth runtime.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `GetLocaleFunc`

GetLocaleFunc resolves a locale from the live endpoint context. It runs for
direct API calls too, including calls that carry no HTTP headers.

```go
type GetLocaleFunc func(*engine.Context) (string, error)
```

### `LocaleDetectionStrategy`

LocaleDetectionStrategy selects one request-local locale source. Strategies
are evaluated in declaration order and the first available locale wins.

```go
type LocaleDetectionStrategy string
```

## Constants associated with `LocaleDetectionStrategy`

```go
const (
	DetectionHeader   LocaleDetectionStrategy = "header"
	DetectionCookie   LocaleDetectionStrategy = "cookie"
	DetectionSession  LocaleDetectionStrategy = "session"
	DetectionCallback LocaleDetectionStrategy = "callback"
)
```

### `Options`

Options configures error translation and locale detection.

```go
type Options struct {
	Translations    map[string]TranslationDictionary
	DefaultLocale   string
	Detection       []LocaleDetectionStrategy
	LocaleCookie    string
	UserLocaleField string
	GetLocale       GetLocaleFunc
}
```

### `TranslationDictionary`

TranslationDictionary maps stable single-auth error codes to localized
messages.

```go
type TranslationDictionary map[string]string
```

