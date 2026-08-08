package i18n

import (
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const emptyTranslationsError = "i18n plugin: translations object is empty. At least one locale must be provided."

type rootFactory struct{ options Options }

type compiledPlugin struct {
	translations    map[string]TranslationDictionary
	available       map[string]struct{}
	defaultLocale   string
	detection       []LocaleDetectionStrategy
	localeCookie    string
	userLocaleField string
	getLocale       GetLocaleFunc
	resolveSession  func(*engine.Context, singleauth.PluginSessionMode) (*singleauth.PluginSessionState, error)
}

// NewFactory binds session locale detection to the final auth runtime.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

func (*rootFactory) PluginID() string { return PluginID }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	if _, err := compile(factory.options, nil); err != nil {
		return storage.Schema{}, err
	}
	return storage.Schema{}, nil
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	return newPlugin(factory.options, host.ResolveSession)
}

// New constructs a standalone i18n descriptor. Header, cookie, callback, and
// session state already established by endpoint middleware are available.
// NewFactory additionally enables lazy session resolution from the root auth.
func New(options Options) (engine.Plugin, error) {
	return newPlugin(options, nil)
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

func newPlugin(
	options Options,
	resolveSession func(*engine.Context, singleauth.PluginSessionMode) (*singleauth.PluginSessionState, error),
) (engine.Plugin, error) {
	compiled, err := compile(options, resolveSession)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID:      PluginID,
		Version: Version,
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    PluginID,
			Matcher: func(*engine.Context) (bool, error) { return true, nil },
			Handler: compiled.after,
		}}},
	}, nil
}

func compile(
	input Options,
	resolveSession func(*engine.Context, singleauth.PluginSessionMode) (*singleauth.PluginSessionState, error),
) (*compiledPlugin, error) {
	options := snapshotOptions(input)
	if len(options.Translations) == 0 {
		return nil, errors.New(emptyTranslationsError)
	}
	if options.DefaultLocale == "" {
		options.DefaultLocale = "en"
	}
	if options.Detection == nil {
		options.Detection = []LocaleDetectionStrategy{DetectionHeader}
	}
	if options.LocaleCookie == "" {
		options.LocaleCookie = "locale"
	}
	if options.UserLocaleField == "" {
		options.UserLocaleField = "locale"
	}
	available := make(map[string]struct{}, len(options.Translations))
	for locale := range options.Translations {
		available[locale] = struct{}{}
	}
	return &compiledPlugin{
		translations: options.Translations, available: available,
		defaultLocale: options.DefaultLocale, detection: options.Detection,
		localeCookie: options.LocaleCookie, userLocaleField: options.UserLocaleField,
		getLocale: options.GetLocale, resolveSession: resolveSession,
	}, nil
}

func snapshotOptions(source Options) Options {
	result := source
	if source.Detection != nil {
		result.Detection = append([]LocaleDetectionStrategy(nil), source.Detection...)
	}
	result.Translations = make(map[string]TranslationDictionary, len(source.Translations))
	for locale, dictionary := range source.Translations {
		clone := make(TranslationDictionary, len(dictionary))
		for code, message := range dictionary {
			clone[code] = message
		}
		result.Translations[locale] = clone
	}
	return result
}

func (plugin *compiledPlugin) after(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	_, returnedErr, returned := ctx.Returned()
	apiError, typed := contract.AsAPIError(returnedErr)
	if !returned || !typed {
		return nil, nil
	}

	var body map[string]any
	if err := json.Unmarshal(response.Body(), &body); err != nil {
		return nil, nil
	}
	code, ok := body["code"].(string)
	if !ok {
		return nil, nil
	}
	locale, err := plugin.detectLocale(ctx)
	if err != nil {
		return nil, err
	}
	translation := plugin.translations[locale][code]
	if translation == "" {
		return nil, nil
	}

	translated := contract.NewAPIError(response.Status(), code, translation).WithWireBody(struct {
		Code            string `json:"code"`
		Message         string `json:"message"`
		OriginalMessage string `json:"originalMessage"`
	}{
		Code: code, Message: translation, OriginalMessage: apiError.Message,
	})
	return nil, translated
}

func (plugin *compiledPlugin) detectLocale(ctx *engine.Context) (string, error) {
	for _, strategy := range plugin.detection {
		locale, err := plugin.detectWith(ctx, strategy)
		if err != nil {
			return "", err
		}
		if _, ok := plugin.available[locale]; ok && locale != "" {
			return locale, nil
		}
	}
	return plugin.defaultLocale, nil
}

func (plugin *compiledPlugin) detectWith(
	ctx *engine.Context,
	strategy LocaleDetectionStrategy,
) (string, error) {
	switch strategy {
	case DetectionHeader:
		values := ctx.Request().Headers().Values("Accept-Language")
		for _, locale := range parseAcceptLanguage(strings.Join(values, ", ")) {
			if _, ok := plugin.available[locale]; ok {
				return locale, nil
			}
		}
	case DetectionCookie:
		values := ctx.Request().Headers().Values("Cookie")
		if parsed := cookies.Parse(strings.Join(values, "; ")); len(values) > 0 {
			if locale, ok := parsed.Get(plugin.localeCookie); ok {
				return locale, nil
			}
		}
	case DetectionSession:
		if session, ok := singleauth.SessionFromEndpointContext(ctx); ok {
			return stringField(session.User, plugin.userLocaleField), nil
		}
		if plugin.resolveSession != nil {
			session, err := plugin.resolveSession(ctx, singleauth.PluginSessionOptional)
			if err != nil {
				return "", err
			}
			if session != nil {
				return stringField(session.User, plugin.userLocaleField), nil
			}
		}
	case DetectionCallback:
		if plugin.getLocale != nil {
			return plugin.getLocale(ctx)
		}
	}
	return "", nil
}

func stringField(record storage.Record, name string) string {
	value, _ := record[name].(string)
	return value
}

type weightedLocale struct {
	locale string
	q      float64
}

func parseAcceptLanguage(header string) []string {
	if header == "" {
		return nil
	}
	weighted := make([]weightedLocale, 0)
	for _, part := range strings.Split(header, ",") {
		pieces := strings.Split(strings.TrimSpace(part), ";")
		localePart := ""
		if len(pieces) > 0 {
			localePart = strings.TrimSpace(pieces[0])
		}
		quality := "q=1"
		if len(pieces) > 1 {
			quality = pieces[1]
		}
		q, err := strconv.ParseFloat(strings.Replace(quality, "q=", "", 1), 64)
		if err != nil {
			q = math.NaN()
		}
		locale := strings.Split(localePart, "-")[0]
		if locale != "" {
			weighted = append(weighted, weightedLocale{locale: locale, q: q})
		}
	}
	sort.SliceStable(weighted, func(i, j int) bool {
		if math.IsNaN(weighted[i].q) || math.IsNaN(weighted[j].q) {
			return false
		}
		return weighted[i].q > weighted[j].q
	})
	locales := make([]string, len(weighted))
	for index, item := range weighted {
		locales[index] = item.locale
	}
	return locales
}
