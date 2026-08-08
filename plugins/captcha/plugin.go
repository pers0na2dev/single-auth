package captcha

import (
	"errors"
	"fmt"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type compiledPlugin struct {
	options  Options
	verifier verifier
}

// New snapshots options and constructs a standalone CAPTCHA descriptor.
func New(options Options) (engine.Plugin, error) {
	plugin := compile(options)
	return plugin.descriptor(), nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

// NewFactory binds provider HTTP, IP, base-path, and logger dependencies to the
// root configuration finalized by singleauth.New.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return PluginID }

func (*rootFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := snapshotOptions(factory.options)
	if options.Runtime.HTTPClient == nil {
		options.Runtime.HTTPClient = host.Options.HTTPClient
	}
	if options.Runtime.BasePath == "" {
		options.Runtime.BasePath = host.Options.BasePath
	}
	if options.Runtime.ResolveIPAddress == nil {
		options.Runtime.ResolveIPAddress = host.ResolveIPAddress
	}
	if options.Runtime.Logger == nil {
		options.Runtime.Logger = host.Logger
	}
	return New(options)
}

func compile(input Options) *compiledPlugin {
	options := snapshotOptions(input)
	if options.Runtime.BasePath == "" {
		options.Runtime.BasePath = defaultBasePath
	}
	return &compiledPlugin{
		options:  options,
		verifier: newVerifier(options.Runtime.HTTPClient),
	}
}

func snapshotOptions(source Options) Options {
	result := source
	result.Endpoints = append([]string(nil), source.Endpoints...)
	result.AllowedHostnames = append([]string(nil), source.AllowedHostnames...)
	if source.MinScore != nil {
		value := *source.MinScore
		result.MinScore = &value
	}
	return result
}

func (plugin *compiledPlugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID:         PluginID,
		Version:    Version,
		OnRequest:  plugin.onRequest,
		ErrorCodes: errorDefinitions(),
	}
}

func (plugin *compiledPlugin) onRequest(ctx *engine.Context) (result engine.OnRequestResult, returnedErr error) {
	if ctx == nil {
		return engine.OnRequestResult{}, nil
	}
	request := ctx.Request()
	if !protectedPath(request.RawPath(), plugin.options.Runtime.BasePath, plugin.options.Endpoints) {
		return engine.OnRequestResult{}, nil
	}

	// single-auth catches every exception raised by this middleware, logs it,
	// and sends the same stable UNKNOWN_ERROR response.
	defer func() {
		if recovered := recover(); recovered != nil {
			plugin.logFailure(request, fmt.Errorf("panic: %v", recovered))
			response := unknownError()
			result = engine.OnRequestResult{Response: &response}
			returnedErr = nil
		}
	}()

	if plugin.options.SecretKey == "" {
		return plugin.fail(request, errors.New(internalMissingSecretKey))
	}
	// WHATWG Headers.get combines repeated values with comma-space.
	captchaResponse := strings.Join(request.Headers().Values("x-captcha-response"), ", ")
	if captchaResponse == "" {
		response := missingResponse()
		return engine.OnRequestResult{Response: &response}, nil
	}

	remoteIP := ""
	if plugin.options.Runtime.ResolveIPAddress != nil {
		remoteIP = plugin.options.Runtime.ResolveIPAddress(request)
	}
	verifyURL := plugin.options.SiteVerifyURLOverride
	if verifyURL == "" {
		verifyURL = SiteVerifyURL(plugin.options.Provider)
	}
	input := verifyInput{
		URL: verifyURL, SecretKey: plugin.options.SecretKey,
		CaptchaResponse: captchaResponse, RemoteIP: remoteIP,
		SiteKey: plugin.options.SiteKey, MinScore: plugin.options.MinScore,
		ExpectedAction:   plugin.options.ExpectedAction,
		AllowedHostnames: plugin.options.AllowedHostnames,
	}

	var (
		verified bool
		err      error
	)
	switch plugin.options.Provider {
	case CloudflareTurnstile:
		verified, err = plugin.verifier.cloudflare(ctx.GoContext(), input)
	case GoogleRecaptcha:
		verified, err = plugin.verifier.google(ctx.GoContext(), input)
	case HCaptcha:
		verified, err = plugin.verifier.hcaptcha(ctx.GoContext(), input)
	case CaptchaFox:
		verified, err = plugin.verifier.captchafox(ctx.GoContext(), input)
	default:
		// No provider branch executes upstream, so the protected request proceeds.
		return engine.OnRequestResult{}, nil
	}
	if err != nil {
		return plugin.fail(request, err)
	}
	if !verified {
		response := verificationFailed()
		return engine.OnRequestResult{Response: &response}, nil
	}
	return engine.OnRequestResult{}, nil
}

func (plugin *compiledPlugin) fail(request contract.Request, err error) (engine.OnRequestResult, error) {
	plugin.logFailure(request, err)
	response := unknownError()
	return engine.OnRequestResult{Response: &response}, nil
}

func (plugin *compiledPlugin) logFailure(request contract.Request, err error) {
	if plugin.options.Runtime.Logger == nil {
		return
	}
	message := "Unknown error"
	if err != nil && err.Error() != "" {
		message = err.Error()
	}
	plugin.options.Runtime.Logger.Error(message, map[string]any{
		"endpoint": requestURL(request),
		"message":  err,
	})
}
