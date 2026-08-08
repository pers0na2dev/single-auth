package openapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type Options struct {
	Path                    string
	DisableDefaultReference bool
	Theme                   string
	Nonce                   string
}

type Runtime struct {
	Schema         storage.Schema
	ListEndpoints  func() []engine.Endpoint
	ResolveBaseURL func(contract.Request) (string, error)
	BaseURL        string
	DisabledPaths  []string
}

// New constructs the transport-neutral OpenAPI plugin from explicit runtime
// dependencies. Root users normally use NewFactory so schema and endpoint
// enumeration are bound automatically.
func New(options Options, runtime Runtime) (engine.Plugin, error) {
	path := options.Path
	if path == "" {
		path = "/reference"
	}
	if !strings.HasPrefix(path, "/") {
		return engine.Plugin{}, fmt.Errorf("openapi: reference path must start with /")
	}
	generator, err := NewGenerator(GeneratorOptions{
		Schema: runtime.Schema, ListEndpoints: runtime.ListEndpoints,
		ResolveBaseURL: runtime.ResolveBaseURL, BaseURL: runtime.BaseURL,
		DisabledPaths: runtime.DisabledPaths,
	})
	if err != nil {
		return engine.Plugin{}, err
	}
	implementation := &plugin{options: options, generator: generator}
	hidden := Metadata{Hidden: true}
	return engine.Plugin{
		ID: "open-api", Version: Version,
		Endpoints: []engine.Endpoint{
			WithMetadata(engine.Endpoint{
				Name: "generateOpenAPISchema", Path: "/open-api/generate-schema",
				Methods: []string{http.MethodGet}, Handler: implementation.generateSchema,
			}, hidden),
			WithMetadata(engine.Endpoint{
				Name: "openAPIReference", Path: path,
				Methods: []string{http.MethodGet}, Handler: implementation.reference,
			}, hidden),
		},
	}, nil
}

type plugin struct {
	options   Options
	generator *Generator
}

func (plugin *plugin) generateSchema(ctx *engine.Context) (contract.Response, error) {
	document, err := plugin.generator.Generate(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, document)
}

func (plugin *plugin) reference(ctx *engine.Context) (contract.Response, error) {
	if plugin.options.DisableDefaultReference {
		err := contract.NewAPIError(contract.StatusNotFound, "NOT_FOUND", "Not Found")
		return contract.Response{}, err
	}
	document, err := plugin.generator.Generate(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	html, err := referenceHTML(document, plugin.options.Theme, plugin.options.Nonce)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.NewResponse(contract.StatusOK, contract.NewHeaders(contract.HeaderField{
		Name: "Content-Type", Value: "text/html",
	}), []byte(html)), nil
}

const scalarLogo = `<svg width="75" height="75" viewBox="0 0 75 75" xmlns="http://www.w3.org/2000/svg"><rect width="75" height="75" rx="16" fill="black"/><path d="M20 24h35v8H20zm0 19h35v8H20z" fill="white"/></svg>`

func referenceHTML(document Document, theme, nonce string) (string, error) {
	if theme == "" {
		theme = "default"
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return "", err
	}
	schemaJSON := strings.TrimSuffix(encoded.String(), "\n")
	nonceAttribute := ""
	if nonce != "" {
		nonceAttribute = `nonce="` + nonce + `"`
	}
	favicon := url.QueryEscape(scalarLogo)
	return `<!doctype html>
<html>
  <head>
    <title>Scalar API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      type="application/json">
    ` + schemaJSON + `
    </script>
	 <script ` + nonceAttribute + `>
      var configuration = {
	  	favicon: "data:image/svg+xml;utf8,` + favicon + `",
	   	theme: "` + theme + `",
        metaData: {
			title: "single-auth API",
			description: "API Reference for your single-auth Instance",
		}
      }

      document.getElementById('api-reference').dataset.configuration =
        JSON.stringify(configuration)
    </script>
	  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference" ` + nonceAttribute + `></script>
  </body>
</html>`, nil
}
