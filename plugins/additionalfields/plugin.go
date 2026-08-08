package additionalfields

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// New validates and snapshots a single-auth additional-fields plugin.
func New(options Options) (engine.Plugin, error) {
	processor, err := Compile(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return processor.Plugin(), nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

// NewFactory contributes the schema before the root adapter is constructed
// and binds the processor clock to the final auth runtime.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: snapshotOptions(options)}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "additional-fields" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	processor, err := Compile(factory.options)
	if err != nil {
		return storage.Schema{}, err
	}
	return processor.Schema(), nil
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Clock = host.Clock
	return New(options)
}

// Plugin returns an independent descriptor backed by the immutable processor.
func (p *Processor) Plugin() engine.Plugin {
	if p == nil {
		return engine.Plugin{}
	}
	hooks := engine.Hooks{}
	if len(p.models[ModelUser].fields) > 0 || len(p.models[ModelSession].fields) > 0 {
		hooks.Before = []engine.BeforeHook{{
			Name:    "additional-fields-input",
			Matcher: p.matchesInputEndpoint,
			Handler: p.parseEndpointInput,
		}}
	}
	return engine.Plugin{
		ID:      "additional-fields",
		Version: Version,
		Schema:  p.Schema(),
		Hooks:   hooks,
		ErrorCodes: map[string]engine.ErrorDefinition{
			CodeFieldNotAllowed:             {Message: "Field not allowed to be set"},
			CodeAsyncValidationNotSupported: {Message: "Async validation is not supported"},
			CodeValidation:                  {Message: "Validation Error"},
			CodeMissingField:                {Message: "Field is required"},
		},
	}
}

func (p *Processor) matchesInputEndpoint(ctx *engine.Context) (bool, error) {
	endpoint, matched := ctx.Endpoint()
	if !matched {
		return false, nil
	}
	switch endpoint.Name {
	case "signUpEmail", "updateUser", "updateSession":
		return true, nil
	default:
		return false, nil
	}
}

func (p *Processor) parseEndpointInput(ctx *engine.Context) (*contract.Response, error) {
	endpoint, matched := ctx.Endpoint()
	if !matched {
		return nil, nil
	}
	modelName, action := ModelUser, ActionUpdate
	switch endpoint.Name {
	case "signUpEmail":
		modelName, action = ModelUser, ActionCreate
	case "updateUser":
		modelName, action = ModelUser, ActionUpdate
	case "updateSession":
		modelName, action = ModelSession, ActionUpdate
	default:
		return nil, nil
	}

	request := ctx.Request()
	body, ok := decodeEndpointObject(request)
	if !ok {
		// The host endpoint owns malformed-body and base-field error ordering.
		return nil, nil
	}
	input := make(storage.Record, len(body))
	for key, value := range body {
		input[key] = value
	}
	if endpoint.Name == "signUpEmail" {
		// sign-up destructures these core/control fields before parseUserInput.
		for _, key := range []string{
			"name", "email", "password", "image", "callbackURL", "rememberMe",
		} {
			delete(input, key)
		}
	} else if endpoint.Name == "updateUser" {
		// update-user passes only the rest object to parseUserInput.
		delete(input, "name")
		delete(input, "image")
	}
	parsed, err := p.ParseInput(modelName, input, action)
	if err != nil {
		return nil, err
	}
	model, err := p.model(modelName)
	if err != nil {
		return nil, err
	}
	for _, field := range model.fields {
		delete(body, field.name)
	}
	for key, value := range parsed {
		field := model.byName[key]
		// The root parser independently enforces input:false. Leaving these
		// fields absent lets its adapter apply create defaults without making
		// authority fields client-writable.
		if field.attribute.Input != nil && !*field.attribute.Input {
			continue
		}
		body[key] = value
	}

	encoded, err := encodeObject(body)
	if err != nil {
		return nil, err
	}
	headers := request.Headers()
	headers.Set("Content-Type", "application/json")
	ctx.ReplaceRequest(request.WithHeaders(headers).WithBody(encoded))
	return nil, nil
}

func decodeEndpointObject(request contract.Request) (map[string]any, bool) {
	body := bytes.TrimSpace(request.Body())
	if len(body) == 0 {
		return nil, false
	}
	contentType := strings.Join(request.Headers().Values("Content-Type"), ", ")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, false
		}
		result := make(map[string]any, len(values))
		for key, entries := range values {
			if len(entries) == 0 {
				result[key] = ""
				continue
			}
			switch entries[0] {
			case "true":
				result[key] = true
			case "false":
				result[key] = false
			default:
				result[key] = entries[0]
			}
		}
		return result, true
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	object, ok := decoded.(map[string]any)
	return object, ok
}

func encodeObject(value map[string]any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}
