package oauthproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/observability/logger"
)

const maxBodyBytes = 4 << 20

func stripTrailingSlash(value string) string { return strings.TrimRight(value, "/") }

func getVendorBaseURL() string {
	if value := strings.TrimSpace(os.Getenv("VERCEL_URL")); value != "" {
		return "https://" + value
	}
	for _, name := range []string{
		"NETLIFY_URL", "RENDER_URL", "AWS_LAMBDA_FUNCTION_NAME",
		"GOOGLE_CLOUD_FUNCTION_NAME", "AZURE_FUNCTION_NAME",
	} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func originOf(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func requestURL(request contract.Request) string {
	if request.Scheme() == "" || request.Host() == "" {
		return ""
	}
	return request.Scheme() + "://" + request.Host() + request.Target()
}

func (p *plugin) resolveCurrentURL(request contract.Request) (*url.URL, error) {
	if p.options.CurrentURL != "" {
		return absoluteURL(p.options.CurrentURL)
	}
	if candidate := requestURL(request); candidate != "" {
		origin := originOf(candidate)
		trusted, err := p.runtime.IsTrustedOrigin(request, origin, false)
		if err != nil {
			return nil, err
		}
		if origin != "" && trusted {
			return absoluteURL(candidate)
		}
	}
	if vendor := getVendorBaseURL(); originOf(vendor) != "" {
		return absoluteURL(vendor)
	}
	baseURL, err := p.runtime.ResolveBaseURL(request)
	if err != nil {
		return nil, err
	}
	return absoluteURL(baseURL)
}

func (p *plugin) checkSkipProxy(request contract.Request) bool {
	if value, ok := request.Headers().Get("X-Skip-OAuth-Proxy"); ok && value != "" {
		return true
	}
	productionURL := p.options.ProductionURL
	if productionURL == "" {
		productionURL = strings.TrimSpace(os.Getenv("SINGLE_AUTH_URL"))
	}
	if productionURL == "" {
		productionURL = p.runtime.BaseURL
		if productionURL == "" {
			productionURL, _ = p.runtime.ResolveBaseURL(request)
		}
	}
	if productionURL == "" {
		return false
	}
	currentURL := p.options.CurrentURL
	if currentURL == "" {
		currentURL = requestURL(request)
	}
	if currentURL == "" {
		currentURL = getVendorBaseURL()
	}
	if currentURL == "" {
		return false
	}
	return originOf(productionURL) == originOf(currentURL)
}

func absoluteURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		if err == nil {
			err = errors.New("URL must include http:// or https://")
		}
		return nil, err
	}
	return parsed, nil
}

func decodeObjectBody(request contract.Request) (map[string]any, error) {
	body := request.Body()
	if len(body) > maxBodyBytes {
		return nil, errors.New("request body is too large")
	}
	contentType, _ := request.Headers().Get("Content-Type")
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		result := make(map[string]any, len(values))
		for key, entries := range values {
			if len(entries) != 0 {
				result[key] = entries[0]
			}
		}
		return result, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil || result == nil {
		return nil, errors.New("invalid request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("invalid request body")
	}
	return result, nil
}

func replaceJSONBody(request contract.Request, body map[string]any) (contract.Request, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return contract.Request{}, err
	}
	return request.WithHeader("Content-Type", "application/json").WithBody(encoded), nil
}

func redirect(location string) contract.Response {
	return contract.NewResponse(http.StatusFound, contract.NewHeaders(
		contract.HeaderField{Name: "Location", Value: location},
	), nil)
}

func redirectError(target, code, description string) contract.Response {
	parsed, err := url.Parse(target)
	if err != nil {
		parsed = &url.URL{Path: target}
	}
	query := parsed.Query()
	query.Set("error", code)
	if description != "" {
		query.Set("error_description", description)
	}
	parsed.RawQuery = query.Encode()
	return redirect(parsed.String())
}

func (p *plugin) defaultErrorURL(request contract.Request) string {
	if p.runtime.ErrorURL != "" {
		return p.runtime.ErrorURL
	}
	baseURL, err := p.runtime.ResolveBaseURL(request)
	if err == nil && baseURL != "" {
		return stripTrailingSlash(baseURL) + "/error"
	}
	base := stripTrailingSlash(p.runtime.BaseURL)
	if base == "" {
		return p.runtime.BasePath + "/error"
	}
	if origin := originOf(base); origin != "" {
		parsed, _ := url.Parse(base)
		if parsed.Path == "" || parsed.Path == "/" {
			return origin + p.runtime.BasePath + "/error"
		}
	}
	return base + "/error"
}

func badRequest(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", message)
}

func forbidden(code, message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusForbidden, code, message)
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

func stringValue(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok
}

func timestampMilliseconds(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	case float64:
		return typed, true
	case int64:
		return float64(typed), true
	case int:
		return float64(typed), true
	default:
		return 0, false
	}
}

func warn(logger *logger.Logger, values ...any) {
	if logger != nil {
		logger.Warn(fmt.Sprint(values...))
	}
}

func logError(logger *logger.Logger, values ...any) {
	if logger == nil || len(values) == 0 {
		return
	}
	message := fmt.Sprint(values[0])
	logger.Error(message, values[1:]...)
}
