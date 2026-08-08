package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type verifier struct {
	client HTTPDoer
}

func newVerifier(client HTTPDoer) verifier {
	if client == nil {
		client = http.DefaultClient
	}
	return verifier{client: client}
}

type verifyInput struct {
	URL              string
	SecretKey        string
	CaptchaResponse  string
	RemoteIP         string
	SiteKey          string
	MinScore         *float64
	ExpectedAction   string
	AllowedHostnames []string
}

func (verifier verifier) cloudflare(ctx context.Context, input verifyInput) (bool, error) {
	body := struct {
		Secret   string `json:"secret"`
		Response string `json:"response"`
		RemoteIP string `json:"remoteip,omitempty"`
	}{Secret: input.SecretKey, Response: input.CaptchaResponse, RemoteIP: input.RemoteIP}
	encoded, err := javascriptJSON(body)
	if err != nil {
		return false, err
	}
	data, err := verifier.post(ctx, input.URL, "application/json", encoded)
	if err != nil {
		return false, err
	}
	if !javascriptTruthy(javascriptProperty(data, "success")) {
		return false, nil
	}
	if input.ExpectedAction != "" {
		action, ok := strictString(javascriptProperty(data, "action"))
		if !ok || action != input.ExpectedAction {
			return false, nil
		}
	}
	if len(input.AllowedHostnames) > 0 {
		hostname, ok := strictString(javascriptProperty(data, "hostname"))
		if !ok || hostname == "" || !containsString(input.AllowedHostnames, hostname) {
			return false, nil
		}
	}
	return true, nil
}

func (verifier verifier) google(ctx context.Context, input verifyInput) (bool, error) {
	fields := []formField{{name: "secret", value: input.SecretKey}, {name: "response", value: input.CaptchaResponse}}
	if input.RemoteIP != "" {
		fields = append(fields, formField{name: "remoteip", value: input.RemoteIP})
	}
	data, err := verifier.post(ctx, input.URL, "application/x-www-form-urlencoded", []byte(encodeForm(fields)))
	if err != nil {
		return false, err
	}
	if !javascriptTruthy(javascriptProperty(data, "success")) {
		return false, nil
	}
	minScore := 0.5
	if input.MinScore != nil {
		minScore = *input.MinScore
	}
	if score, isNumber := javascriptProperty(data, "score").(float64); isNumber && score < minScore {
		return false, nil
	}
	if input.ExpectedAction != "" {
		action, ok := strictString(javascriptProperty(data, "action"))
		if !ok || action != input.ExpectedAction {
			return false, nil
		}
	}
	if len(input.AllowedHostnames) > 0 {
		hostname, ok := strictString(javascriptProperty(data, "hostname"))
		if !ok || !containsString(input.AllowedHostnames, hostname) {
			return false, nil
		}
	}
	return true, nil
}

func (verifier verifier) hcaptcha(ctx context.Context, input verifyInput) (bool, error) {
	fields := []formField{{name: "secret", value: input.SecretKey}, {name: "response", value: input.CaptchaResponse}}
	if input.SiteKey != "" {
		fields = append(fields, formField{name: "sitekey", value: input.SiteKey})
	}
	if input.RemoteIP != "" {
		fields = append(fields, formField{name: "remoteip", value: input.RemoteIP})
	}
	data, err := verifier.post(ctx, input.URL, "application/x-www-form-urlencoded", []byte(encodeForm(fields)))
	if err != nil {
		return false, err
	}
	return javascriptTruthy(javascriptProperty(data, "success")), nil
}

func (verifier verifier) captchafox(ctx context.Context, input verifyInput) (bool, error) {
	fields := []formField{{name: "secret", value: input.SecretKey}, {name: "response", value: input.CaptchaResponse}}
	if input.SiteKey != "" {
		fields = append(fields, formField{name: "sitekey", value: input.SiteKey})
	}
	if input.RemoteIP != "" {
		fields = append(fields, formField{name: "remoteIp", value: input.RemoteIP})
	}
	data, err := verifier.post(ctx, input.URL, "application/x-www-form-urlencoded", []byte(encodeForm(fields)))
	if err != nil {
		return false, err
	}
	return javascriptTruthy(javascriptProperty(data, "success")), nil
}

func (verifier verifier) post(
	parent context.Context,
	url string,
	contentType string,
	body []byte,
) (any, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, VerifyTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", contentType)
	response, err := verifier.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New(internalServiceUnavailable)
	}
	if response.Body == nil {
		return nil, errors.New(internalServiceUnavailable)
	}
	defer response.Body.Close()
	bodyBytes, readErr := io.ReadAll(response.Body)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, errors.New(internalServiceUnavailable)
	}
	if readErr != nil {
		return nil, errors.New(internalServiceUnavailable)
	}
	var data any
	if err := json.Unmarshal(bodyBytes, &data); err != nil || !javascriptTruthy(data) {
		return nil, errors.New(internalServiceUnavailable)
	}
	return data, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
