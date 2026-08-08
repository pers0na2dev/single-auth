package bearer

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestDescriptorAndRuntimeValidation(t *testing.T) {
	values := loadBearerTestValues(t)
	options := Options{Runtime: Runtime{Secret: values.Secret, SessionCookieName: values.SessionCookieName}}
	_, plugin := newTestDispatcher(t, options, probeEndpoint(values.Secret, values.SessionCookieName))
	if plugin.ID != "bearer" || plugin.Version != Version {
		t.Fatalf("plugin = %s@%s", plugin.ID, plugin.Version)
	}
	if len(plugin.Hooks.Before) != 1 || len(plugin.Hooks.After) != 1 ||
		len(plugin.Endpoints) != 0 || len(plugin.ErrorCodes) != 0 || len(plugin.Schema.Models) != 0 {
		t.Fatalf("descriptor = %#v", plugin)
	}

	for _, invalid := range []Options{
		{Runtime: Runtime{SessionCookieName: values.SessionCookieName}},
		{Runtime: Runtime{Secret: values.Secret}},
		{Runtime: Runtime{Secret: values.Secret, SessionCookieName: "bad cookie"}},
	} {
		if _, err := New(invalid); err == nil {
			t.Fatalf("New(%#v) succeeded", invalid)
		}
	}
}

func TestSignedBearerVariantsMatchExpectedValues(t *testing.T) {
	values := loadBearerTestValues(t)
	options := Options{RequireSignature: true, Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}
	dispatcher, _ := newTestDispatcher(t, options, probeEndpoint(values.Secret, values.SessionCookieName))
	urlSafeToken := values.UnsignedToken + "." + values.URLSafeSignature
	tests := []struct {
		name          string
		authorization string
		wantSession   string
	}{
		{name: "canonical", authorization: "Bearer " + values.SignedToken, wantSession: values.SignedToken},
		{name: "URL encoded", authorization: "Bearer " + values.EncodedSignedToken, wantSession: values.SignedToken},
		{name: "base64url no padding", authorization: "Bearer " + urlSafeToken, wantSession: urlSafeToken},
		{name: "lowercase scheme", authorization: "bearer " + values.SignedToken, wantSession: values.SignedToken},
		{name: "uppercase scheme", authorization: "BEARER " + values.SignedToken, wantSession: values.SignedToken},
		{name: "mixed scheme", authorization: "BeArEr " + values.SignedToken, wantSession: values.SignedToken},
		{name: "extra ASCII whitespace", authorization: "Bearer   " + values.SignedToken + "  ", wantSession: values.SignedToken},
		{name: "JavaScript BOM trim", authorization: "Bearer \uFEFF" + values.SignedToken + "\uFEFF", wantSession: values.SignedToken},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := contract.NewHeaders(contract.HeaderField{Name: "Authorization", Value: test.authorization})
			response, err := dispatch(t, dispatcher, "GET", "/probe", headers)
			if err != nil {
				t.Fatal(err)
			}
			probe := decodeProbe(t, response)
			if probe.Session != test.wantSession || !probe.SessionValid || probe.Authorization != test.authorization {
				t.Fatalf("probe = %#v", probe)
			}
		})
	}
}

func TestUnsignedBearerIsSignedExactlyLikeBetterCall(t *testing.T) {
	values := loadBearerTestValues(t)
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, probeEndpoint(values.Secret, values.SessionCookieName))
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + values.UnsignedToken},
		contract.HeaderField{Name: "Cookie", Value: "theme=dark"},
	)
	response, err := dispatch(t, dispatcher, "GET", "/probe", headers)
	if err != nil {
		t.Fatal(err)
	}
	probe := decodeProbe(t, response)
	if probe.Session != values.SignedToken || !probe.SessionValid || probe.Cookie != values.InjectedCookieWithExisting {
		t.Fatalf("probe = %#v", probe)
	}
}

func TestRequireSignatureRejectsRawToken(t *testing.T) {
	values := loadBearerTestValues(t)
	dispatcher, _ := newTestDispatcher(t, Options{RequireSignature: true, Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, probeEndpoint(values.Secret, values.SessionCookieName))
	response, err := dispatch(t, dispatcher, "GET", "/probe", contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + values.UnsignedToken},
	))
	if err != nil {
		t.Fatal(err)
	}
	probe := decodeProbe(t, response)
	if probe.Session != "" || probe.SessionValid {
		t.Fatalf("raw token accepted: %#v", probe)
	}
}

func TestInvalidAuthorizationNeverOverwritesExistingCookie(t *testing.T) {
	values := loadBearerTestValues(t)
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, probeEndpoint(values.Secret, values.SessionCookieName))
	existingCookie := values.SessionCookieName + "=" + values.EncodedSignedToken + "; theme=dark"
	tests := []struct {
		name          string
		authorization string
	}{
		{name: "non-bearer", authorization: "Basic abc"},
		{name: "empty bearer", authorization: "Bearer    "},
		{name: "leading whitespace", authorization: " Bearer " + values.SignedToken},
		{name: "tab scheme separator", authorization: "Bearer\t" + values.SignedToken},
		{name: "tampered signature", authorization: "Bearer " + values.SignedToken[:len(values.SignedToken)-2] + "A="},
		{name: "malformed percent encoding", authorization: "Bearer " + values.SignedToken[:len(values.SignedToken)-1] + "%ZZ"},
		{name: "dotted raw token is not resigned", authorization: "Bearer raw.with-dot"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := contract.NewHeaders(
				contract.HeaderField{Name: "Authorization", Value: test.authorization},
				contract.HeaderField{Name: "Cookie", Value: existingCookie},
			)
			response, err := dispatch(t, dispatcher, "GET", "/probe", headers)
			if err != nil {
				t.Fatal(err)
			}
			probe := decodeProbe(t, response)
			if probe.Session != values.SignedToken || !probe.SessionValid || probe.Cookie != existingCookie {
				t.Fatalf("invalid authorization changed cookie: %#v", probe)
			}
		})
	}
}

func TestValidBearerOverwritesOnlySessionCookie(t *testing.T) {
	values := loadBearerTestValues(t)
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, probeEndpoint(values.Secret, values.SessionCookieName))
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + values.SignedToken},
		contract.HeaderField{Name: "Cookie", Value: "theme=dark; " + values.SessionCookieName + "=invalid.token; locale=en"},
	)
	response, err := dispatch(t, dispatcher, "GET", "/probe", headers)
	if err != nil {
		t.Fatal(err)
	}
	probe := decodeProbe(t, response)
	want := "theme=dark; " + values.SessionCookieName + "=" + values.EncodedSignedToken + "; locale=en"
	if probe.Cookie != want || probe.Session != values.SignedToken {
		t.Fatalf("cookie = %q session=%q", probe.Cookie, probe.Session)
	}
}

func TestRepeatedAuthorizationMatchesWHATWGAndUpstreamDecoderSemantics(t *testing.T) {
	values := loadBearerTestValues(t)
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, probeEndpoint(values.Secret, values.SessionCookieName))
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + values.SignedToken},
		contract.HeaderField{Name: "Authorization", Value: "Basic second"},
	)
	response, err := dispatch(t, dispatcher, "GET", "/probe", headers)
	if err != nil {
		t.Fatal(err)
	}
	probe := decodeProbe(t, response)
	want := values.SignedToken + ", Basic second"
	if probe.Session != want || !probe.SessionValid || probe.Authorization != "Bearer "+want {
		t.Fatalf("combined authorization = %#v", probe)
	}
}

func TestBearerHooksRunForDirectServerInvocation(t *testing.T) {
	values := loadBearerTestValues(t)
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, probeEndpoint(values.Secret, values.SessionCookieName))
	request := contract.NewRequest("GET", "/probe", contract.RequestOptions{Headers: contract.NewHeaders(
		contract.HeaderField{Name: "authorization", Value: "Bearer " + values.SignedToken},
	)})
	response, err := dispatcher.Invoke("probe", engine.DirectInput{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	if probe := decodeProbe(t, response); probe.Session != values.SignedToken || !probe.SessionValid {
		t.Fatalf("direct probe = %#v", probe)
	}
}

func TestBearerBeforeHookIsRaceSafe(t *testing.T) {
	values := loadBearerTestValues(t)
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, probeEndpoint(values.Secret, values.SessionCookieName))

	const requests = 64
	errorsByRequest := make([]error, requests)
	var group sync.WaitGroup
	group.Add(requests)
	for index := range requests {
		go func() {
			defer group.Done()
			header := fmt.Sprintf("Bearer token-%d", index)
			request := contract.NewRequest("GET", "/api/auth/probe", contract.RequestOptions{
				Headers: contract.NewHeaders(contract.HeaderField{Name: "Authorization", Value: header}),
			})
			response, err := dispatcher.Dispatch(request)
			if err == nil {
				var probe probeResult
				if decodeErr := json.Unmarshal(response.Body(), &probe); decodeErr != nil || !probe.SessionValid {
					err = fmt.Errorf("invalid concurrent probe: %#v: %w", probe, decodeErr)
				}
			}
			errorsByRequest[index] = err
		}()
	}
	group.Wait()
	for index, err := range errorsByRequest {
		if err != nil {
			t.Fatalf("request %d: %v", index, err)
		}
	}
}
