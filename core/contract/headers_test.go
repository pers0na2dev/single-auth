package contract

import (
	"reflect"
	"testing"
)

func TestHeadersPreserveOrderAndRepeatedValues(t *testing.T) {
	headers := NewHeaders(
		HeaderField{Name: "X-Trace", Value: "one"},
		HeaderField{Name: "Set-Cookie", Value: "session=one; Path=/"},
		HeaderField{Name: "x-trace", Value: "two"},
		HeaderField{Name: "Set-Cookie", Value: "csrf=two; Path=/"},
	)

	if got, want := headers.Values("X-TRACE"), []string{"one", "two"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Values() = %#v, want %#v", got, want)
	}
	if got, want := headers.Values("set-cookie"), []string{"session=one; Path=/", "csrf=two; Path=/"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Set-Cookie values = %#v, want %#v", got, want)
	}
	if got := headers.Fields(); !reflect.DeepEqual(got, []HeaderField{
		{Name: "X-Trace", Value: "one"},
		{Name: "Set-Cookie", Value: "session=one; Path=/"},
		{Name: "x-trace", Value: "two"},
		{Name: "Set-Cookie", Value: "csrf=two; Path=/"},
	}) {
		t.Fatalf("Fields() changed wire order: %#v", got)
	}
}

func TestMergeResponseAppendsCookiesAndReplacesOtherHeaders(t *testing.T) {
	headers := NewHeaders(
		HeaderField{Name: "Set-Cookie", Value: "session=old"},
		HeaderField{Name: "Cache-Control", Value: "private"},
		HeaderField{Name: "X-Keep", Value: "yes"},
	)
	headers.MergeResponse(NewHeaders(
		HeaderField{Name: "set-cookie", Value: "csrf=new"},
		HeaderField{Name: "cache-control", Value: "no-store"},
		HeaderField{Name: "Cache-Control", Value: "max-age=0"},
	))

	if got, want := headers.Values("Set-Cookie"), []string{"session=old", "csrf=new"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cookies = %#v, want %#v", got, want)
	}
	if got, want := headers.Values("Cache-Control"), []string{"no-store", "max-age=0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cache-control = %#v, want %#v", got, want)
	}
	if got, ok := headers.Get("X-Keep"); !ok || got != "yes" {
		t.Fatalf("unrelated header = %q, %v", got, ok)
	}
}

func TestRequestAndResponseOwnTheirBuffers(t *testing.T) {
	body := []byte("original")
	headers := NewHeaders(HeaderField{Name: "X-Test", Value: "original"})
	request := NewRequest("post", "/path", RequestOptions{Headers: headers, Body: body})
	response := NewResponse(201, headers, body)

	body[0] = 'X'
	headers.Set("X-Test", "changed")
	requestBody := request.Body()
	requestBody[0] = 'Y'
	responseBody := response.Body()
	responseBody[0] = 'Z'

	if got := string(request.Body()); got != "original" {
		t.Fatalf("request body was aliased: %q", got)
	}
	if got := string(response.Body()); got != "original" {
		t.Fatalf("response body was aliased: %q", got)
	}
	if got, _ := request.Headers().Get("x-test"); got != "original" {
		t.Fatalf("request headers were aliased: %q", got)
	}
	if got, _ := response.Headers().Get("x-test"); got != "original" {
		t.Fatalf("response headers were aliased: %q", got)
	}
}
