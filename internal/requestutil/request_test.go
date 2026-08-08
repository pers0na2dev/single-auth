package requestutil

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSafeCloneRequestFallsBackToBodylessCopy(t *testing.T) {
	const requestURL = "http://localhost/clone-throws"
	request, err := http.NewRequest(http.MethodPost, requestURL, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	fallback := safeCloneRequestWith(request, func(*http.Request) *http.Request {
		panic("unusable")
	})
	if fallback == nil {
		t.Fatal("fallback request is nil")
	}
	body, err := io.ReadAll(fallback.Body)
	if err != nil {
		t.Fatal(err)
	}
	if fallback == request || fallback.Method != http.MethodPost ||
		fallback.URL.String() != requestURL || string(body) != "" ||
		fallback.Header.Get("Content-Type") != request.Header.Get("Content-Type") {
		t.Fatalf("fallback=%#v body=%q", fallback, body)
	}
}
