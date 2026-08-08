package cookies

import (
	"strings"
	"testing"
	"time"
)

func TestSplitAndParseSetCookie(t *testing.T) {
	t.Parallel()
	header := "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/, b=hello%20world%3Dfoo; Max-Age=300; Secure; HttpOnly; SameSite=None; Partitioned"
	parsed := ParseSetCookieHeader(header)
	if len(parsed) != 2 {
		t.Fatalf("expected two cookies, got %#v", parsed)
	}
	if parsed[0].Name != "a" || parsed[0].Attributes.Value != "1" || parsed[0].Attributes.Expires == nil {
		t.Fatalf("unexpected first cookie: %#v", parsed[0])
	}
	if parsed[1].Attributes.Value != "hello world=foo" || parsed[1].Attributes.MaxAge == nil || *parsed[1].Attributes.MaxAge != 300 ||
		!parsed[1].Attributes.Secure || !parsed[1].Attributes.HTTPOnly || !parsed[1].Attributes.Partitioned || parsed[1].Attributes.SameSite != "none" {
		t.Fatalf("unexpected second cookie: %#v", parsed[1])
	}
}

func TestRequestCookieMutationMatchesReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header string
		key    string
		value  string
		want   string
	}{
		{"empty", "", "single-auth.session_token", "abc", "single-auth.session_token=abc"},
		{"append", "preference=dark; locale=en", "single-auth.session_token", "abc", "preference=dark; locale=en; single-auth.session_token=abc"},
		{"replace", "single-auth.session_token=stale; locale=en", "single-auth.session_token", "fresh", "single-auth.session_token=fresh; locale=en"},
		{"malformed", "valid=1; ; =orphan; locale=en", "single-auth.session_token", "abc", "valid=1; locale=en; single-auth.session_token=abc"},
		{"reserved", "locale=en", "session", "foo;bar=baz", "locale=en; session=foo%3Bbar%3Dbaz"},
		{"quotes", "", "token", `"abc"`, "token=%22abc%22"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := SetRequestCookie(test.header, test.key, test.value); got != test.want {
				t.Fatalf("want %q, got %q", test.want, got)
			}
		})
	}
}

func TestParseRequestCookieValidationAndLastWins(t *testing.T) {
	t.Parallel()
	parsed := Parse("session=old; bad name=x; quoted=\"abc\"; session=new;encoded=foo%3Bbar")
	if value, _ := parsed.Get("session"); value != "new" {
		t.Fatalf("expected last session, got %q", value)
	}
	if _, ok := parsed.Get("bad name"); ok {
		t.Fatal("invalid name was accepted")
	}
	if value, _ := parsed.Get("quoted"); value != "abc" {
		t.Fatalf("quoted value was not unquoted: %q", value)
	}
	if value, _ := parsed.Get("encoded"); value != "foo;bar" {
		t.Fatalf("encoded value was not decoded: %q", value)
	}
}

func TestChunkAndReconstruct(t *testing.T) {
	t.Parallel()
	maxAge := 300
	options := Options{MaxAge: &maxAge, Path: "/", HTTPOnly: true, Secure: true, SameSite: "lax"}
	store := NewStore("Session", "single-auth.session_data", options, "single-auth.session_data.0=stale; single-auth.session_data.1=chunks", nil)
	value := strings.Repeat("x", 9000)
	writes := store.ChunkValue(value, nil)
	if len(writes) < 4 {
		t.Fatalf("expected cleanup plus chunks, got %d writes", len(writes))
	}
	var requestHeader string
	for _, write := range writes {
		if write.Value == "" {
			continue
		}
		line := Serialize(write.Name, write.Value, write.Options)
		if len(line) > MaxCookieSize {
			t.Fatalf("serialized chunk %q is %d bytes", write.Name, len(line))
		}
		requestHeader = SetRequestCookie(requestHeader, write.Name, write.Value)
	}
	reconstructed, ok := GetChunked(requestHeader, "single-auth.session_data")
	if !ok || reconstructed != value {
		t.Fatalf("failed to reconstruct %d bytes", len(value))
	}
}

func TestChunkSkipsImpossibleValueAndCleansStale(t *testing.T) {
	t.Parallel()
	warnings := make([]string, 0, 1)
	store := NewStore("Session", "session_data", Options{Path: "/"}, "session_data.0=stale", func(message string) {
		warnings = append(warnings, message)
	})
	writes := store.ChunkValue(strings.Repeat("x", 420_000), nil)
	if len(writes) != 1 || writes[0].Name != "session_data.0" || writes[0].Options.MaxAge == nil || *writes[0].Options.MaxAge != 0 {
		t.Fatalf("expected stale cleanup only, got %#v", writes)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "too large") {
		t.Fatalf("missing warning: %#v", warnings)
	}
}

func TestSerialize(t *testing.T) {
	t.Parallel()
	maxAge := 300
	expires := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	got := Serialize("session", "a=b", Options{
		MaxAge:      &maxAge,
		Expires:     &expires,
		Domain:      "example.com",
		Path:        "/auth",
		Secure:      true,
		HTTPOnly:    true,
		Partitioned: true,
		SameSite:    "none",
	})
	want := "session=a%3Db; Max-Age=300; Domain=example.com; Path=/auth; Expires=Thu, 01 Jan 2026 00:00:00 GMT; HttpOnly; Secure; SameSite=None; Partitioned"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestSecurePrefix(t *testing.T) {
	t.Parallel()
	if got := StripSecurePrefix(SecurePrefix + HostPrefix + "session"); got != HostPrefix+"session" {
		t.Fatalf("unexpected prefix result: %q", got)
	}
}
