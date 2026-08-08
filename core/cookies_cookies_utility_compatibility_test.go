package core

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func cookieBehaviorUtilityRunner(vector cookiesBehaviorVector) (func(*testing.T), bool) {
	switch vector.Suite {
	case "cookie-utils parseSetCookieHeader":
		return func(t *testing.T) { runParseSetCookieBehavior(t, vector.Title) }, true
	case "cookie-utils stripSecureCookiePrefix":
		return func(t *testing.T) { runStripSecurePrefixBehavior(t, vector.Title) }, true
	case "cookie-utils setRequestCookie":
		return func(t *testing.T) { runSetRequestCookieBehavior(t, vector.Title) }, true
	case "parse cookies":
		return func(t *testing.T) { runParseCookiesBehavior(t, vector.Title) }, true
	case "Cookie header without whitespace after semicolon":
		return func(t *testing.T) { runNoWhitespaceCookieBehavior(t, vector.Title) }, true
	case "parseCookies validation":
		return func(t *testing.T) { runParseCookiesValidationBehavior(t, vector.Title) }, true
	case "applySetCookies":
		return func(t *testing.T) { runApplySetCookiesBehavior(t, vector.Title) }, true
	case "expireCookie":
		return func(t *testing.T) { runExpireCookieBehavior(t, vector.Title) }, true
	default:
		return nil, false
	}
}

func parsedSetCookieByName(t *testing.T, header, name string) cookies.Attributes {
	t.Helper()
	for _, parsed := range cookies.ParseSetCookieHeader(header) {
		if parsed.Name == name {
			return parsed.Attributes
		}
	}
	t.Fatalf("cookie %q missing from %q", name, header)
	return cookies.Attributes{}
}

func runParseSetCookieBehavior(t *testing.T, title string) {
	assertValues := func(header string, values map[string]string) []cookies.SetCookie {
		t.Helper()
		parsed := cookies.ParseSetCookieHeader(header)
		actual := make(map[string]string, len(parsed))
		for _, cookie := range parsed {
			actual[cookie.Name] = cookie.Attributes.Value
		}
		if !reflect.DeepEqual(actual, values) {
			t.Fatalf("parsed values=%#v want=%#v", actual, values)
		}
		return parsed
	}
	switch title {
	case "handles Expires with commas and multiple cookies":
		parsed := assertValues(
			"a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/, b=2; Expires=Thu, 22 Oct 2015 07:28:00 GMT; Path=/",
			map[string]string{"a": "1", "b": "2"},
		)
		if parsed[0].Attributes.Expires == nil || parsed[1].Attributes.Expires == nil ||
			parsed[0].Attributes.Expires.UTC().Format(http.TimeFormat) != "Wed, 21 Oct 2015 07:28:00 GMT" ||
			parsed[1].Attributes.Expires.UTC().Format(http.TimeFormat) != "Thu, 22 Oct 2015 07:28:00 GMT" {
			t.Fatalf("expires attributes=%#v", parsed)
		}
	case "decodes URI-encoded cookie values":
		assertValues("token=hello%20world%3Dfoo; Path=/", map[string]string{"token": "hello world=foo"})
	case "handles cookie with Expires followed by cookie without Expires":
		parsed := assertValues(
			"session=xyz; Expires=Mon, 01 Jan 2026 00:00:00 GMT, token=abc",
			map[string]string{"session": "xyz", "token": "abc"},
		)
		if parsed[0].Attributes.Expires == nil || parsed[1].Attributes.Expires != nil {
			t.Fatalf("expires attributes=%#v", parsed)
		}
	case "handles Expires when cookie value contains gmt substring":
		parsed := assertValues(
			"session_data=testsessiondata; Path=/; Expires=Mon, 02 Mar 2026 05:42:16 GMT; Max-Age=300; Secure; HttpOnly; SameSite=lax",
			map[string]string{"session_data": "testsessiondata"},
		)
		if parsed[0].Attributes.Expires == nil {
			t.Fatalf("missing expires: %#v", parsed[0])
		}
	case "handles non-standard Expires=0":
		assertValues("a=1; Expires=0, b=2", map[string]string{"a": "1", "b": "2"})
	case "handles RFC 850 date format":
		assertValues("a=1; Expires=Sunday, 06-Nov-94 08:49:37 GMT, b=2", map[string]string{"a": "1", "b": "2"})
	case "handles asctime date format (no comma in date)":
		assertValues("a=1; Expires=Sun Nov 6 08:49:37 1994, b=2", map[string]string{"a": "1", "b": "2"})
	case "handles mixed cookies with and without Expires":
		parsed := assertValues(
			"a=1; Path=/; HttpOnly, b=2; Expires=Mon, 01 Jan 2026 00:00:00 GMT; Secure, c=3; SameSite=Lax",
			map[string]string{"a": "1", "b": "2", "c": "3"},
		)
		if parsed[1].Attributes.Expires == nil {
			t.Fatalf("missing middle expires: %#v", parsed)
		}
	case "parses partitioned as a boolean cookie attribute":
		attributes := parsedSetCookieByName(t, "session=xyz; Path=/; Secure; HttpOnly; SameSite=None; Partitioned", "session")
		if attributes.Value != "xyz" || !attributes.Secure || !attributes.HTTPOnly ||
			attributes.SameSite != "none" || !attributes.Partitioned {
			t.Fatalf("attributes=%#v", attributes)
		}
	case "converts parsed cookie attributes into cookie options":
		attributes := parsedSetCookieByName(t, "session=xyz; Path=/auth; Expires=Mon, 01 Jan 2026 00:00:00 GMT; Max-Age=300; Secure; HttpOnly; SameSite=None; Partitioned", "session")
		options := cookies.OptionsFromAttributes(attributes)
		if options.Path != "/auth" || options.Expires == nil || options.MaxAge == nil ||
			*options.MaxAge != 300 || !options.Secure || !options.HTTPOnly ||
			options.SameSite != "none" || !options.Partitioned {
			t.Fatalf("options=%#v", options)
		}
	default:
		t.Fatalf("unsupported parseSetCookieHeader title %q", title)
	}
}

func runStripSecurePrefixBehavior(t *testing.T, title string) {
	var input, want string
	switch title {
	case "should strip __Secure- prefix from cookie name":
		input, want = "__Secure-session_token", "session_token"
	case "should strip __Host- prefix from cookie name":
		input, want = "__Host-session_token", "session_token"
	case "should return cookie name unchanged if no prefix":
		input, want = "session_token", "session_token"
	case "should handle cookie names with prefix-like strings in the middle":
		input, want = "my__Secure-cookie", "my__Secure-cookie"
	case "should handle empty string":
		input, want = "", ""
	case "should handle cookie names that are exactly the prefix":
		if cookies.StripSecurePrefix(cookies.SecurePrefix) != "" || cookies.StripSecurePrefix(cookies.HostPrefix) != "" {
			t.Fatal("exact prefixes were not stripped")
		}
		return
	case "should prioritize __Secure- prefix over __Host- prefix":
		input, want = cookies.SecurePrefix+cookies.HostPrefix+"test", cookies.HostPrefix+"test"
	case "should handle cookie names with dots and special characters":
		input, want = cookies.SecurePrefix+"single-auth.session_token", "single-auth.session_token"
	default:
		t.Fatalf("unsupported stripSecureCookiePrefix title %q", title)
	}
	if got := cookies.StripSecurePrefix(input); got != want {
		t.Fatalf("StripSecurePrefix(%q)=%q want=%q", input, got, want)
	}
}

func runSetRequestCookieBehavior(t *testing.T, title string) {
	tests := map[string]struct{ header, name, value, want string }{
		"writes a cookie when the header is empty":                                {"", "single-auth.session_token", "abc", "single-auth.session_token=abc"},
		"preserves existing cookies and joins with `; ` per RFC 6265":             {"preference=dark; locale=en", "single-auth.session_token", "abc", "preference=dark; locale=en; single-auth.session_token=abc"},
		"replaces an existing cookie of the same name rather than duplicating it": {"single-auth.session_token=stale; locale=en", "single-auth.session_token", "fresh", "single-auth.session_token=fresh; locale=en"},
		"ignores malformed pairs in the existing header":                          {"valid=1; ; =orphan; locale=en", "single-auth.session_token", "abc", "valid=1; locale=en; single-auth.session_token=abc"},
		"percent-encodes reserved cookie-octet bytes when serializing":            {"locale=en", "session", "foo;bar=baz", "locale=en; session=foo%3Bbar%3Dbaz"},
		"treats input as semantic and percent-encodes literal double-quotes":      {"", "token", `"abc"`, "token=%22abc%22"},
	}
	test, ok := tests[title]
	if !ok {
		t.Fatalf("unsupported setRequestCookie title %q", title)
	}
	if got := cookies.SetRequestCookie(test.header, test.name, test.value); got != test.want {
		t.Fatalf("header=%q want=%q", got, test.want)
	}
}

func runParseCookiesBehavior(t *testing.T, title string) {
	header := "single-auth.session_token=session-token.signature; single-auth.session_data=session-data.signature"
	wantToken, wantData := "session-token.signature", "session-data.signature"
	if title == "should securely parse the signed cookies with padding" {
		header = "single-auth.session_token=session-token.signature=; single-auth.session_data=session-data.signature="
		wantToken, wantData = "session-token.signature=", "session-data.signature="
	} else if title != "should parse cookies into key-value map" {
		t.Fatalf("unsupported parse cookies title %q", title)
	}
	parsed := cookies.Parse(header)
	if token, _ := parsed.Get("single-auth.session_token"); token != wantToken {
		t.Fatalf("token=%q want=%q", token, wantToken)
	}
	if data, _ := parsed.Get("single-auth.session_data"); data != wantData {
		t.Fatalf("data=%q want=%q", data, wantData)
	}
}

func runNoWhitespaceCookieBehavior(t *testing.T, title string) {
	switch title {
	case "parseCookies returns each pair when separator is `;` only":
		parsed := cookies.Parse("single-auth.session_token=session-token.signature;single-auth.session_data=session-data.signature")
		if token, _ := parsed.Get("single-auth.session_token"); token != "session-token.signature" {
			t.Fatalf("token=%q", token)
		}
		if data, _ := parsed.Get("single-auth.session_data"); data != "session-data.signature" {
			t.Fatalf("data=%q", data)
		}
	case "parseCookies tolerates mixed `;`, `; `, and `;\\t` separators":
		parsed := cookies.Parse("a=1; b=2;c=3;\td=4")
		for name, want := range map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"} {
			if got, _ := parsed.Get(name); got != want {
				t.Fatalf("%s=%q want=%q", name, got, want)
			}
		}
	case "getSessionCookie finds the session cookie when separator is `;` only":
		value, ok := cookies.GetSessionCookie("preference=dark;single-auth.session_token=token-123", cookies.SessionLookupOptions{})
		if !ok || value != "token-123" {
			t.Fatalf("session cookie=%q ok=%v", value, ok)
		}
	case "getChunkedCookie reconstructs chunks across `;`-only separators":
		value, ok := cookies.GetChunked("single-auth.session_data.0=chunkA;single-auth.session_data.1=chunkB", "single-auth.session_data")
		if !ok || value != "chunkAchunkB" {
			t.Fatalf("chunked=%q ok=%v", value, ok)
		}
	default:
		t.Fatalf("unsupported no-whitespace title %q", title)
	}
}

func runParseCookiesValidationBehavior(t *testing.T, title string) {
	switch title {
	case "returns empty map for empty header":
		if len(cookies.Parse("").Pairs()) != 0 {
			t.Fatal("empty header produced cookies")
		}
	case "rejects names containing characters outside RFC 7230 token":
		parsed := cookies.Parse("bad name=v1; ok=v2; bad,name=v3; bad:name=v4")
		for _, name := range []string{"bad name", "bad,name", "bad:name"} {
			if _, ok := parsed.Get(name); ok {
				t.Fatalf("accepted invalid name %q", name)
			}
		}
		if value, _ := parsed.Get("ok"); value != "v2" {
			t.Fatalf("ok=%q", value)
		}
	case "rejects values containing control chars, double-quote, or backslash":
		parsed := cookies.Parse("a=ok; b=has\rcr; c=has\"quote; d=has\\slash")
		if value, _ := parsed.Get("a"); value != "ok" {
			t.Fatalf("a=%q", value)
		}
		for _, name := range []string{"b", "c", "d"} {
			if _, ok := parsed.Get(name); ok {
				t.Fatalf("accepted invalid %s", name)
			}
		}
	case "accepts values with space and comma (real-world deviation)":
		parsed := cookies.Parse("a=hello world; b=v1,v2")
		if a, _ := parsed.Get("a"); a != "hello world" {
			t.Fatalf("a=%q", a)
		}
		if b, _ := parsed.Get("b"); b != "v1,v2" {
			t.Fatalf("b=%q", b)
		}
	case "splits on first `=` only, preserving subsequent `=` in value":
		if value, _ := cookies.Parse("a=b=c=d").Get("a"); value != "b=c=d" {
			t.Fatalf("a=%q", value)
		}
	case "rejects entries with CR/LF in raw key or value (no trim escape)":
		parsed := cookies.Parse("a=ok\r; b\r=1; c=v\nv; d=ok")
		for _, name := range []string{"a", "b", "c"} {
			if _, ok := parsed.Get(name); ok {
				t.Fatalf("accepted invalid %s", name)
			}
		}
		if value, _ := parsed.Get("d"); value != "ok" {
			t.Fatalf("d=%q", value)
		}
	case "strips double-quoted values per RFC 6265 §4.1.1":
		parsed := cookies.Parse(`a="hello"; b=plain; c="with space"`)
		for name, want := range map[string]string{"a": "hello", "b": "plain", "c": "with space"} {
			if value, _ := parsed.Get(name); value != want {
				t.Fatalf("%s=%q want=%q", name, value, want)
			}
		}
	default:
		t.Fatalf("unsupported parseCookies validation title %q", title)
	}
}

func runApplySetCookiesBehavior(t *testing.T, title string) {
	tests := map[string]struct {
		header string
		values []string
		want   string
	}{
		"merges into empty Cookie header":                                     {"", []string{"a=1; Path=/"}, "a=1"},
		"strips Set-Cookie attributes (only name=value lands)":                {"", []string{"a=1; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Lax"}, "a=1"},
		"merges multiple Set-Cookie values":                                   {"", []string{"a=1; Path=/", "b=2; Path=/"}, "a=1; b=2"},
		"last-wins on duplicate cookie name (existing + new)":                 {"a=old; b=keep", []string{"a=new; Path=/"}, "a=new; b=keep"},
		"re-encodes Set-Cookie values containing reserved bytes on wire join": {"session=safe", []string{"pref=foo%3Bbar=hello; Path=/"}, "session=safe; pref=foo%3Bbar%3Dhello"},
		"strips RFC 6265 quoted-string wrapping from Set-Cookie values":       {"", []string{`token="abc"; Path=/`}, "token=abc"},
	}
	test, ok := tests[title]
	if !ok {
		t.Fatalf("unsupported applySetCookies title %q", title)
	}
	if got := cookies.ApplySetCookies(test.header, test.values); got != test.want {
		t.Fatalf("cookie header=%q want=%q", got, test.want)
	}
}

func runExpireCookieBehavior(t *testing.T, title string) {
	var initial []string
	options := cookies.Options{Path: "/custom", HTTPOnly: true}
	name := "test"
	if title == "scrubs collapsed Set-Cookie headers when getSetCookie is unavailable" {
		name = "target"
		options = cookies.Options{Path: "/"}
		initial = []string{"keep=1; Path=/, target=valid; Path=/, target.0=chunk; Path=/"}
	} else if title != "preserves attributes" {
		t.Fatalf("unsupported expireCookie title %q", title)
	}
	lines := dispatchExpireCookie(t, initial, name, options)
	joined := strings.Join(lines, "\n")
	if title == "preserves attributes" {
		attributes := parsedSetCookieByName(t, joined, "test")
		if attributes.Path != "/custom" || !attributes.HTTPOnly || attributes.MaxAge == nil || *attributes.MaxAge != 0 {
			t.Fatalf("expired attributes=%#v", attributes)
		}
		return
	}
	if !strings.Contains(joined, "keep=1") || strings.Contains(joined, "target=valid") ||
		strings.Contains(joined, "target.0=chunk") || !strings.Contains(joined, "target=; Max-Age=0; Path=/") {
		t.Fatalf("scrubbed Set-Cookie=%q", joined)
	}
}

func dispatchExpireCookie(t *testing.T, initial []string, name string, options cookies.Options) []string {
	t.Helper()
	registry, err := engine.NewRegistry([]engine.Endpoint{{
		Name: "expire-cookie", Path: "/expire-cookie", Methods: []string{http.MethodPost},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			for _, value := range initial {
				ctx.AddSetCookie(value)
			}
			ExpireCookie(ctx, name, options)
			return contract.TextResponse(contract.StatusOK, "ok"), nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := dispatcher.Dispatch(contract.NewRequest(http.MethodPost, "/expire-cookie", contract.RequestOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Headers().Values("Set-Cookie")
}
