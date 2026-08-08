package ratelimit

import (
	"reflect"
	"testing"
)

func intPointer(value int) *int { return &value }

func TestIPNormalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		input  string
		prefix *int
		want   string
	}{
		{"ipv4", "192.168.1.1", nil, "192.168.1.1"},
		{"compressed", "2001:db8::1", intPointer(128), "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"uppercase", "2001:0DB8:ABCD:EF00::1", intPointer(128), "2001:0db8:abcd:ef00:0000:0000:0000:0001"},
		{"zero", "::", intPointer(128), "0000:0000:0000:0000:0000:0000:0000:0000"},
		{"mapped dotted", "::FFFF:192.0.2.1", nil, "192.0.2.1"},
		{"mapped hex", "::ffff:c000:0201", nil, "192.0.2.1"},
		{"mapped full", "0:0:0:0:0:ffff:192.0.2.1", nil, "192.0.2.1"},
		{"default subnet", "2001:db8::1", nil, "2001:0db8:0000:0000:0000:0000:0000:0000"},
		{"prefix 56", "2001:db8:abcd:ef00:1111:2222:3333:4444", intPointer(56), "2001:0db8:abcd:ef00:0000:0000:0000:0000"},
		{"prefix 40", "2001:db8:ab00:1234:5678:9abc:def0:1234", intPointer(40), "2001:0db8:ab00:0000:0000:0000:0000:0000"},
		{"prefix zero", "2001:db8::1", intPointer(0), "0000:0000:0000:0000:0000:0000:0000:0000"},
		{"negative clamps", "2001:db8::1", intPointer(-1), "0000:0000:0000:0000:0000:0000:0000:0000"},
		{"above 128 does not mask", "2001:db8::1", intPointer(129), "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"invalid lowercases", "NOT-AN-IP", nil, "not-an-ip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeIP(test.input, test.prefix); got != test.want {
				t.Fatalf("NormalizeIP(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestIPValidationAndTrustedProxyDiagnostics(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{"192.168.1.1", "0.0.0.0", "255.255.255.255", "2001:db8::1", "::1", "::"} {
		if !IsValidIP(valid) {
			t.Errorf("expected %q to be valid", valid)
		}
	}
	for _, invalid := range []string{"not-an-ip", "999.999.999.999", "gggg::1", "fe80::1%eth0"} {
		if IsValidIP(invalid) {
			t.Errorf("expected %q to be invalid", invalid)
		}
	}
	want := []string{"10.0.0./8", "10.0.0.0/8x", "10.0.0.0/33", "10.0.0.0/3.5", "10.0.0.0/", "not-an-ip", ""}
	got := FindInvalidTrustedProxies(append([]string{"10.0.0.5", "10.0.0.0/8", "::1", "fc00::/7", "0.0.0.0/0"}, want...))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("invalid proxies = %#v, want %#v", got, want)
	}
}

func TestGetIPFromHeaderTrustModel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		trusted []string
		want    string
	}{
		{"single", " 198.51.100.10 ", nil, "198.51.100.10"},
		{"untrusted chain", "198.51.100.10, 10.0.0.5", nil, ""},
		{"invalid", "not-an-ip", nil, ""},
		{"rightmost untrusted", "1.2.3.4, 198.51.100.10, 10.0.0.5", []string{"10.0.0.0/8"}, "198.51.100.10"},
		{"all trusted", "10.0.0.9, 10.0.0.5", []string{"10.0.0.0/8"}, ""},
		{"malformed hop", "198.51.100.10, not-an-ip", []string{"10.0.0.0/8"}, ""},
		{"bare trusted", "198.51.100.10, 192.0.2.1", []string{"192.0.2.1"}, "198.51.100.10"},
		{"malformed config disables chain", "198.51.100.10, 10.0.0.5", []string{"10.0.0.0/8x"}, ""},
		{"valid config survives malformed", "198.51.100.10, 10.0.0.5", []string{"10.0.0.0/8x", "10.0.0.0/8"}, "198.51.100.10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := GetIPFromHeader(test.value, nil, test.trusted); got != test.want {
				t.Fatalf("GetIPFromHeader() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCreateKeyUsesSeparator(t *testing.T) {
	t.Parallel()
	if got := CreateKey("192.0.2.1", "/sign-in"); got != "192.0.2.1|/sign-in" {
		t.Fatal(got)
	}
	if CreateKey("192.0.2.1", "/sign-in") == CreateKey("192.0.2", ".1/sign-in") {
		t.Fatal("separator collision")
	}
}

func TestGetIPHeaderOrderAndEnvironmentFallbacks(t *testing.T) {
	t.Parallel()
	headers := HeaderGetterFunc(func(name string) string {
		switch name {
		case "x-custom-first":
			return "not-an-ip"
		case "x-custom-second":
			return "198.51.100.20"
		case "x-forwarded-for":
			return "198.51.100.30"
		default:
			return ""
		}
	})
	if got := GetIP(headers, IPOptions{Headers: []string{"x-custom-first", "x-custom-second"}}); got != "198.51.100.20" {
		t.Fatalf("ordered custom headers = %q", got)
	}
	if got := GetIP(headers, IPOptions{Headers: []string{}}); got != "" {
		t.Fatalf("explicitly empty headers fell back to defaults: %q", got)
	}
	if got := GetIP(nil, IPOptions{Development: true}); got != "127.0.0.1" {
		t.Fatalf("development fallback = %q", got)
	}
	if got := GetIP(nil, IPOptions{Test: true}); got != "127.0.0.1" {
		t.Fatalf("test fallback = %q", got)
	}
	if got := GetIP(headers, IPOptions{DisableTracking: true}); got != "" {
		t.Fatalf("disabled tracking = %q", got)
	}
}

func FuzzIPHelpersNeverPanic(f *testing.F) {
	for _, seed := range []string{"", "::", "::ffff:c000:0201", "1.2.3.4, 10.0.0.1", "fe80::1%eth0", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = IsValidIP(value)
		_ = NormalizeIP(value, nil)
		_ = GetIPFromHeader(value, nil, []string{"10.0.0.0/8", value})
		_ = FindInvalidTrustedProxies([]string{value})
	})
}
