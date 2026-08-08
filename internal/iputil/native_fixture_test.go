package iputil

type ipCase struct {
	function    string
	value       string
	second      string
	subnet      *int
	proxies     []string
	entries     []string
	wantString  *string
	wantBool    *bool
	wantStrings []string
}

func ipString(value string) *string { return &value }
func ipBool(value bool) *bool       { return &value }
func ipInt(value int) *int          { return &value }

var ipCases = []ipCase{
	{function: "normalizeIP", value: "0.0.0.0", wantString: ipString("0.0.0.0")},
	{function: "normalizeIP", value: "::", subnet: ipInt(128), wantString: ipString("0000:0000:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "169.254.0.1", wantString: ipString("169.254.0.1")},
	{function: "normalizeIP", value: "fe80::1", subnet: ipInt(128), wantString: ipString("fe80:0000:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "127.0.0.1", wantString: ipString("127.0.0.1")},
	{function: "normalizeIP", value: "::1", subnet: ipInt(128), wantString: ipString("0000:0000:0000:0000:0000:0000:0000:0001")},
	{function: "getIPFromHeader", value: "198.51.100.10, not-an-ip", proxies: []string{"10.0.0.0/8"}},
	{function: "getIPFromHeader", value: "10.0.0.9, 10.0.0.5", proxies: []string{"10.0.0.0/8"}},
	{function: "getIPFromHeader", value: "203.0.113.7, 198.51.100.10, 10.0.0.5", proxies: []string{"10.0.0.0/8"}, wantString: ipString("198.51.100.10")},
	{function: "getIPFromHeader", value: "203.0.113.8, 198.51.100.10, 10.0.0.5", proxies: []string{"10.0.0.0/8"}, wantString: ipString("198.51.100.10")},
	{function: "getIPFromHeader", value: "198.51.100.10, 10.0.0.5", proxies: []string{"10.0.0.0/8x"}},
	{function: "getIPFromHeader", value: "2001:db8::1, fc00::1", subnet: ipInt(128), proxies: []string{"fc00::/7"}, wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "getIPFromHeader", value: "198.51.100.10, 192.0.2.1", proxies: []string{"192.0.2.1"}, wantString: ipString("198.51.100.10")},
	{function: "getIPFromHeader", value: "1.2.3.4, 198.51.100.10, 10.0.0.5", proxies: []string{"10.0.0.0/8"}, wantString: ipString("198.51.100.10")},
	{function: "getIPFromHeader", value: "198.51.100.10, 10.0.0.5", proxies: []string{"10.0.0.0/8x", "10.0.0.0/8"}, wantString: ipString("198.51.100.10")},
	{function: "getIPFromHeader", value: " 198.51.100.10 ", wantString: ipString("198.51.100.10")},
	{function: "getIPFromHeader", value: "2001:db8::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "getIPFromHeader", value: "198.51.100.10, 10.0.0.5"},
	{function: "getIPFromHeader", value: ""},
	{function: "getIPFromHeader", value: "not-an-ip"},
	{function: "normalizeIP", value: "192.168.1.1", wantString: ipString("192.168.1.1")},
	{function: "normalizeIP", value: "127.0.0.1", wantString: ipString("127.0.0.1")},
	{function: "normalizeIP", value: "10.0.0.1", wantString: ipString("10.0.0.1")},
	{function: "normalizeIP", value: "::ffff:192.0.2.1", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "::ffff:127.0.0.1", wantString: ipString("127.0.0.1")},
	{function: "normalizeIP", value: "::FFFF:10.0.0.1", wantString: ipString("10.0.0.1")},
	{function: "normalizeIP", value: "0:0:0:0:0:ffff:192.0.2.1", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "::ffff:c000:0201", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "::ffff:7f00:0001", wantString: ipString("127.0.0.1")},
	{function: "normalizeIP", value: "2001:db8:85a3::8a2e:370:7334", subnet: ipInt(128), wantString: ipString("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
	{function: "normalizeIP", value: "::ffff:192.0.2.1", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "2001:db8::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:0db8:0:0:0:0:0:1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:db8:0::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:0db8::0:0:0:1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:db8::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "::1", subnet: ipInt(128), wantString: ipString("0000:0000:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "::", subnet: ipInt(128), wantString: ipString("0000:0000:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:DB8::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:0DB8:ABCD:EF00::1", subnet: ipInt(128), wantString: ipString("2001:0db8:abcd:ef00:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:db8:abcd:ef00:1111:2222:3333:4444", subnet: ipInt(56), wantString: ipString("2001:0db8:abcd:ef00:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:ab00:1234:5678:9abc:def0:1234", subnet: ipInt(40), wantString: ipString("2001:0db8:ab00:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:1234:5678:90ab:cdef:1234:5678", subnet: ipInt(32), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", subnet: ipInt(32), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:1234:5678:90ab:cdef:1234:5678", subnet: ipInt(48), wantString: ipString("2001:0db8:1234:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:1234:ffff:ffff:ffff:ffff:ffff", subnet: ipInt(48), wantString: ipString("2001:0db8:1234:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:0:0:1234:5678:90ab:cdef", subnet: ipInt(64), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:0:0:ffff:ffff:ffff:ffff", subnet: ipInt(64), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8::1", wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8::1", subnet: ipInt(64), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8::1", subnet: ipInt(0), wantString: ipString("0000:0000:0000:0000:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "192.168.1.1", subnet: ipInt(64), wantString: ipString("192.168.1.1")},
	{function: "createRateLimitKey", value: "192.168.1.1", second: "/sign-in", wantString: ipString("192.168.1.1|/sign-in")},
	{function: "createRateLimitKey", value: "2001:db8::1", second: "/api/auth", wantString: ipString("2001:db8::1|/api/auth")},
	{function: "createRateLimitKey", value: "192.0.2.1", second: "/sign-in", wantString: ipString("192.0.2.1|/sign-in")},
	{function: "createRateLimitKey", value: "192.0.2", second: ".1/sign-in", wantString: ipString("192.0.2|.1/sign-in")},
	{function: "normalizeIP", value: "2001:db8:abcd:1234:0000:0000:0000:0001", subnet: ipInt(64), wantString: ipString("2001:0db8:abcd:1234:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:abcd:1234:1111:2222:3333:4444", subnet: ipInt(64), wantString: ipString("2001:0db8:abcd:1234:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:abcd:1234:ffff:ffff:ffff:ffff", subnet: ipInt(64), wantString: ipString("2001:0db8:abcd:1234:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "2001:db8:abcd:1234:aaaa:bbbb:cccc:dddd", subnet: ipInt(64), wantString: ipString("2001:0db8:abcd:1234:0000:0000:0000:0000")},
	{function: "normalizeIP", value: "192.0.2.1", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "::ffff:192.0.2.1", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "::FFFF:192.0.2.1", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "::ffff:c000:0201", wantString: ipString("192.0.2.1")},
	{function: "normalizeIP", value: "2001:db8::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:DB8::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:0db8::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:db8:0::1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:0db8:0:0:0:0:0:1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "normalizeIP", value: "2001:db8::0:1", subnet: ipInt(128), wantString: ipString("2001:0db8:0000:0000:0000:0000:0000:0001")},
	{function: "findInvalidTrustedProxies", entries: []string{"10.0.0.5", "10.0.0.0/8", "::1", "fc00::/7", "0.0.0.0/0"}, wantStrings: []string{}},
	{function: "findInvalidTrustedProxies", entries: []string{"10.0.0.0/8", "10.0.0./8", "10.0.0.0/8x", "10.0.0.0/33", "10.0.0.0/3.5", "10.0.0.0/", "not-an-ip", ""}, wantStrings: []string{"10.0.0./8", "10.0.0.0/8x", "10.0.0.0/33", "10.0.0.0/3.5", "10.0.0.0/", "not-an-ip", ""}},
	{function: "isValidIP", value: "not-an-ip", wantBool: ipBool(false)},
	{function: "isValidIP", value: "999.999.999.999", wantBool: ipBool(false)},
	{function: "isValidIP", value: "gggg::1", wantBool: ipBool(false)},
	{function: "isValidIP", value: "192.168.1.1", wantBool: ipBool(true)},
	{function: "isValidIP", value: "127.0.0.1", wantBool: ipBool(true)},
	{function: "isValidIP", value: "0.0.0.0", wantBool: ipBool(true)},
	{function: "isValidIP", value: "255.255.255.255", wantBool: ipBool(true)},
	{function: "isValidIP", value: "2001:db8::1", wantBool: ipBool(true)},
	{function: "isValidIP", value: "::1", wantBool: ipBool(true)},
	{function: "isValidIP", value: "::", wantBool: ipBool(true)},
	{function: "isValidIP", value: "2001:0db8:0000:0000:0000:0000:0000:0001", wantBool: ipBool(true)},
}
