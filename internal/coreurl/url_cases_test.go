package coreurl

type urlUtilityCase struct {
	operation    string
	inputs       []string
	boolOutput   *bool
	stringOutput string
}

func urlBool(value bool) *bool { return &value }

var urlUtilityCases = []urlUtilityCase{
	{operation: "safeUrlSchema", inputs: []string{"http://localhost:3000/cb"}, boolOutput: urlBool(true)},
	{operation: "safeUrlSchema", inputs: []string{"http://127.0.0.1/cb"}, boolOutput: urlBool(true)},
	{operation: "safeUrlSchema", inputs: []string{"javascript:alert(1)"}, boolOutput: urlBool(false)},
	{operation: "safeUrlSchema", inputs: []string{"data:text/html,x"}, boolOutput: urlBool(false)},
	{operation: "safeUrlSchema", inputs: []string{"vbscript:x"}, boolOutput: urlBool(false)},
	{operation: "safeUrlSchema", inputs: []string{"https://example.com/cb#token"}, boolOutput: urlBool(false)},
	{operation: "safeUrlSchema", inputs: []string{"https://example.com/cb#"}, boolOutput: urlBool(false)},
	{operation: "safeUrlSchema", inputs: []string{"https://example.com/cb"}, boolOutput: urlBool(true)},
	{operation: "safeUrlSchema", inputs: []string{"http://example.com/cb"}, boolOutput: urlBool(false)},
	{operation: "safeUrlSchema", inputs: []string{"https://example.com/cb"}, boolOutput: urlBool(true)},
	{operation: "isSafeUrlScheme", inputs: []string{"https://example.com/callback"}, boolOutput: urlBool(true)},
	{operation: "isSafeUrlScheme", inputs: []string{"http://localhost:3000/callback"}, boolOutput: urlBool(true)},
	{operation: "isSafeUrlScheme", inputs: []string{"/dashboard"}, boolOutput: urlBool(true)},
	{operation: "isSafeUrlScheme", inputs: []string{"myapp://callback"}, boolOutput: urlBool(true)},
	{operation: "isSafeUrlScheme", inputs: []string{"JavaScript:alert(1)"}, boolOutput: urlBool(false)},
	{operation: "isSafeUrlScheme", inputs: []string{"JAVASCRIPT:alert(1)"}, boolOutput: urlBool(false)},
	{operation: "isSafeUrlScheme", inputs: []string{"javascript:alert(1)"}, boolOutput: urlBool(false)},
	{operation: "isSafeUrlScheme", inputs: []string{"data:text/html,<script>alert(1)</script>"}, boolOutput: urlBool(false)},
	{operation: "isSafeUrlScheme", inputs: []string{"vbscript:msgbox(1)"}, boolOutput: urlBool(false)},
	{operation: "normalizePathname", inputs: []string{"http://localhost:3000/api/auth/sign-in", "/api/auth/"}, stringOutput: "/sign-in"},
	{operation: "normalizePathname", inputs: []string{"http://localhost:3000/api/auth", "/api/auth/"}, stringOutput: "/"},
	{operation: "normalizePathname", inputs: []string{"http://localhost:3000/api/authevil/x", "/api/auth"}, stringOutput: "/api/authevil/x"},
	{operation: "normalizePathname", inputs: []string{"not a url", "/api/auth"}, stringOutput: "/"},
	{operation: "normalizePathname", inputs: []string{"http://localhost:3000/api/auth/sign-in", "/api/auth"}, stringOutput: "/sign-in"},
	{operation: "normalizePathname", inputs: []string{"http://localhost:3000/sign-in/", "/"}, stringOutput: "/sign-in"},
	{operation: "normalizePathname", inputs: []string{"http://localhost:3000/sign-in", ""}, stringOutput: "/sign-in"},
}
