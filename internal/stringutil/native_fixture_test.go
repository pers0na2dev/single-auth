package stringutil

var stringUtilityCases = []struct {
	operation string
	input     string
	want      string
}{
	{operation: "toCamelCase", input: "", want: ""},
	{operation: "toCamelCase", input: "URL_PATH", want: "urlPATH"},
	{operation: "toCamelCase", input: "UserId", want: "userId"},
	{operation: "toCamelCase", input: "my-kebab-case", want: "myKebabCase"},
	{operation: "toCamelCase", input: "user-id", want: "userId"},
	{operation: "toCamelCase", input: "user_id", want: "userId"},
	{operation: "toKebabCase", input: "", want: ""},
	{operation: "toKebabCase", input: "URLPath", want: "url-path"},
	{operation: "toKebabCase", input: "UserId", want: "user-id"},
	{operation: "toKebabCase", input: "userId", want: "user-id"},
	{operation: "toKebabCase", input: "user_id", want: "user-id"},
	{operation: "toPascalCase", input: "", want: ""},
	{operation: "toPascalCase", input: "POST", want: "Post"},
	{operation: "toPascalCase", input: "URL_PATH", want: "UrlPath"},
	{operation: "toPascalCase", input: "get", want: "Get"},
	{operation: "toPascalCase", input: "my-kebab-case", want: "MyKebabCase"},
	{operation: "toPascalCase", input: "user-id", want: "UserId"},
	{operation: "toPascalCase", input: "userId", want: "UserId"},
	{operation: "toPascalCase", input: "user_id", want: "UserId"},
	{operation: "toPascalCase", input: "한글test", want: "한글Test"},
	{operation: "toSnakeCase", input: "", want: ""},
	{operation: "toSnakeCase", input: "URL", want: "url"},
	{operation: "toSnakeCase", input: "URLPath", want: "url_path"},
	{operation: "toSnakeCase", input: "USER_ID", want: "user_id"},
	{operation: "toSnakeCase", input: "UserId", want: "user_id"},
	{operation: "toSnakeCase", input: "caféBar", want: "café_bar"},
	{operation: "toSnakeCase", input: "foo123Bar", want: "foo123_bar"},
	{operation: "toSnakeCase", input: "it's a test", want: "its_a_test"},
	{operation: "toSnakeCase", input: "my-kebab-case", want: "my_kebab_case"},
	{operation: "toSnakeCase", input: "userId", want: "user_id"},
	{operation: "toSnakeCase", input: "user_id", want: "user_id"},
	{operation: "toSnakeCase", input: "user_한글_id", want: "user_한글_id"},
	{operation: "toSnakeCase", input: "한글Test", want: "한글_test"},
}
