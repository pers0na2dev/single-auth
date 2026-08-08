---
title: "github.com/pers0na2dev/single-auth/security/ratelimit"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/security/ratelimit.

- Import path: `github.com/pers0na2dev/single-auth/security/ratelimit`
- Package name: `ratelimit`

Package ratelimit implements reference implementation compatible, per-IP request rate
limiting without depending on a concrete HTTP framework. The net/http,
fasthttp, and Fiber bridges live in their respective transport packages.

## Constants

```go
const (
	DefaultWindow int64 = 10

	DefaultMax int64 = 100

	NoTrustedIPKey = "no-trusted-ip"

	TooManyRequestsMessage = "Too many requests. Please try again later."

	TooManyRequestsBody = `{"message":"Too many requests. Please try again later."}`
)
```

## Variables

```go
var ErrNilRequest = errors.New("ratelimit: request is nil")
```

## Functions

### `CreateKey`

CreateKey separates the IP and path so attacker-controlled concatenations
cannot collide.

```go
func CreateKey(ip, path string) string
```

### `FindInvalidTrustedProxies`

FindInvalidTrustedProxies returns configured proxy entries that are neither
a valid bare IP nor a valid IP/prefix range, preserving input order.

```go
func FindInvalidTrustedProxies(entries []string) []string
```

### `GetIP`

GetIP resolves a client IP from configured headers. It returns an empty
string when tracking is disabled or no trustworthy value exists.

```go
func GetIP(headers HeaderGetter, options IPOptions) string
```

### `GetIPFromHeader`

GetIPFromHeader resolves a trustworthy client from one forwarded header.
Without a valid trusted-proxy configuration only a single address is
accepted. With one, proxy hops are stripped from right to left.

```go
func GetIPFromHeader(value string, ipv6Subnet *int, trustedProxies []string) string
```

### `IsValidIP`

IsValidIP reports whether value is a syntactically valid IPv4 or IPv6
address. Zone-qualified IPv6 addresses are intentionally rejected.

```go
func IsValidIP(value string) bool
```

### `NormalizeIP`

NormalizeIP applies reference implementation's address canonicalization. IPv4-mapped
IPv6 addresses become IPv4. IPv6 addresses are expanded to eight lowercase
groups and masked to /64 unless an explicit prefix is supplied.

```go
func NormalizeIP(value string, ipv6Subnet *int) string
```

### `NormalizePathname`

NormalizePathname strips the auth base path and trailing slashes. Like the
upstream WHATWG URL call, it requires an absolute URL and returns "/" when
parsing fails.

```go
func NormalizePathname(requestURL, basePath string) string
```

### `Schema`

Schema returns the canonical reference implementation database-backed rate-limit model.
A unique key constraint is the atomic create-race guard; count is numeric,
and lastRequest is stored as a bigint Unix-millisecond value.

```go
func Schema() storage.Schema
```

### `SchemaWithModelName`

SchemaWithModelName returns the canonical rateLimit schema using modelName
as its physical table/model name. An empty name selects "rateLimit".

```go
func SchemaWithModelName(modelName string) storage.Schema
```

### `WildcardMatch`

WildcardMatch implements the default slash-separated behavioral compatibility of Better
Auth's wildcard-match dependency. '*' and '?' stay within a path segment;
'**' can span segments; repeated slash/backslash separators are accepted.

```go
func WildcardMatch(pattern, sample string) bool
```

## Types

### `AtomicStorage`

AtomicStorage performs check-and-increment as one indivisible operation.
Strict enforcement under concurrency requires this interface.

```go
type AtomicStorage interface {
	Storage
	Consume(context.Context, string, Rule) (ConsumeResult, error)
}
```

### `Config`

Config configures a Limiter. A nil Enabled value follows reference implementation's
production default: enabled in production and disabled otherwise.

```go
type Config struct {
	Enabled     *bool
	Production  bool
	BasePath    string
	DefaultRule Rule
	PluginRules [][]MatcherRule
	CustomRules []CustomRule
	IP          IPOptions
	Warn        func(string)
	Now         func() time.Time
}
```

### `ConsumeResult`

ConsumeResult is returned by an atomic storage backend.

```go
type ConsumeResult struct {
	Allowed    bool
	RetryAfter *int64
}
```

### `CustomRule`

CustomRule is an ordered reference implementation custom rule. Pattern is exact unless it
contains '*', in which case reference implementation wildcard matching is used.

```go
type CustomRule struct {
	Pattern  string
	Rule     Rule
	Disabled bool
	Resolve  func(context.Context, RequestInfo, Rule) (Rule, bool, error)
}
```

### `DatabaseOptions`

DatabaseOptions configures reference implementation's rateLimit model backend.

```go
type DatabaseOptions struct {
	Model        string
	GlobalWindow int64
	Now          func() time.Time
	Error        func(string, error)
}
```

### `DatabaseStore`

DatabaseStore stores rate limits through the shared storage adapter and
uses IncrementOne guards for strict concurrency behavioral compatibility.

```go
type DatabaseStore struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `DatabaseStore`

### `NewDatabaseStore`

NewDatabaseStore constructs an atomic database-backed store.

```go
func NewDatabaseStore(adapter storage.TransactionAdapter, options DatabaseOptions) *DatabaseStore
```

## Methods on `DatabaseStore`

### `Consume`

Consume atomically checks and advances one database counter.

```go
func (store *DatabaseStore) Consume(ctx context.Context, key string, rule Rule) (ConsumeResult, error)
```

### `Get`

Get reads one rateLimit row.

```go
func (store *DatabaseStore) Get(ctx context.Context, key string) (*Record, error)
```

### `Set`

Set implements reference implementation's legacy database storage operation. Like the
upstream wrapper, write errors are logged and swallowed.

```go
func (store *DatabaseStore) Set(ctx context.Context, key string, value Record, update bool, _ int64) error
```

### `HeaderGetter`

HeaderGetter exposes the only header operation needed by the limiter.
Concrete transports adapt their native header collections to this
interface without copying the full request.

```go
type HeaderGetter interface {
	Get(string) string
}
```

### `HeaderGetterFunc`

HeaderGetterFunc adapts a function to HeaderGetter.

```go
type HeaderGetterFunc func(string) string
```

## Methods on `HeaderGetterFunc`

### `Get`

Get implements HeaderGetter.

```go
func (f HeaderGetterFunc) Get(name string) string
```

### `IPOptions`

IPOptions controls trusted-client-IP resolution.

```go
type IPOptions struct {
	DisableTracking bool
	Headers         []string
	TrustedProxies  []string
	// IPv6Subnet defaults to 64. A non-nil value, including zero, is honored.
	IPv6Subnet *int
	// Development and Test enable reference implementation's 127.0.0.1 fallback.
	Development bool
	Test        bool
}
```

### `Limiter`

Limiter resolves reference implementation rules and consumes their storage counters.

```go
type Limiter struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Limiter`

### `New`

New constructs a limiter. A nil store selects an isolated memory backend.

```go
func New(config Config, store Storage) *Limiter
```

## Methods on `Limiter`

### `Check`

Check resolves and consumes the rate-limit bucket for a transport-neutral
request.

```go
func (limiter *Limiter) Check(ctx context.Context, request RequestInfo) (Result, error)
```

### `MatcherRule`

MatcherRule is one plugin-provided rule. Plugin rule groups are evaluated
in plugin order; the first matching rule in the first matching group wins.

```go
type MatcherRule struct {
	Match func(string) bool
	Rule  Rule
}
```

### `MemoryOptions`

MemoryOptions configures an isolated in-process storage instance.

```go
type MemoryOptions struct {
	MaxEntries int
	Now        func() time.Time
}
```

### `MemoryStore`

MemoryStore is a race-safe atomic storage backend. Each instance is
isolated, making tests and multiple auth engines independent.

```go
type MemoryStore struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MemoryStore`

### `NewMemoryStore`

NewMemoryStore creates an empty atomic in-process backend.

```go
func NewMemoryStore(options MemoryOptions) *MemoryStore
```

## Methods on `MemoryStore`

### `Consume`

Consume atomically decides and records one request.

```go
func (store *MemoryStore) Consume(ctx context.Context, key string, rule Rule) (ConsumeResult, error)
```

### `Get`

Get returns a copy of a live record.

```go
func (store *MemoryStore) Get(ctx context.Context, key string) (*Record, error)
```

### `Len`

Len returns the number of entries, including entries that have not yet been
encountered by an expiry sweep.

```go
func (store *MemoryStore) Len() int
```

### `Set`

Set creates or updates a record and slides its expiry by ttlSeconds.

```go
func (store *MemoryStore) Set(ctx context.Context, key string, value Record, _ bool, ttlSeconds int64) error
```

### `Record`

Record is the persisted reference implementation rateLimit row. LastRequest is Unix time
in milliseconds.

```go
type Record struct {
	Key         string `json:"key"`
	Count       int64  `json:"count"`
	LastRequest int64  `json:"lastRequest"`
}
```

### `RequestInfo`

RequestInfo is the transport-neutral request shape used by the limiter.

```go
type RequestInfo struct {
	URL     string
	Headers HeaderGetter
}
```

### `Result`

Result describes a rate-limit check. Applied is false when limiting is
disabled globally, for a custom rule, or by DisableTracking.

```go
type Result struct {
	Applied    bool
	Allowed    bool
	Key        string
	Path       string
	Rule       Rule
	RetryAfter int64
}
```

### `Rule`

Rule is a rate-limit window. Window is measured in whole seconds.

```go
type Rule struct {
	Window int64
	Max    int64
}
```

### `SecondaryIncrementer`

SecondaryIncrementer is the optional fixed-window atomic counter primitive.
Increment must create a missing counter with ttlSeconds and must not extend
that TTL on subsequent calls.

```go
type SecondaryIncrementer interface {
	Increment(context.Context, string, int64) (int64, error)
}
```

### `SecondaryOptions`

SecondaryOptions configures JSON parse diagnostics.

```go
type SecondaryOptions struct {
	Error func(string, error)
}
```

### `SecondaryStorage`

SecondaryStorage is reference implementation's string-valued cache contract. An empty
value represents a missing key.

```go
type SecondaryStorage interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string, int64) error
}
```

### `Storage`

Storage is the backward-compatible reference implementation storage contract. Set's
update argument is false when the key is first created and true thereafter.
ttlSeconds is the rule window selected for this request.

```go
type Storage interface {
	Get(context.Context, string) (*Record, error)
	Set(context.Context, string, Record, bool, int64) error
}
```

## Constructors and functions for `Storage`

### `NewSecondaryStore`

NewSecondaryStore wraps a reference implementation secondary storage implementation. If
storage also implements SecondaryIncrementer, the returned Storage also
implements AtomicStorage.

```go
func NewSecondaryStore(storage SecondaryStorage, options SecondaryOptions) Storage
```

