# План завершения Go-порта `single-auth`

Дата актуализации: 2026-08-11.

Этот документ — рабочий backlog текущего Go milestone. Источником машинно
проверяемого статуса является `conformance/capability-map.json`; эталоном
поведения остаётся read-only дерево `better-auth-main/`.

## 1. Зафиксированный scope

Цель — нативная Go-библиотека с package name `singleauth` и module path
`github.com/pers0na2dev/single-auth`, которая переносит применимые к Go server-side возможности
Better Auth и поддерживает:

- `net/http`;
- прямой `fasthttp`;
- Fiber;
- memory, SQLite, PostgreSQL, MySQL, MSSQL, MongoDB и Redis там, где backend
  применим;
- отдельный browser client package с React, Next.js, Vue и Solid integrations;
- Testcontainers для реальных серверных хранилищ и межсервисных E2E.

Production-код и обычные Go-тесты не должны запускать или читать JavaScript/TS
runtime. Frozen JSON fixtures допустимы только как данные с зафиксированным
происхождением; `better-auth-main/` нужен разработчику для сверки, но не
потребителю Go module и не обычному `go test`.

На 2026-08-11 browser, React, Next.js, Vue и Solid package проходит 28
Bun-теста, declaration/ESM build, packed-export smoke и live lifecycle против
Go server.

Не входят в текущий milestone:

- CLI;
- нативный typed/raw Go HTTP client;
- JavaScript framework integrations кроме React, Next.js, Vue и Solid;
- billing/payment integrations, включая Stripe и Polar;
- anonymous product telemetry и её publisher; tracing/instrumentation и
  application logging остаются в scope;
- Cloudflare Workers, Bun, Deno, Vite, esbuild и browser-runtime smoke;
- TypeScript compiler/type-inference contracts;
- искусственные Drizzle, Prisma и Kysely packages или compatibility adapters.

Повторяющиеся upstream ORM suites используются только как источник
наблюдаемого DB-поведения. В Go это поведение доказывается один раз на каждом
нативном adapter.

## 2. Текущий подтверждённый статус

Последний зелёный capability report:

| Категория | Passing | Partial | Missing | Всего | Готовность |
|---|---:|---:|---:|---:|---:|
| Core HTTP | 8 | 0 | 0 | 8 | 100% |
| Transports | 3 | 0 | 0 | 3 | 100% |
| Native storage | 9 | 0 | 0 | 9 | 100% |
| Protocols/plugins | 18 | 0 | 0 | 18 | 100% |
| **Итого** | **38** | **0** | **0** | **38** | **100%** |

Счёт повышается только после реализации observable contract, обычных тестов,
race-проверки применимого пакета, `go vet` и проверки ссылок capability map.
Наличие package или endpoint без закрытой матрицы не считается `passing`.

## 3. Что уже закрыто

### 3.1 Герметичный Go-контур

- Вне `better-auth-main/` нет JS/TS source, package manifests, Bun locks и
  `node_modules`.
- Go tests не запускают Bun/Node и не читают локальный upstream source tree.
- Default capability report работает без `better-auth-main/`; opt-in сверка
  ссылок выполняется отдельно.
- Правила scope и запрет возврата не-Go зависимостей зафиксированы в
  `AGENTS.md`, `README.md` и [плане реализации](implementation-plan.md).

### 3.2 Transports и storage

- `net/http`, прямой `fasthttp` и Fiber закрыты общей transport contract
  матрицей.
- Memory, SQLite, PostgreSQL, MySQL, MSSQL, MongoDB и Redis реализованы
  нативными Go adapters.
- Миграции SQLite/PostgreSQL/MySQL/MSSQL закрывают initial create, additive
  upgrade частичной схемы, indexes, foreign keys, повторный no-op и
  backend-specific rollback policy.
- PostgreSQL/MySQL/MSSQL/MongoDB/Redis проверяются реальными контейнерами.
- Публичный `Auth.RunMigrationsContext` делегирует миграции adapter-у.

Ограничение SQLite: foreign key для уже существующей колонки нельзя добавить
metadata-only через `ALTER TABLE`; он создаётся inline при добавлении новой
колонки. Полный rebuild существующей таблицы остаётся отдельной осознанной
операцией.

### 3.3 Core и client boundaries

- Email/password, session lifecycle, cookies, CSRF/origin, rate limiting,
  account/session primitives и transport-neutral dispatcher реализованы.
- Account/social linking полностью закрывает list/info/link/unlink/token,
  owner/provider scoping, trusted/implicit-link policy, encrypted cookies и
  tokens, refresh semantics, rollback, replay/concurrency и все transports.
- Go callers используют transport-neutral direct API или публичные HTTP routes;
  отдельный native Go HTTP client намеренно удалён.
- Browser, React, Next.js, Vue и Solid integrations вызывают тот же публичный
  HTTP surface из изолированного `clients/` package и имеют отдельный Bun gate.
- Two-factor server capability полностью закрывает enrollment, TOTP/OTP,
  backup codes, trust-device, passwordless/custom storage, lockout, replay,
  concurrency и cross-sign-in enforcement.
- OpenAPI 3.1 полностью закрывает 29 применимых upstream schema cases,
  registered core/plugin routes и все transports.
- Device authorization полностью закрывает client binding, polling states,
  ownership, approval/deny, expiry, custom options и concurrent redemption.
- Admin полностью закрывает 99 upstream cases: users, permissions, roles,
  bans, sessions, impersonation, security и cross-plugin integration.
- Social provider registry полностью закрывает 34 применимых built-in
  provider-а: inventory, authorization/token/refresh requests, profile mapping,
  redirects, PKCE, nonce, JWT/JWKS и provider-specific security policy.
- OIDC provider полностью закрывает 51 применимый upstream-кейс и три unit
  контракта: discovery, registration, authorization, consent, token, refresh,
  userinfo, prompt/max-age, PKCE, client auth, replay и end-session на всех
  трёх HTTP transports.
- Organization server полностью закрывает CRUD, invitations, members, teams,
  hooks, tenant boundaries, dynamic/custom roles, anti-escalation, limits,
  cascade/compensation, concurrency и все три transports.
- OAuth authorization server полностью закрывает authorization/consent,
  PKCE, public/confidential clients, client lifecycle, auth-code,
  client-credentials, refresh rotation, userinfo, introspection, revocation,
  opaque/JWT tokens, memory/SQLite и все три transports.
- Остальные Go-native server plugins закрыты единым normal/race/vet срезом:
  bearer, anonymous, custom session, email OTP, magic link, MCP, one-time
  token, phone, SIWE, username, multi-session, last-login-method и HIBP.

### 3.4 Уже принятые protocol/plugin возможности

Полностью приняты SAML primitives, OAuth2/OIDC primitives, WebAuthn,
passkey server lifecycle, API keys, SCIM, CAPTCHA server integration,
organization и SSO, включая social-callback organization assignment,
настраиваемый SAML error URL и все 17 публичных SSO HTTP operations.

## 4. Активная работа

В capability manifest больше нет `partial` или `missing`: все 38 применимые
Go capability закрыты. Активная работа относится к pre-1.0 release hardening,
публикации module, документации, CI и повторяемости полного regression/E2E
набора, а не к незакрытому observable behavior.

## 5. Закрытые последние capability

### SSO

- SAML SLO и session records закрывают SP-initiated и IdP-initiated logout,
  signatures, replay, expiry и session invalidation.
- Signed/encrypted assertions, OIDC callback/provider lifecycle, metadata,
  ACS и logout покрыты для persisted/default providers и применимых
  transports.
- Обычный social OAuth callback запускает SSO domain-based organization
  assignment после создания session; domain-verification policy и
  идемпотентность membership сохраняются.
- Unauthenticated SAML GET callback использует настроенный
  `OnAPIError.ErrorURL` и fallback `/error` только при отсутствии настройки.
- Все 17 публичных SSO операций закрыты server route/direct API coverage.

### Client boundary

- Native typed/raw Go client и plugin-specific remote façades удалены.
- Go applications используют direct API или обычный HTTP; browser и framework
  applications используют отдельно проверяемый `clients/` package.
- JS client readiness не увеличивает denominator нативных Go capabilities.

## 6. Обязательная тестовая матрица

После каждого независимого среза:

1. `go test` целевого package;
2. `go test -race` целевого package;
3. `go vet` целевого package;
4. `git diff --check` по затронутым файлам;
5. default capability report;
6. opt-in проверка upstream ссылок.

Перед изменением статуса capability на `passing`:

- позитивные, негативные и security cases;
- concurrency/replay/idempotency;
- `net/http`, `fasthttp`, Fiber для HTTP-visible behavior;
- memory и каждый применимый native storage backend;
- Testcontainers для PostgreSQL/MySQL/MSSQL/MongoDB/Redis;
- rollback/compensation при injected failures;
- отсутствие Bun/Node/JS runtime и чтения upstream во время обычного теста.

## 7. Финальные release gates

При текущих 38 из 38 capability в статусе `passing`:

1. `go test ./... -count=1`;
2. `go test -race ./... -count=1`;
3. `go vet ./...`;
4. полный Testcontainers E2E для заявленных server backends;
5. capability report без `partial` и `missing`;
6. upstream-reference validation в opt-in режиме;
7. проверка clean copy без `better-auth-main/`, JS toolchain и локальных
   caches;
8. физический scan: вне upstream нет JS/TS/package manifests/`node_modules`;
9. API/doc/examples/license review;
10. повторный полный run после устранения любых flakes.

## 8. Definition of Done

Go milestone завершён, только если одновременно:

- все 38 применимые capability имеют `status: passing`;
- каждый observable contract подтверждён исполняемым Go-тестом;
- normal, race, vet, transport, storage и Testcontainers gates зелёные;
- Go production и Go tests не требуют Bun, Node, TypeScript или upstream tree;
- `clients/` проходит собственные Bun lint, typecheck, test и ESM build gates;
- public Go API не содержит native remote client, billing, fake ORM или
  JS-runtime compatibility;
- migrations доступны как library API на всех заявленных relational backends;
- `net/http`, прямой `fasthttp` и Fiber дают одинаковое наблюдаемое
  поведение;
- README и compatibility report отделяют подтверждённые Go capabilities от
  отдельно проверяемого JavaScript ecosystem package.

После этого `better-auth-main/` можно оставить отдельным development reference
или вынести из поставляемого module artifact. Удалять его до завершения и
подтверждения compatibility нельзя.
