# План завершения `single-auth` как нативной Go-библиотеки

Дата пересмотра scope: 2026-08-11.

Этот документ заменяет one-to-one Vitest compatibility как критерий готовности. Frozen
Better Auth 1.6.26 остаётся источником требований и примеров edge cases, но
структура TypeScript test suite не копируется в Go.

Краткие обязательные правила для всех будущих реализаций и субагентов также
зафиксированы в корневом `AGENTS.md`; этот план остаётся подробным source of
truth для порядка работ и критериев приёмки.

## 0. Неподвижные правила реализации

- `better-auth-main/` сохраняется до завершения порта как read-only эталонный
  исходник. Его анализируют при переносе, но production Go code и `go test`
  никогда не читают его во время исполнения.
- Текущий результат — нативная Go server/library, а не переупаковка
  JavaScript. В поставляемом module graph нет Bun, Node, TypeScript runtime или
  JS compatibility layer.
- Drizzle, Prisma и Kysely не реализуются и не имитируются в Go. Их повторяющиеся
  upstream-тесты служат только источником SQL edge cases; применимые assertions
  входят в единый contract нативных adapters.
- Go server, protocols, native storage и migrations остаются чистым Go graph.
  Browser client и React, Next.js, Vue, Solid integrations поставляются
  отдельным Bun-пакетом из `clients/` и вызывают только Go HTTP API.
- CLI, Stripe, Polar и остальные billing/payment integrations исключены из
  scope и не входят в процент готовности.

## 1. Целевой продукт

`single-auth` — серверная auth-библиотека на Go с единым поведением для:

- `net/http`;
- нативного `fasthttp`;
- Fiber поверх `fasthttp`;
- memory, SQLite, PostgreSQL, MySQL, MSSQL и MongoDB;
- Redis как secondary storage;
- прямого Go API;
- отдельного browser client package с React, Next.js, Vue и Solid entrypoints.

Проверяется полное покрытие **уникальных применимых поведений** Better Auth:
wire contract, cookies, sessions, security, hooks, storage mutations,
transactions, migrations, OAuth/OIDC/SAML/SCIM/WebAuthn и поддерживаемые
server plugins.

Один идиоматичный table-driven Go test может покрывать несколько одинаковых
upstream leaf tests. Повторения одного adapter contract в Drizzle, Prisma и
Kysely не создают три разных требования к Go.

## 2. Что намеренно не входит

- Better Auth CLI;
- нативный typed/raw Go HTTP client; Go-код использует direct API или HTTP;
- JavaScript frameworks кроме React, Next.js, Vue и Solid;
- Svelte, Expo, Electron, Lynx, SvelteKit, SolidStart и TanStack integrations;
- Bun, Deno, Cloudflare Workers, Vite и esbuild package/runtime smoke;
- TypeScript declaration, inference и compiler-diagnostic tests;
- Playwright/browser harness как способ исполнения теста;
- публичные Drizzle, Prisma и Kysely compatibility adapters;
- Stripe и любые provider-specific billing/payment integrations, включая
  Polar billing, Creem, Dodo Payments и Autumn;
- Polar OAuth provider — исключён отдельным решением владельца;
- anonymous product telemetry и её publisher — исключены отдельным решением
  владельца; tracing/instrumentation и application logging остаются в scope.

Если исключённый browser/ORM тест содержит применимое серверное поведение, это
поведение переносится в обычный Go HTTP/storage test, а не сохраняет исходный
JS harness.

## 3. Жёсткое правило тестового контура

Обычный `go test ./...` должен работать с установленным только Go toolchain.

В `*_test.go` запрещены:

- запуск Bun, Node, npm, Vitest, Playwright или TypeScript;
- чтение `better-auth-main`;
- чтение любого `node_modules`;
- запуск `.ts`/`.js` oracle generator;
- проверка хеша живого JavaScript source tree;
- JS-only skip, выданный за Go coverage.

Go tests могут читать только versioned JSON/golden fixtures и Go-native test
assets. JSON — это данные, не исполняемый JS runtime.

Поведение извлекается прямым чтением сохранённого `better-auth-main`, а
результат переносится в versioned JSON/golden data или сразу в Go table tests.
JS/TS генераторы и runtime harnesses не являются частью Go-модуля.

## 4. Как теперь измеряется готовность

Старый показатель `passing upstream IDs / 10 835` остаётся историческим
аудитом источника и больше не является процентом готовности Go-библиотеки.

Новый source of truth — capability manifest. Одна запись описывает:

- стабильный Go capability ID;
- observable contract;
- применимые transports;
- применимые real storage backends;
- production Go source;
- Go test/function;
- статус `missing`, `partial` или `passing`;
- список upstream кейсов, из которых извлечено требование;
- причину исключения неприменимых ecosystem деталей.

Capability считается `passing`, только когда прошли все заявленные
transport/backend dimensions. Процент считается по capability, а не по числу
повторяющихся Vitest leaf tests.

## 5. Фактически реализованная основа

На текущем worktree уже есть:

- transport-neutral auth engine, dispatcher, request context и hooks;
- cookies, session lifecycle, origin/CSRF protection и rate limiting;
- `net/http`, `fasthttp` и Fiber adapters;
- memory, SQLite, PostgreSQL, MySQL, MSSQL, MongoDB и Redis adapters;
- Testcontainers suites для PostgreSQL, MySQL, MSSQL, MongoDB и Redis;
- email/password, account/session routes и direct Go calls;
- organization, API key, admin, SCIM, SSO, OAuth/OIDC provider, 2FA,
  passkey/WebAuthn, JWT, bearer, email OTP, magic link и другие server plugins;
- OAuth2, OIDC, SAML и WebAuthn primitives;
- browser/React/Next.js/Vue/Solid client package для публичного HTTP surface;
- PostgreSQL qualified schemas, serial references, JSONB/arrays,
  `LIKE`/`ILIKE` semantics и multi-query joins;
- independently audited API-key and SCIM behavior slices.

Наличие пакета не означает полного capability coverage. Stub endpoints,
неполные migrations и непроверенные backend-specific branches должны остаться
`partial` или `missing`.

## 6. Порядок реализации

### P0 — очистить Go contour

- [x] Удалить Go CLI.
- [x] Удалить Stripe package и Stripe typecheck consumer recoverable через
  Trash.
- [x] Исключить Polar из публичного OAuth provider registry.
- [x] Удалить anonymous telemetry package и publisher; сохранить отдельные
  tracing/instrumentation и logger packages.
- [x] Удалить Bun/Deno/Cloudflare/Vite/esbuild runtime smoke Go tests и их
  runtime fixtures recoverable через Trash.
- [x] Удалить из всех `*_test.go` запуск Bun/Node/TS, включая opt-in tests.
- [x] Удалить из всех `*_test.go` live-чтение `better-auth-main` и
  `node_modules`.
- [x] Убрать JS/browser/framework test harness из обычного Go package graph.
- [x] Удалить fake ORM packages/tests: Drizzle, Prisma и Kysely aliases;
  применимые DB assertions оставить только в native adapter contract.
- [x] Доказать clean-copy `go test ./...`, `go test -race ./...` и
  `go vet ./...` без Bun, upstream tree и node_modules.

Gate: root Go module герметичен и не знает о наличии JavaScript toolchain.

Gate подтверждён 2026-08-10: normal/race/vet прошли как в worktree, так и в
отдельной копии без `.git` и `better-auth-main`; вне эталонного upstream tree
нет JS/TS source, package manifests, Bun locks или `node_modules`.

### P1 — создать Go capability manifest

- [x] Проинвентаризировать публичные Go endpoints, direct APIs, plugins,
  storage operations и migrations.
- [x] Из upstream Better Auth tests извлечь уникальные применимые behaviors и
  дедуплицировать ORM/runtime/framework повторы.
- [x] Для каждой capability зафиксировать transports/backends и observable
  contracts/assertions.
- [x] Для каждой capability зафиксировать explicit `upstreamRefs` с точными
  source/test case substrings внутри сохранённого `better-auth-main`.
- [x] Отдельно перечислить исключённые ecosystem/billing capabilities с
  причиной.
- [x] Добавить генератор краткого отчёта по capability-группам.

Gate: любая цифра готовности воспроизводимо получается из Go capability
manifest; upstream leaf count рядом публикуется только как справочная история.

Gate обновлён 2026-08-11: `conformance/capability-map.json` содержит 38
уникальных Go capability-групп и 10 явных scope exclusions. Нативный
`go run ./internal/conformance/cmd/capability-report` валидирует ссылки и воспроизводит
snapshot: 38 `passing`, 0 `partial`, 0 `missing`, то есть 100% полностью
закрытых capability. Schema v2 дополнительно проверяет 38 structured observable
contracts, 76 assertion strings, 83 upstream references и 267 exact case substrings.
Опциональный `-upstream-root better-auth-main` физически сверяет эти пути/кейсы
с read-only snapshot; обычный Go test/report от snapshot не зависит. `partial` не
прибавляется к проценту.

### P2 — core auth и HTTP

- [x] Sign-up/sign-in/sign-out во всех credential/social ветках.
- [x] Email verification, password reset/change и account linking/unlinking.
- [x] Session create/get/list/update/revoke/revoke-all, refresh и cookie cache.
- [x] Account update/delete, server-only endpoints и endpoint conflicts.
- [x] Exact status/body/error/header/redirect/`Set-Cookie` contract.
- [x] Trusted proxy, dynamic base URL, origins, CSRF и open-redirect защита.
- [x] Rate limits, hooks, transaction boundaries и rollback semantics.
- [x] Одинаковый HTTP corpus на `net/http`, `fasthttp` и Fiber.

### P3 — native storage contract

Создать один дедуплицированный adapter contract и прогонять его напрямую над
каждым native backend.

Обязательные capability-группы:

- create/findOne/findMany/count/update/updateMany/delete/deleteMany;
- exact predicates, multi-clause predicates, `in`, comparisons,
  starts/ends/contains и case-insensitive behavior;
- sort, limit, offset и deterministic pagination;
- joins, relation aliases, plural model names и schema-qualified names;
- text, UUID и serial IDs плюс reference decoding;
- dates, booleans, JSON, string/number arrays and null semantics;
- unique constraints, affected rows и returned records;
- atomic consume/increment;
- transactions, rollback, cancellation и concurrency;
- schema create/inspect/migrate/index/foreign-key lifecycle.

Backend matrix:

- [x] memory;
- [x] SQLite;
- [x] PostgreSQL;
- [x] MySQL;
- [x] MSSQL;
- [x] MongoDB replica set;
- [x] Redis secondary storage.

Relational migration lifecycle закрыт 2026-08-10: публичные
`EnsureSchema`/`Auth.RunMigrations` используют общий inspect/additive reconcile
для SQLite, PostgreSQL, MySQL и MSSQL; initial create, partial-schema upgrade,
index/FK repair, повторный no-op и rollback policy прошли normal/race/vet и
real Testcontainers. MongoDB schema-less storage не входит в relational
migration capability.

Drizzle/Prisma/Kysely названия допустимы только внутри ссылок на сохранённый
upstream source. В Go production API и именах Go-тестов ORM compatibility
surface отсутствует; уникальные behaviors проверяются напрямую над native
backends.

### P4 — server plugins и протоколы

- [x] Organization: members, invitations, teams, access control и hooks.
- [x] API key: create/verify/update/list/delete, permissions and limits.
- [x] Admin: CRUD, roles/permissions, bans, sessions, impersonation,
  cross-plugin behavior и exact coverage всех 99 upstream cases.
- [x] Anonymous, username, phone, email OTP, magic link, bearer,
  multi-session, one-time token, custom session, MCP, SIWE, last-login-method
  и HIBP.
- [x] 2FA/TOTP/OTP, recovery, trust, lockout и concurrency.
- [x] Device authorization: client binding, polling, approval/deny, ownership,
  expiry, slow-down, concurrency и transport compatibility.
- [x] Passkey/WebAuthn registration/authentication and counters.
- [x] Generic OAuth, OAuth proxy/popup server behavior and account linking.
- [x] OAuth/OIDC provider authorization, token, introspection, revoke,
  registration, consent, PKCE and pairwise subjects.
- [x] SSO: OIDC discovery/domain assignment, social-callback assignment,
  configured SAML error routing, SAML validation/bindings и все 17 публичных
  HTTP-операций.
- [x] SCIM provider management and user CRUD/PATCH, bearer auth and
  transactional hooks.
- [x] JWT/JWKS rotation, MCP server, OpenAPI, CAPTCHA, HIBP and SIWE.

OpenAPI 3.1 capability закрыта отдельной exact-coverage картой всех 29
применимых upstream cases, включая core/plugin endpoints и все transports.

Payment/billing plugins не входят в этот этап и не учитываются в готовности.

### P5 — удаление native Go client

- [x] Удалить core typed/raw HTTP client и общий remote-client helper.
- [x] Удалить plugin-specific remote clients, локальные client façades и их
  compile/runtime fixtures recoverable через Trash.
- [x] Исключить native Go client из capability denominator и зафиксировать
  решение отдельным scope exclusion.
- [x] Сохранить прямой Go API, публичные HTTP routes и отдельный JavaScript
  package как поддерживаемые способы вызова.

### P5B — Browser и framework clients

- [x] Общий credentialed browser client и dynamic endpoint proxy.
- [x] React, Vue и Solid reactive session adapters.
- [x] Next.js Fetch handler, remote Go proxy и server-session helpers.
- [x] Bun lint, typecheck, unit tests, declarations и ESM build.
- [x] Live client lifecycle против native Go HTTP server.

### P6 — public API и release hardening

- [ ] Удалить временные compatibility packages из public module graph.
- [ ] Выбрать канонический module import path, сохранив имя `single-auth`.
- [ ] Добавить examples для трёх transports и native databases.
- [ ] Документировать cookies/proxy/origin/secrets/migrations/plugins.
- [ ] CI: format, vet, normal, race, Testcontainers, fuzz smoke and clean copy.
- [ ] Security tests: malformed inputs, replay, token rotation, leaks,
  cancellation and bounded resources.
- [ ] License/NOTICE and Better Auth attribution.

## 7. Workflow любой capability

1. Выделить уникальное observable поведение, а не имя upstream test.
2. Найти все upstream cases, которые это поведение иллюстрируют.
3. Отделить JS/ORM/framework detail от применимого server/storage contract.
4. Реализовать production behavior.
5. Написать идиоматичный Go test с полными assertions.
6. Прогнать все применимые transports/backends.
7. Выполнить normal, race, vet и real-service Testcontainers при необходимости.
8. Провести независимый review поведения и негативных веток.
9. Только после этого поставить capability `passing`.

Запрещено:

- считать наличие package или endpoint descriptor завершённой реализацией;
- писать test-only shim вместо production behavior;
- раздувать процент повторяющимися ORM или transport wrappers;
- исполнять JS из Go tests;
- требовать upstream source tree или node_modules для `go test`;
- считать исключённый ecosystem test незакрытым Go behavior;
- скрывать настоящий server/storage gap пометкой «не применимо».

## 8. Definition of Done

`single-auth` готов, когда:

1. capability manifest не содержит `missing` или `partial` в заявленном
   Go-server scope;
2. каждый HTTP behavior проходит на `net/http`, `fasthttp` и Fiber;
3. native storage contract проходит на всех заявленных real backends;
4. migrations и cross-runtime database round trips доказаны;
5. `go test ./...` и `go test -race ./...` проходят без JS toolchain,
   upstream source tree и node_modules;
6. в Go tests нет JS execution/source dependencies;
7. public API не содержит Stripe/billing, Polar или TS ORM compatibility
   abstractions;
8. examples, compatibility matrix, security checks and release CI завершены.
