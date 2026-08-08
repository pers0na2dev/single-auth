export type NextJsFetchHandler = (request: Request) => Promise<Response>;

export type NextJsHandlerInput =
	| { handler: NextJsFetchHandler }
	| NextJsFetchHandler;

export interface NextJsHandlers {
	GET: NextJsFetchHandler;
	POST: NextJsFetchHandler;
	PATCH: NextJsFetchHandler;
	PUT: NextJsFetchHandler;
	DELETE: NextJsFetchHandler;
}

/**
 * Adapts a Fetch handler to the named exports expected by a Next.js App
 * Router route. This intentionally matches Better Auth's public adapter.
 */
export function toNextJsHandler(auth: NextJsHandlerInput): NextJsHandlers {
	const handler: NextJsFetchHandler = async (request) =>
		"handler" in auth ? auth.handler(request) : auth(request);
	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		PUT: handler,
		DELETE: handler,
	};
}

export type NextJsHeaderSource =
	| HeadersInit
	| (() => HeadersInit | Promise<HeadersInit>);

export type NextJsProxyHeaderSource =
	| HeadersInit
	| ((request: Request) => HeadersInit | Promise<HeadersInit>);

export interface NextJsProxyOptions {
	/** Base URL of the Go auth API, normally ending in `/api/auth`. */
	authURL: string | URL;
	/** Path where the catch-all Next route is mounted. Defaults to `/api/auth`. */
	basePath?: string;
	fetch?: typeof globalThis.fetch;
	/** Extra non-forwarding upstream headers, optionally derived per request. */
	headers?: NextJsProxyHeaderSource;
	/**
	 * Trusted proxy and client-IP headers derived by server-owned code. Configure
	 * this when the Go rate limiter runs behind Next; never copy an unsanitized
	 * browser header unless the deployment edge guarantees that it overwrites it.
	 */
	forwardedHeaders?: NextJsProxyHeaderSource;
}

const hopByHopHeaders = new Set([
	"connection",
	"content-length",
	"host",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
]);

const decodedRepresentationHeaders = new Set([
	"accept-ranges",
	"content-digest",
	"content-encoding",
	"content-md5",
	"content-range",
	"digest",
	"etag",
	"repr-digest",
]);

const clientIPHeaders = new Set([
	"cf-connecting-ip",
	"fastly-client-ip",
	"true-client-ip",
	"x-client-ip",
	"x-real-ip",
]);

function isForwardingHeader(name: string): boolean {
	const normalized = name.toLowerCase();
	return (
		normalized === "forwarded" ||
		normalized.startsWith("x-forwarded-") ||
		clientIPHeaders.has(normalized)
	);
}

function connectionHeaderNames(headers: Headers): Set<string> {
	const result = new Set<string>();
	for (const value of (headers.get("connection") ?? "").split(",")) {
		const name = value.trim().toLowerCase();
		if (name) result.add(name);
	}
	return result;
}

function appendEndToEndHeaders(
	source: Headers,
	target: Headers,
	excluded?: ReadonlySet<string> | undefined,
): void {
	const connectionNames = connectionHeaderNames(source);
	source.forEach((value, name) => {
		const normalized = name.toLowerCase();
		if (
			hopByHopHeaders.has(normalized) ||
			connectionNames.has(normalized) ||
			excluded?.has(normalized) ||
			normalized === "set-cookie"
		) {
			return;
		}
		target.set(name, value);
	});
}

function removeForwardingHeaders(headers: Headers): void {
	for (const name of Array.from(headers.keys())) {
		if (isForwardingHeader(name)) headers.delete(name);
	}
}

function appendTrustedForwardingHeaders(
	source: Headers,
	target: Headers,
): void {
	source.forEach((value, name) => {
		if (isForwardingHeader(name)) target.set(name, value);
	});
}

function applyPublicOrigin(headers: Headers, origin: string | URL): void {
	const publicURL = new URL(origin);
	if (publicURL.protocol !== "http:" && publicURL.protocol !== "https:") {
		throw new TypeError(
			`single-auth next-js: unsupported public origin protocol ${publicURL.protocol}`,
		);
	}
	if (publicURL.username || publicURL.password) {
		throw new TypeError("single-auth next-js: public origin cannot contain credentials");
	}
	headers.set("x-forwarded-host", publicURL.host);
	headers.set("x-forwarded-proto", publicURL.protocol.replace(/:$/, ""));
}

async function resolveHeaderSource(source: NextJsHeaderSource): Promise<Headers> {
	const value = typeof source === "function" ? await source() : source;
	return new Headers(value);
}

async function resolveProxyHeaderSource(
	source: NextJsProxyHeaderSource,
	request: Request,
): Promise<Headers> {
	const value = typeof source === "function" ? await source(request) : source;
	return new Headers(value);
}

function normalizeBasePath(path: string): string {
	const withLeadingSlash = path.startsWith("/") ? path : `/${path}`;
	const normalized = withLeadingSlash.replace(/\/{2,}/g, "/");
	return normalized === "/" ? "" : normalized.replace(/\/$/, "");
}

function appendURLPath(basePath: string, suffix: string): string {
	const base = basePath === "/" ? "" : basePath.replace(/\/$/, "");
	const tail = suffix === "/" ? "" : suffix.replace(/^\//, "");
	return `${base}/${tail}`.replace(/\/{2,}/g, "/") || "/";
}

function proxyTargetURL(
	authURL: string | URL,
	requestURL: string,
	basePath: string,
): URL {
	const target = new URL(authURL);
	const incoming = new URL(requestURL);
	let suffix = incoming.pathname;
	if (basePath && incoming.pathname === basePath) {
		suffix = "";
	} else if (basePath && incoming.pathname.startsWith(`${basePath}/`)) {
		suffix = incoming.pathname.slice(basePath.length);
	}
	target.pathname = appendURLPath(target.pathname, suffix);
	target.search = incoming.search;
	target.hash = "";
	return target;
}

function splitSetCookieHeader(setCookie: string): string[] {
	if (!setCookie) return [];
	const result: string[] = [];
	let start = 0;
	let index = 0;
	while (index < setCookie.length) {
		if (setCookie[index] === ",") {
			let cursor = index + 1;
			while (cursor < setCookie.length && setCookie[cursor] === " ") cursor++;
			while (
				cursor < setCookie.length &&
				setCookie[cursor] !== "=" &&
				setCookie[cursor] !== ";" &&
				setCookie[cursor] !== ","
			) {
				cursor++;
			}
			if (setCookie[cursor] === "=") {
				const part = setCookie.slice(start, index).trim();
				if (part) result.push(part);
				start = index + 1;
				while (start < setCookie.length && setCookie[start] === " ") start++;
				index = start;
				continue;
			}
		}
		index++;
	}
	const last = setCookie.slice(start).trim();
	if (last) result.push(last);
	return result;
}

type ExtendedHeaders = Headers & {
	getSetCookie?: () => string[];
	getAll?: (name: string) => string[];
	raw?: () => Record<string, string[] | undefined>;
};

function getSetCookieHeaders(headers: Headers): string[] {
	const extended = headers as ExtendedHeaders;
	const fromSetCookie = extended.getSetCookie?.();
	if (fromSetCookie && fromSetCookie.length > 0) {
		return fromSetCookie.flatMap(splitSetCookieHeader);
	}
	const fromGetAll = extended.getAll?.("set-cookie");
	if (fromGetAll && fromGetAll.length > 0) {
		return fromGetAll.flatMap(splitSetCookieHeader);
	}
	const fromRaw = extended.raw?.()["set-cookie"];
	if (fromRaw && fromRaw.length > 0) {
		return fromRaw.flatMap(splitSetCookieHeader);
	}
	return splitSetCookieHeader(headers.get("set-cookie") ?? "");
}

function proxyResponse(upstream: Response): Response {
	const headers = new Headers();
	appendEndToEndHeaders(
		upstream.headers,
		headers,
		upstream.headers.has("content-encoding")
			? decodedRepresentationHeaders
			: undefined,
	);
	for (const cookie of getSetCookieHeaders(upstream.headers)) {
		headers.append("set-cookie", cookie);
	}
	return new Response(upstream.body, {
		status: upstream.status,
		statusText: upstream.statusText,
		headers,
	});
}

/**
 * Creates a Fetch handler that transparently proxies a Next catch-all route to
 * the native Go auth HTTP API.
 */
export function createNextJsProxyHandler(
	options: NextJsProxyOptions,
): NextJsFetchHandler {
	const authURL = new URL(options.authURL);
	const basePath = normalizeBasePath(options.basePath ?? "/api/auth");
	const fetchImplementation = options.fetch ?? globalThis.fetch;
	if (typeof fetchImplementation !== "function") {
		throw new TypeError("single-auth next-js: fetch is unavailable");
	}

	return async (request) => {
		const target = proxyTargetURL(authURL, request.url, basePath);
		const headers = new Headers();
		appendEndToEndHeaders(request.headers, headers);
		// Do not let a browser choose the public origin used by DynamicBaseURL.
		// Reconstruct the immediate public hop and allow only the server-owned
		// `options.headers` source below to override it deliberately.
		removeForwardingHeaders(headers);
		applyPublicOrigin(headers, request.url);
		if (options.headers !== undefined) {
			const extraHeaders = await resolveProxyHeaderSource(
				options.headers,
				request,
			);
			removeForwardingHeaders(extraHeaders);
			appendEndToEndHeaders(extraHeaders, headers);
		}
		if (options.forwardedHeaders !== undefined) {
			appendTrustedForwardingHeaders(
				await resolveProxyHeaderSource(options.forwardedHeaders, request),
				headers,
			);
		}
		// Server-side Fetch implementations decode gzip/br bodies but commonly
		// retain Content-Encoding. Request identity so the rebuilt response body
		// and metadata cannot disagree; proxyResponse also handles non-compliant
		// upstreams that ignore this preference.
		headers.set("accept-encoding", "identity");
		const init: RequestInit & { duplex?: "half" } = {
			method: request.method,
			headers,
			cache: "no-store",
			redirect: "manual",
			signal: request.signal,
		};
		if (request.method !== "GET" && request.method !== "HEAD" && request.body) {
			init.body = request.body;
			init.duplex = "half";
		}
		return proxyResponse(await fetchImplementation(target, init));
	};
}

export type NextCookieSameSite = "lax" | "strict" | "none" | boolean;
export type NextCookiePriority = "low" | "medium" | "high";

export interface NextCookieOptions {
	domain?: string;
	expires?: Date;
	httpOnly?: boolean;
	maxAge?: number;
	partitioned?: boolean;
	path?: string;
	priority?: NextCookiePriority;
	sameSite?: NextCookieSameSite;
	secure?: boolean;
}

export interface NextCookieStore {
	set(name: string, value: string, options?: NextCookieOptions): unknown;
}

export type NextCookieStoreSource =
	| NextCookieStore
	| (() => NextCookieStore | Promise<NextCookieStore>);

export interface ApplyNextResponseCookiesOptions {
	cookies?: NextCookieStoreSource;
}

interface ParsedCookie {
	name: string;
	value: string;
	options: NextCookieOptions;
}

function decodeCookieValue(value: string): string {
	let unquoted = value;
	if (
		value.length >= 2 &&
		((value.startsWith('"') && value.endsWith('"')) ||
			(value.startsWith("'") && value.endsWith("'")))
	) {
		unquoted = value.slice(1, -1).replace(/\\([\\"])/g, "$1");
	}
	try {
		return decodeURIComponent(unquoted);
	} catch {
		return unquoted;
	}
}

function parseSetCookie(cookie: string): ParsedCookie | undefined {
	const [nameValue = "", ...attributes] = cookie
		.split(";")
		.map((part) => part.trim());
	const separator = nameValue.indexOf("=");
	if (separator <= 0) return undefined;
	const name = nameValue.slice(0, separator).trim();
	if (!name) return undefined;
	const options: NextCookieOptions = {};
	for (const attribute of attributes) {
		const attributeSeparator = attribute.indexOf("=");
		const rawName =
			attributeSeparator < 0
				? attribute
				: attribute.slice(0, attributeSeparator);
		const rawValue =
			attributeSeparator < 0 ? "" : attribute.slice(attributeSeparator + 1);
		switch (rawName.trim().toLowerCase()) {
			case "domain":
				if (rawValue) options.domain = rawValue.trim();
				break;
			case "expires": {
				const expires = new Date(rawValue.trim());
				if (!Number.isNaN(expires.getTime())) options.expires = expires;
				break;
			}
			case "httponly":
				options.httpOnly = true;
				break;
			case "max-age": {
				const maxAge = Number.parseInt(rawValue.trim(), 10);
				if (Number.isFinite(maxAge)) options.maxAge = maxAge;
				break;
			}
			case "partitioned":
				options.partitioned = true;
				break;
			case "path":
				if (rawValue) options.path = rawValue.trim();
				break;
			case "priority": {
				const priority = rawValue.trim().toLowerCase();
				if (priority === "low" || priority === "medium" || priority === "high") {
					options.priority = priority;
				}
				break;
			}
			case "samesite": {
				const sameSite = rawValue.trim().toLowerCase();
				if (sameSite === "lax" || sameSite === "strict" || sameSite === "none") {
					options.sameSite = sameSite;
				}
				break;
			}
			case "secure":
				options.secure = true;
				break;
		}
	}
	return {
		name,
		value: decodeCookieValue(nameValue.slice(separator + 1)),
		options,
	};
}

type NextHeadersModule = typeof import("next/headers.js");

let nextHeadersModulePromise: Promise<NextHeadersModule> | undefined;

function loadNextHeadersModule(): Promise<NextHeadersModule> {
	nextHeadersModulePromise ??= import("next/headers.js").catch((error: unknown) => {
		nextHeadersModulePromise = undefined;
		throw error;
	});
	return nextHeadersModulePromise;
}

function unavailableNextContext(error: unknown): boolean {
	if (!(error instanceof Error)) return false;
	const errorWithCode = error as Error & { code?: string };
	return (
		errorWithCode.code === "ERR_MODULE_NOT_FOUND" ||
		error.message.startsWith("`cookies` was called outside a request scope.") ||
		error.message.includes("Cannot find module") ||
		error.message.includes("outside a request scope")
	);
}

async function resolveCookieStore(
	source: NextCookieStoreSource | undefined,
): Promise<NextCookieStore | undefined> {
	if (source !== undefined) {
		return typeof source === "function" ? await source() : source;
	}
	try {
		const { cookies } = await loadNextHeadersModule();
		return (await cookies()) as NextCookieStore;
	} catch (error) {
		if (unavailableNextContext(error)) return undefined;
		throw error;
	}
}

/** Copies every Set-Cookie line from a Go response into Next's cookie store. */
export async function applyNextResponseCookies(
	response: Response | Headers,
	options: ApplyNextResponseCookiesOptions = {},
): Promise<void> {
	const headers = response instanceof Headers ? response : response.headers;
	const cookieHeaders = getSetCookieHeaders(headers);
	if (cookieHeaders.length === 0) return;
	const cookieStore = await resolveCookieStore(options.cookies);
	if (!cookieStore) return;
	for (const cookieHeader of cookieHeaders) {
		const cookie = parseSetCookie(cookieHeader);
		if (!cookie) continue;
		try {
			cookieStore.set(cookie.name, cookie.value, cookie.options);
		} catch {
			// Next.js rejects writes from pure Server Components. The caller still
			// receives the session result, matching the upstream integration.
		}
	}
}

export interface NextSessionResult<
	TSession = Record<string, unknown>,
	TUser = Record<string, unknown>,
> {
	session: TSession;
	user: TUser;
	needsRefresh?: boolean;
}

export interface GetNextSessionOptions {
	authURL: string | URL;
	fetch?: typeof globalThis.fetch;
	/** Explicit request headers; omitted uses request-scoped `next/headers`. */
	headers?: NextJsHeaderSource;
	/** Optional writable cookie store for refreshed session cookies. */
	cookies?: NextCookieStoreSource;
	/** Public browser origin forwarded to a Go DynamicBaseURL configuration. */
	publicOrigin?: string | URL;
	/**
	 * Trusted proxy/IP headers supplied by server-owned code. Incoming request
	 * forwarding headers are removed before this source is applied.
	 */
	forwardedHeaders?: NextJsHeaderSource;
}

async function nextRequestHeaders(
	source: NextJsHeaderSource | undefined,
): Promise<{ headers: Headers; dynamic: boolean }> {
	if (source !== undefined) {
		return { headers: await resolveHeaderSource(source), dynamic: false };
	}
	const { headers } = await loadNextHeadersModule();
	return { headers: new Headers(await headers()), dynamic: true };
}

function sessionEndpointURL(authURL: string | URL): URL {
	const endpoint = new URL(authURL);
	endpoint.pathname = appendURLPath(endpoint.pathname, "/get-session");
	endpoint.hash = "";
	return endpoint;
}

/**
 * Reads the current Go session from a Server Component, Server Action, or
 * another Next server context. Pure RSC reads suppress both session refresh
 * and cookie-cache writes because RSC cannot commit response cookies.
 */
export async function getNextSession<
	TResult = NextSessionResult,
>(options: GetNextSessionOptions): Promise<TResult | null> {
	const fetchImplementation = options.fetch ?? globalThis.fetch;
	if (typeof fetchImplementation !== "function") {
		throw new TypeError("single-auth next-js: fetch is unavailable");
	}
	const resolved = await nextRequestHeaders(options.headers);
	const isRSC = resolved.headers.get("RSC") === "1";
	const isServerAction = Boolean(resolved.headers.get("next-action"));
	const isPureRSC = isRSC && !isServerAction;
	const endpoint = sessionEndpointURL(options.authURL);
	if (isPureRSC) {
		endpoint.searchParams.set("disableRefresh", "true");
		endpoint.searchParams.set("disableCookieCache", "true");
	}
	const requestHeaders = new Headers();
	appendEndToEndHeaders(resolved.headers, requestHeaders);
	removeForwardingHeaders(requestHeaders);
	if (options.publicOrigin !== undefined) {
		applyPublicOrigin(requestHeaders, options.publicOrigin);
	}
	if (options.forwardedHeaders !== undefined) {
		appendEndToEndHeaders(
			await resolveHeaderSource(options.forwardedHeaders),
			requestHeaders,
		);
	}
	const response = await fetchImplementation(endpoint, {
		method: "GET",
		headers: requestHeaders,
		cache: "no-store",
		redirect: "manual",
	});
	if (!response.ok) {
		throw new Error(
			`single-auth next-js: get-session returned HTTP ${response.status}`,
		);
	}
	if (!isPureRSC) {
		await applyNextResponseCookies(
			response,
			options.cookies === undefined ? {} : { cookies: options.cookies },
		);
	}
	if (response.status === 204) return null;
	const body = await response.text();
	if (!body.trim()) return null;
	return JSON.parse(body) as TResult | null;
}
