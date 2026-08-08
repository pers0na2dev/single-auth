import { beforeEach, describe, expect, it, mock } from "bun:test";
import * as nextIntegration from "../src/next-js/index.js";
import {
	applyNextResponseCookies,
	createNextJsProxyHandler,
	getNextSession,
	toNextJsHandler,
	type NextCookieOptions,
} from "../src/next-js/index.js";

interface CookieCall {
	name: string;
	value: string;
	options: NextCookieOptions | undefined;
}

let dynamicHeaders = new Headers();
const dynamicCookieCalls: CookieCall[] = [];

mock.module("next/headers.js", () => ({
	headers: async () => dynamicHeaders,
	cookies: async () => ({
		set(name: string, value: string, options?: NextCookieOptions) {
			dynamicCookieCalls.push({ name, value, options });
		},
	}),
}));

beforeEach(() => {
	dynamicHeaders = new Headers();
	dynamicCookieCalls.length = 0;
});

describe("toNextJsHandler", () => {
	it("exposes the upstream-compatible methods and passes requests through", async () => {
		const request = new Request("https://app.example/api/auth/session");
		const response = new Response("ok", { status: 201 });
		let received: Request | undefined;
		const handlers = toNextJsHandler({
			handler: async (value) => {
				received = value;
				return response;
			},
		});

		expect(Object.keys(handlers)).toEqual([
			"GET",
			"POST",
			"PATCH",
			"PUT",
			"DELETE",
		]);
		expect(handlers.GET).toBe(handlers.POST);
		expect(handlers.GET).toBe(handlers.PATCH);
		expect(handlers.GET).toBe(handlers.PUT);
		expect(handlers.GET).toBe(handlers.DELETE);
		expect(await handlers.GET(request)).toBe(response);
		expect(received).toBe(request);
	});

	it("accepts a bare Fetch handler and does not export nextCookies", async () => {
		const handlers = toNextJsHandler(async () => new Response("function"));
		expect(await handlers.POST(new Request("https://app.example"))).toBeInstanceOf(
			Response,
		);
		expect("nextCookies" in nextIntegration).toBeFalse();
	});
});

describe("createNextJsProxyHandler", () => {
	it("preserves the response and multiple cookies while filtering hop-by-hop headers", async () => {
		let receivedURL = "";
		let receivedInit: RequestInit | undefined;
		let receivedBody = "";
		const fetchMock = (async (input: RequestInfo | URL, init?: RequestInit) => {
			receivedURL = String(input);
			receivedInit = init;
			if (init?.body) receivedBody = await new Response(init.body).text();
			const headers = new Headers({
				Connection: "close, X-Upstream-Only",
				Location: "/after-sign-in",
				"X-Upstream-Only": "private",
				"X-Visible": "yes",
			});
			headers.append("Set-Cookie", "session=one; Path=/; HttpOnly");
			headers.append(
				"Set-Cookie",
				"cache=two; Path=/; Max-Age=300; SameSite=Lax",
			);
			return new Response("redirect-body", {
				status: 307,
				statusText: "Temporary Redirect",
				headers,
			});
		}) as typeof fetch;

		const handler = createNextJsProxyHandler({
			authURL: "https://go.example/internal/auth/",
			basePath: "/api/auth/",
			fetch: fetchMock,
			headers: async () => ({
				Authorization: "Bearer service-token",
				Connection: "X-Configured-Hop",
				"X-Forwarded-For": "203.0.113.99",
				"X-Configured-Hop": "remove",
				"X-Default": "configured",
			}),
		});
		const response = await handler(
			new Request(
				"https://app.example/api/auth/sign-in/email?callbackURL=%2Fdashboard",
				{
					method: "POST",
					body: JSON.stringify({ email: "ada@example.test" }),
					headers: {
						"Content-Type": "application/json",
						Connection: "keep-alive, X-Remove-Me",
						"Keep-Alive": "timeout=5",
						Forwarded: "host=evil.example;proto=http",
						"X-Forwarded-For": "203.0.113.66",
						"X-Forwarded-Host": "evil.example",
						"X-Forwarded-Proto": "http",
						"X-Real-IP": "203.0.113.67",
						"X-Remove-Me": "private",
						"X-Request": "visible",
					},
				},
			),
		);

		expect(receivedURL).toBe(
			"https://go.example/internal/auth/sign-in/email?callbackURL=%2Fdashboard",
		);
		expect(receivedInit?.method).toBe("POST");
		expect(receivedInit?.cache).toBe("no-store");
		expect(receivedInit?.redirect).toBe("manual");
		expect(receivedBody).toBe('{"email":"ada@example.test"}');
		const upstreamHeaders = new Headers(receivedInit?.headers);
		expect(upstreamHeaders.get("authorization")).toBe("Bearer service-token");
		expect(upstreamHeaders.get("x-default")).toBe("configured");
		expect(upstreamHeaders.get("x-request")).toBe("visible");
		expect(upstreamHeaders.get("connection")).toBeNull();
		expect(upstreamHeaders.get("keep-alive")).toBeNull();
		expect(upstreamHeaders.get("forwarded")).toBeNull();
		expect(upstreamHeaders.get("x-forwarded-for")).toBeNull();
		expect(upstreamHeaders.get("x-forwarded-host")).toBe("app.example");
		expect(upstreamHeaders.get("x-forwarded-proto")).toBe("https");
		expect(upstreamHeaders.get("x-real-ip")).toBeNull();
		expect(upstreamHeaders.get("x-remove-me")).toBeNull();
		expect(upstreamHeaders.get("x-configured-hop")).toBeNull();

		expect(response.status).toBe(307);
		expect(response.statusText).toBe("Temporary Redirect");
		expect(response.headers.get("location")).toBe("/after-sign-in");
		expect(response.headers.get("x-visible")).toBe("yes");
		expect(response.headers.get("connection")).toBeNull();
		expect(response.headers.get("x-upstream-only")).toBeNull();
		expect(
			(
				response.headers as Headers & { getSetCookie(): string[] }
			).getSetCookie(),
		).toEqual([
			"session=one; Path=/; HttpOnly",
			"cache=two; Path=/; Max-Age=300; SameSite=Lax",
		]);
		expect(await response.text()).toBe("redirect-body");
	});

	it("allows a server-owned forwarded origin override", async () => {
		let receivedHeaders = new Headers();
		const handler = createNextJsProxyHandler({
			authURL: "https://go.internal/api/auth",
			fetch: (async (_input, init) => {
				receivedHeaders = new Headers(init?.headers);
				return Response.json({ ok: true });
			}) as typeof fetch,
			forwardedHeaders: (request) => ({
				"X-Forwarded-For": request.headers.get("x-platform-client-ip") ?? "",
				"X-Forwarded-Host": "tenant.example",
				"X-Forwarded-Proto": "https",
			}),
		});

		await handler(
			new Request("http://internal-next/api/auth/get-session", {
				headers: {
					"X-Forwarded-For": "203.0.113.66",
					"X-Platform-Client-IP": "198.51.100.8",
				},
			}),
		);
		expect(receivedHeaders.get("x-forwarded-for")).toBe("198.51.100.8");
		expect(receivedHeaders.get("x-forwarded-host")).toBe("tenant.example");
		expect(receivedHeaders.get("x-forwarded-proto")).toBe("https");
	});

	it("does not relabel a transparently decoded upstream body as compressed", async () => {
		let upstreamAcceptEncoding = "";
		const payload = "native Go auth response";
		const compressed = Bun.gzipSync(payload);
		const upstream = Bun.serve({
			port: 0,
			fetch(request) {
				upstreamAcceptEncoding =
					request.headers.get("accept-encoding") ?? "";
				return new Response(compressed, {
					headers: {
						"Content-Encoding": "gzip",
						"Content-Length": String(compressed.byteLength),
						ETag: '"compressed-representation"',
					},
				});
			},
		});
		const handler = createNextJsProxyHandler({
			authURL: new URL("/api/auth", upstream.url),
		});
		const proxy = Bun.serve({ port: 0, fetch: handler });

		try {
			const response = await fetch(
				new URL("/api/auth/get-session", proxy.url),
			);
			expect(await response.text()).toBe(payload);
			expect(upstreamAcceptEncoding).toBe("identity");
			expect(response.headers.get("content-encoding")).toBeNull();
			expect(response.headers.get("content-length")).toBe(
				String(new TextEncoder().encode(payload).byteLength),
			);
			expect(response.headers.get("etag")).toBeNull();
		} finally {
			proxy.stop(true);
			upstream.stop(true);
		}
	});
});

describe("getNextSession", () => {
	it("uses explicit RSC headers and disables refresh and cookie cache", async () => {
		let receivedURL = "";
		let receivedHeaders = new Headers();
		const fetchMock = (async (input: RequestInfo | URL, init?: RequestInit) => {
			receivedURL = String(input);
			receivedHeaders = new Headers(init?.headers);
			return Response.json({
				session: { id: "session-1" },
				user: { id: "user-1" },
			});
		}) as typeof fetch;

		const result = await getNextSession<{
			session: { id: string };
			user: { id: string };
		}>({
			authURL: "https://go.example/api/auth/",
			fetch: fetchMock,
			headers: {
				Cookie: "single-auth.session_token=signed",
				RSC: "1",
				Connection: "X-Private",
				"X-Forwarded-For": "203.0.113.66",
				"X-Forwarded-Host": "evil.example",
				"X-Private": "remove",
			},
			publicOrigin: "https://tenant.example",
			forwardedHeaders: { "X-Forwarded-For": "198.51.100.8" },
		});

		const endpoint = new URL(receivedURL);
		expect(endpoint.pathname).toBe("/api/auth/get-session");
		expect(endpoint.searchParams.get("disableRefresh")).toBe("true");
		expect(endpoint.searchParams.get("disableCookieCache")).toBe("true");
		expect(receivedHeaders.get("cookie")).toBe(
			"single-auth.session_token=signed",
		);
		expect(receivedHeaders.get("connection")).toBeNull();
		expect(receivedHeaders.get("x-private")).toBeNull();
		expect(receivedHeaders.get("x-forwarded-host")).toBe("tenant.example");
		expect(receivedHeaders.get("x-forwarded-proto")).toBe("https");
		expect(receivedHeaders.get("x-forwarded-for")).toBe("198.51.100.8");
		expect(result?.session.id).toBe("session-1");
	});

	it("loads dynamic Next headers and applies response cookies for a server action", async () => {
		dynamicHeaders = new Headers({
			Cookie: "single-auth.session_token=signed",
			RSC: "1",
			"next-action": "action-id",
		});
		let receivedURL = "";
		const responseHeaders = new Headers();
		responseHeaders.append(
			"Set-Cookie",
			"session=renewed; Path=/; HttpOnly; SameSite=Lax",
		);
		const fetchMock = (async (input: RequestInfo | URL) => {
			receivedURL = String(input);
			return new Response(
				JSON.stringify({ session: { id: "session-2" }, user: { id: "user-2" } }),
				{ status: 200, headers: responseHeaders },
			);
		}) as typeof fetch;

		const result = await getNextSession({
			authURL: "https://go.example/api/auth",
			fetch: fetchMock,
		});

		const endpoint = new URL(receivedURL);
		expect(endpoint.searchParams.has("disableRefresh")).toBeFalse();
		expect(endpoint.searchParams.has("disableCookieCache")).toBeFalse();
		expect(result).not.toBeNull();
		expect(dynamicCookieCalls).toEqual([
			{
				name: "session",
				value: "renewed",
				options: { httpOnly: true, path: "/", sameSite: "lax" },
			},
		]);
	});

	it("applies refreshed cookies when request headers are supplied explicitly", async () => {
		const written: CookieCall[] = [];
		const responseHeaders = new Headers({
			"Set-Cookie": "session=explicit; Path=/; HttpOnly; SameSite=Lax",
		});
		const result = await getNextSession({
			authURL: "https://go.example/api/auth",
			headers: { Cookie: "session=old" },
			fetch: (async () =>
				new Response(
					JSON.stringify({
						session: { id: "session-explicit" },
						user: { id: "user-explicit" },
					}),
					{ headers: responseHeaders },
				)) as unknown as typeof fetch,
			cookies: {
				set(name, value, options) {
					written.push({ name, value, options });
				},
			},
		});

		expect(result).not.toBeNull();
		expect(written).toEqual([
			{
				name: "session",
				value: "explicit",
				options: { httpOnly: true, path: "/", sameSite: "lax" },
			},
		]);
	});

	it("returns null for an empty successful response and rejects HTTP failures", async () => {
		const emptyFetch = (async () =>
			new Response(null, { status: 204 })) as unknown as typeof fetch;
		expect(
			await getNextSession({
				authURL: "https://go.example/api/auth",
				fetch: emptyFetch,
				headers: {},
			}),
		).toBeNull();

		const failedFetch = (async () =>
			new Response("denied", { status: 401 })) as unknown as typeof fetch;
		expect(
			getNextSession({
				authURL: "https://go.example/api/auth",
				fetch: failedFetch,
				headers: {},
			}),
		).rejects.toThrow("get-session returned HTTP 401");
	});
});

describe("applyNextResponseCookies", () => {
	it("forwards every cookie and preserves robustly parsed attributes", async () => {
		const calls: CookieCall[] = [];
		const headers = new Headers();
		headers.append(
			"Set-Cookie",
			"session=hello%20world%3Dfoo; Path=/auth; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Max-Age=300; Secure; HttpOnly; SameSite=None; Partitioned; Priority=High",
		);
		headers.append(
			"Set-Cookie",
			"session=second; Path=/other, cache=two; Domain=.example.test; SameSite=Strict",
		);

		await applyNextResponseCookies(headers, {
			cookies: {
				set(name, value, options) {
					calls.push({ name, value, options });
				},
			},
		});

		expect(calls).toHaveLength(3);
		expect(calls[0]).toEqual({
			name: "session",
			value: "hello world=foo",
			options: {
				expires: new Date("Wed, 21 Oct 2037 07:28:00 GMT"),
				httpOnly: true,
				maxAge: 300,
				partitioned: true,
				path: "/auth",
				priority: "high",
				sameSite: "none",
				secure: true,
			},
		});
		expect(calls[1]).toEqual({
			name: "session",
			value: "second",
			options: { path: "/other" },
		});
		expect(calls[2]).toEqual({
			name: "cache",
			value: "two",
			options: { domain: ".example.test", sameSite: "strict" },
		});
	});

	it("continues after a cookie store rejects an individual write", async () => {
		const written: string[] = [];
		const headers = new Headers();
		headers.append("Set-Cookie", "first=1; Path=/");
		headers.append("Set-Cookie", "second=2; Path=/");
		await applyNextResponseCookies(headers, {
			cookies: {
				set(name) {
					if (name === "first") throw new Error("RSC is read-only");
					written.push(name);
				},
			},
		});
		expect(written).toEqual(["second"]);
	});
});
