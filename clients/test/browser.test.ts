import { describe, expect, test } from "bun:test";
import { atom } from "nanostores";
import { createAuthClient } from "../src/index.js";
import type {
	SignInSocialIDTokenUser,
	SingleAuthAccount,
} from "../src/client/types.js";
import { parseJSON } from "../src/client/parser.js";
import { getBaseURL, isSafeURLScheme } from "../src/client/url.js";

const json = (value: unknown, status = 200) =>
	new Response(JSON.stringify(value), {
		status,
		headers: { "content-type": "application/json" },
	});

const wait = (milliseconds = 20) =>
	new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

describe("browser client", () => {
	test("maps the typed API and generic escape hatch to credentialed HTTP requests", async () => {
		const requests: Array<{
			url: string;
			method: string;
			body: unknown;
			headers: Headers;
		}> = [];
		const client = createAuthClient({
			baseURL: "https://auth.example.test",
			fetchOptions: {
				customFetchImpl: async (input, init) => {
					requests.push({
						url: String(input),
						method: init?.method ?? "GET",
						body:
							typeof init?.body === "string"
								? JSON.parse(init.body)
								: init?.body,
						headers: new Headers(init?.headers),
					});
					return json({ success: true });
				},
			},
		});

		await client.signUp.email(
			{
				name: "Ada",
				email: "ada@example.test",
				password: "correct horse battery staple",
			},
			{ headers: { "x-request-id": "signup" } },
		);
		await client.signOut();
		await client.$call<{ ok: boolean }>(
			"/plugin/custom-action",
			{ value: 42 },
			{ headers: { "x-request-id": "plugin" } },
		);

		expect(requests[0]).toMatchObject({
			url: "https://auth.example.test/api/auth/sign-up/email",
			method: "POST",
			body: {
				name: "Ada",
				email: "ada@example.test",
				password: "correct horse battery staple",
			},
		});
		expect(requests[0]?.headers.get("x-request-id")).toBe("signup");
		expect(requests[1]).toMatchObject({
			url: "https://auth.example.test/api/auth/sign-out",
			method: "POST",
			body: {},
		});
		expect(requests[2]).toMatchObject({
			url: "https://auth.example.test/api/auth/plugin/custom-action",
			method: "POST",
			body: { value: 42 },
		});
		expect(requests[2]?.headers.get("x-request-id")).toBe("plugin");
		expect((client as unknown as { then?: unknown }).then).toBeUndefined();
		expect((client as unknown as { catch?: unknown }).catch).toBeUndefined();
		expect((client as unknown as { finally?: unknown }).finally).toBeUndefined();
	});

	test("honors explicit methods, empty POST mutations, and inline throw typing", async () => {
		const requests: Array<{ url: string; method: string }> = [];
		const client = createAuthClient({
			baseURL: "https://auth.example.test",
			fetchOptions: {
				customFetchImpl: async (input, init) => {
					const url = String(input);
					requests.push({
						url,
						method: init?.method ?? "GET",
					});
					return json(
						url.endsWith("/sign-out")
							? { success: true }
							: url.endsWith("/plugin/raw") ||
								  url.endsWith("/plugin/second-options")
								? { ok: true }
								: { status: true },
					);
				},
			},
		});

		await client.$call("/get-session", undefined, { method: "POST" });
		await client.updateUser({});
		await client.updateSession({});
		await client.deleteUser();
		const signedOut = await client.signOut({
			fetchOptions: { throw: true },
		});
		const custom = await client.$call<{ ok: boolean }>("/plugin/raw", {
			fetchOptions: { throw: true },
		});
		const secondOptions = await client.$call<{ ok: boolean }>(
			"/plugin/second-options",
			undefined,
			{ throw: true },
		);
		const success: boolean = signedOut.success;
		const customOK: boolean = custom.ok;
		const secondOptionsOK: boolean = secondOptions.ok;

		expect(success).toBe(true);
		expect(customOK).toBe(true);
		expect(secondOptionsOK).toBe(true);
		expect(requests).toEqual([
			{
				url: "https://auth.example.test/api/auth/get-session",
				method: "POST",
			},
			{
				url: "https://auth.example.test/api/auth/update-user",
				method: "POST",
			},
			{
				url: "https://auth.example.test/api/auth/update-session",
				method: "POST",
			},
			{
				url: "https://auth.example.test/api/auth/delete-user",
				method: "POST",
			},
			{
				url: "https://auth.example.test/api/auth/sign-out",
				method: "POST",
			},
			{
				url: "https://auth.example.test/api/auth/plugin/raw",
				method: "GET",
			},
			{
				url: "https://auth.example.test/api/auth/plugin/second-options",
				method: "GET",
			},
		]);
	});

	test("preserves explicit fetch-option bodies without corrupting them", async () => {
		const requests: Array<{ method: string; body: BodyInit | null | undefined }> = [];
		const client = createAuthClient({
			baseURL: "https://auth.example.test",
			fetchOptions: {
				customFetchImpl: async (_input, init) => {
					requests.push({ method: init?.method ?? "GET", body: init?.body });
					return json({ ok: true });
				},
			},
		});

		await client.$call("/plugin/object-body", undefined, {
			body: { value: 42 },
		});
		await client.$call("/plugin/string-body", undefined, {
			method: "POST",
			body: "plain text",
			headers: { "content-type": "text/plain" },
		});
		await client.$call(
			"/plugin/merged-body",
			{ first: 1 },
			{ body: { second: 2 } },
		);

		expect(requests.map((request) => request.method)).toEqual([
			"POST",
			"POST",
			"POST",
		]);
		expect(JSON.parse(String(requests[0]?.body))).toEqual({ value: 42 });
		expect(requests[1]?.body).toBe("plain text");
		expect(JSON.parse(String(requests[2]?.body))).toEqual({ first: 1, second: 2 });
	});

	test("exposes the native Go social, account, and reset contracts", async () => {
		const client = createAuthClient({ baseURL: "https://auth.example.test" });
		const assertContracts = async () => {
			await client.signUp.email({
				name: "Ada",
				email: "ada@example.test",
				password: "correct horse battery staple",
				image: "https://example.test/ada.png",
			});
			// @ts-expect-error Go accepts only a string image URL.
			await client.signUp.email({ name: "Ada", email: "ada@example.test", password: "password", image: 42 });
			const signedUp = await client.signUp.email({
				name: "Ada",
				email: "ada@example.test",
				password: "correct horse battery staple",
			});
			const signUpToken: string | null = signedUp.data!.token;
			void signUpToken;
			const signedIn = await client.signIn.email({
				email: "ada@example.test",
				password: "correct horse battery staple",
			});
			const signInToken: string = signedIn.data!.token;
			const signInUserID: string = signedIn.data!.user.id;
			void signInToken;
			void signInUserID;
			const invalidProviderUser: SignInSocialIDTokenUser = {
				// @ts-expect-error Go rejects non-string provider email values.
				email: 42,
			};
			void invalidProviderUser;
			await client.signIn.social({
				provider: "google",
				idToken: {
					token: "id-token",
					expiresAt: Date.now() + 60_000,
					user: {
						email: "ada@example.test",
						name: { firstName: "Ada", lastName: "Lovelace" },
					},
				},
			});
			const linked = await client.linkSocial({
				provider: "google",
				idToken: { token: "id-token", scopes: ["openid", "email"] },
			});
			const linkStatus: boolean | undefined = linked.data?.status;
			void linkStatus;
			await client.resetPassword({
				newPassword: "correct horse battery staple",
				query: { token: "reset-token" },
			});
			const accounts = await client.listAccounts();
			const scopes: string[] = accounts.data![0]!.scopes;
			void scopes;
			const accountSecretsAreUnknown: unknown extends SingleAuthAccount["accessToken"]
				? true
				: false = true;
			void accountSecretsAreUnknown;
			const changed = await client.changePassword({
				currentPassword: "old-password",
				newPassword: "new-password",
			});
			const changedToken: string | null = changed.data!.token;
			void changedToken;
		};
		void assertContracts;
		expect(client).toBeDefined();
	});

	test("deep-merges plugin actions and de-duplicates matching atom signals", async () => {
		const flag = atom(false);
		let callbacks = 0;
		const observedFlagValues: boolean[] = [];
		let stopListening = () => {};
		const client = createAuthClient({
			baseURL: "https://auth.example.test/api/auth",
			fetchOptions: { customFetchImpl: async () => json({ status: true }) },
			plugins: [
				{
					id: "first",
					getActions: (_fetch, store) => {
						stopListening = store.listen("flag", (value) => {
							observedFlagValues.push(value as boolean);
						});
						return { custom: { first: () => "first" as const } };
					},
					getAtoms: () => ({ flag }),
					atomListeners: [
						{
							signal: "flag",
							matcher: (path: string) => path === "/change-password",
							callback: () => callbacks++,
						},
					],
				},
				{
					id: "second",
					getActions: () => ({
						custom: { second: () => "second" as const },
					}),
					atomListeners: [
						{
							signal: "flag",
							matcher: (path: string) => path === "/change-password",
							callback: () => callbacks++,
						},
					],
				},
			] as const,
		});

		expect(client.custom.first()).toBe("first");
		expect(client.custom.second()).toBe("second");
		await client.changePassword({
			currentPassword: "old-password",
			newPassword: "new-password",
		});
		await wait();
		expect(flag.get()).toBe(true);
		expect(callbacks).toBe(1);
		expect(observedFlagValues).toEqual([false, true]);
		stopListening();
		flag.set(false);
		expect(observedFlagValues).toEqual([false, true]);
	});

	test("keeps stale session data on server errors and clears it on 401", async () => {
		const previousWindow = globalThis.window;
		Object.defineProperty(globalThis, "window", {
			configurable: true,
			writable: true,
			value: {
				location: { origin: "https://app.example.test", href: "" },
				addEventListener() {},
				removeEventListener() {},
			},
		});
		let responseIndex = 0;
		const responses = [
			json({
				user: {
					id: "user-1",
					name: "Ada",
					email: "ada@example.test",
					emailVerified: true,
					createdAt: "2026-01-01T00:00:00.000Z",
					updatedAt: "2026-01-01T00:00:00.000Z",
				},
				session: {
					id: "session-1",
					userId: "user-1",
					token: "secret",
					expiresAt: "2026-02-01T00:00:00.000Z",
					createdAt: "2026-01-01T00:00:00.000Z",
					updatedAt: "2026-01-01T00:00:00.000Z",
				},
			}),
			json({ code: "FAILED_TO_GET_SESSION", message: "temporary" }, 500),
			json({ code: "SESSION_EXPIRED", message: "expired" }, 401),
		];
		try {
			const client = createAuthClient({
				baseURL: "https://auth.example.test",
				fetchOptions: {
					customFetchImpl: async () => responses[responseIndex++]!,
				},
			});
			const unsubscribe = client.useSession.subscribe(() => {});
			await wait();
			const original = client.useSession.get().data;
			expect(original?.user.id).toBe("user-1");
			expect(original?.session.expiresAt).toBeInstanceOf(Date);

			await client.useSession.get().refetch();
			expect(client.useSession.get().data).toBe(original);
			expect(client.useSession.get().error?.status).toBe(500);

			await client.useSession.get().refetch();
			expect(client.useSession.get().data).toBeNull();
			expect(client.useSession.get().error?.status).toBe(401);
			unsubscribe();
		} finally {
			Object.defineProperty(globalThis, "window", {
				configurable: true,
				writable: true,
				value: previousWindow,
			});
		}
	});

	test("keeps session references stable when identical payloads contain dates", async () => {
		const previousWindow = globalThis.window;
		Object.defineProperty(globalThis, "window", {
			configurable: true,
			writable: true,
			value: {
				location: { origin: "https://app.example.test", href: "" },
				addEventListener() {},
				removeEventListener() {},
			},
		});
		const payload = {
			user: {
				id: "user-stable",
				name: "Ada",
				email: "ada@example.test",
				emailVerified: true,
				createdAt: "2026-01-01T00:00:00.000Z",
				updatedAt: "2026-01-01T00:00:00.000Z",
			},
			session: {
				id: "session-stable",
				userId: "user-stable",
				token: "secret",
				expiresAt: "2026-02-01T00:00:00.000Z",
				createdAt: "2026-01-01T00:00:00.000Z",
				updatedAt: "2026-01-01T00:00:00.000Z",
			},
		};

		try {
			const client = createAuthClient({
				baseURL: "https://auth.example.test",
				fetchOptions: {
					customFetchImpl: async () => json(payload),
				},
			});
			const unsubscribe = client.useSession.subscribe(() => {});
			await wait();
			const first = client.useSession.get().data;
			expect(first?.session.expiresAt).toBeInstanceOf(Date);

			await client.useSession.get().refetch();
			expect(client.useSession.get().data).toBe(first);
			unsubscribe();
		} finally {
			Object.defineProperty(globalThis, "window", {
				configurable: true,
				writable: true,
				value: previousWindow,
			});
		}
	});

	test("parses dates and rejects prototype-pollution and unsafe redirect inputs", () => {
		const parsed = parseJSON<{ createdAt: Date }>(
			'{"createdAt":"2026-01-01T00:00:00.000Z"}',
		);
		expect(parsed.createdAt).toBeInstanceOf(Date);
		expect(
			parseJSON<Record<string, unknown>>(
				'{"__proto__":{"polluted":true}}',
				{ strict: false },
			),
		).toEqual({});
		expect(() =>
			parseJSON('{"constructor":{"prototype":{"polluted":true}}}'),
		).toThrow();
		expect(isSafeURLScheme("/dashboard")).toBe(true);
		expect(isSafeURLScheme("myapp://callback")).toBe(true);
		expect(isSafeURLScheme("javascript:alert(1)")).toBe(false);
		expect(isSafeURLScheme("data:text/html,hello")).toBe(false);
		expect(getBaseURL("https://auth.example.test", undefined, false)).toBe(
			"https://auth.example.test/api/auth",
		);
		expect(getBaseURL("https://auth.example.test/custom", undefined, false)).toBe(
			"https://auth.example.test/custom",
		);
		expect(getBaseURL("https://auth.example.test", "/", false)).toBe(
			"https://auth.example.test",
		);
		expect(() => getBaseURL("javascript:alert(1)", undefined, false)).toThrow();
	});
});
