import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import { createAuthClient } from "../src/index.js";

async function readFirstLine(
	stream: ReadableStream<Uint8Array>,
): Promise<string> {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let output = "";
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			output += decoder.decode(value, { stream: true });
			const newline = output.indexOf("\n");
			if (newline >= 0) return output.slice(0, newline).trim();
		}
		output += decoder.decode();
		return output.trim();
	} finally {
		reader.releaseLock();
	}
}

function createCookieFetch(): {
	fetch: typeof globalThis.fetch;
	cookies: Map<string, string>;
} {
	const cookies = new Map<string, string>();
	const cookieFetch = (async (input, init) => {
		const headers = new Headers(
			input instanceof Request ? input.headers : undefined,
		);
		new Headers(init?.headers).forEach((value, name) => {
			headers.set(name, value);
		});
		if (cookies.size > 0) {
			headers.set(
				"cookie",
				[...cookies].map(([name, value]) => `${name}=${value}`).join("; "),
			);
		}

		const response = await globalThis.fetch(input, { ...init, headers });
		const setCookieHeaders = (
			response.headers as Headers & { getSetCookie?: () => string[] }
		).getSetCookie?.() ?? [];
		for (const setCookie of setCookieHeaders) {
			const [nameValue = ""] = setCookie.split(";", 1);
			const separator = nameValue.indexOf("=");
			if (separator <= 0) continue;
			const name = nameValue.slice(0, separator).trim();
			const value = nameValue.slice(separator + 1).trim();
			const maxAge = /(?:^|;)\s*Max-Age=(-?\d+)/i.exec(setCookie)?.[1];
			if (value === "" || (maxAge !== undefined && Number(maxAge) <= 0)) {
				cookies.delete(name);
			} else {
				cookies.set(name, value);
			}
		}
		return response;
	}) as typeof globalThis.fetch;
	return { fetch: cookieFetch, cookies };
}

test(
	"runs a browser-client session lifecycle against the native Go server",
	async () => {
		const repositoryRoot = fileURLToPath(new URL("../..", import.meta.url));
		const server = Bun.spawn(
			["go", "run", "./internal/cmd/js-client-test-server"],
			{
				cwd: repositoryRoot,
				stdout: "pipe",
				stderr: "pipe",
			},
		);

		try {
			const baseURL = await readFirstLine(server.stdout);
			expect(baseURL).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
			const cookieTransport = createCookieFetch();
			const client = createAuthClient({
				baseURL,
				fetchOptions: {
					customFetchImpl: cookieTransport.fetch,
					headers: { Origin: baseURL },
				},
			});
			const email = `ada-${crypto.randomUUID()}@example.test`;

			const signedUp = await client.signUp.email({
				name: "Ada Lovelace",
				email,
				password: "correct horse battery staple",
			});
			expect(signedUp.error).toBeNull();
			expect(signedUp.data?.user.email).toBe(email);
			expect(cookieTransport.cookies.has("single-auth.session_token")).toBe(
				true,
			);

			const activeSession = await client.getSession();
			expect(activeSession.error).toBeNull();
			expect(activeSession.data?.user.email).toBe(email);
			expect(activeSession.data?.session.expiresAt).toBeInstanceOf(Date);

			const signedOut = await client.signOut();
			expect(signedOut.error).toBeNull();
			expect(signedOut.data?.success).toBe(true);

			const endedSession = await client.getSession();
			expect(endedSession.error).toBeNull();
			expect(endedSession.data).toBeNull();
		} finally {
			server.kill();
			await server.exited;
		}
	},
	30_000,
);
