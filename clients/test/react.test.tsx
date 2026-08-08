import { describe, expect, test } from "bun:test";
import { atom } from "nanostores";
import { createElement } from "react";
import { act, create } from "react-test-renderer";
import { createAuthClient } from "../src/react/index.js";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean })
	.IS_REACT_ACT_ENVIRONMENT = true;

const json = (value: unknown) =>
	new Response(JSON.stringify(value), {
		headers: { "content-type": "application/json" },
	});

const wait = (milliseconds = 20) =>
	new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

describe("React client", () => {
	test("uses useSyncExternalStore for session and plugin atoms", async () => {
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
		const counter = atom(1);
		let sessionVersion = 0;
		const client = createAuthClient({
			baseURL: "https://auth.example.test",
			plugins: [{ id: "counter", getAtoms: () => ({ counter }) }] as const,
			fetchOptions: {
				customFetchImpl: async () => {
					sessionVersion++;
					return json({
						user: {
							id: `user-${sessionVersion}`,
							name: "Ada",
							email: "ada@example.test",
							emailVerified: true,
							createdAt: "2026-01-01T00:00:00.000Z",
							updatedAt: "2026-01-01T00:00:00.000Z",
						},
						session: {
							id: `session-${sessionVersion}`,
							userId: `user-${sessionVersion}`,
							token: "secret",
							expiresAt: "2026-02-01T00:00:00.000Z",
							createdAt: "2026-01-01T00:00:00.000Z",
							updatedAt: "2026-01-01T00:00:00.000Z",
						},
					});
				},
			},
		});
		let observedCounter = 0;
		let observedUser: string | undefined;
		let observedPending = true;

		function Probe() {
			const session = client.useSession();
			observedCounter = client.useCounter();
			observedUser = session.data?.user.id;
			observedPending = session.isPending;
			return null;
		}

		try {
			let renderer: ReturnType<typeof create> | undefined;
			await act(async () => {
				renderer = create(createElement(Probe));
			});
			await act(async () => {
				await wait();
			});
			expect(observedPending).toBe(false);
			expect(observedUser).toBe("user-1");
			expect(observedCounter).toBe(1);

			await act(async () => {
				counter.set(2);
			});
			expect(observedCounter).toBe(2);

			await act(async () => {
				client.$store.notify("$sessionSignal");
				await wait();
			});
			expect(observedUser).toBe("user-2");

			await act(async () => renderer?.unmount());
			expect(counter.lc).toBe(0);
		} finally {
			Object.defineProperty(globalThis, "window", {
				configurable: true,
				writable: true,
				value: previousWindow,
			});
		}
	});

	test("does not fetch a session while rendered without a browser window", async () => {
		const previousWindow = globalThis.window;
		Object.defineProperty(globalThis, "window", {
			configurable: true,
			writable: true,
			value: undefined,
		});
		let fetches = 0;
		const client = createAuthClient({
			baseURL: "https://auth.example.test",
			fetchOptions: {
				customFetchImpl: async () => {
					fetches++;
					return json(null);
				},
			},
		});
		function Probe() {
			client.useSession();
			return null;
		}
		try {
			let renderer: ReturnType<typeof create> | undefined;
			await act(async () => {
				renderer = create(createElement(Probe));
			});
			await act(async () => {
				await wait();
			});
			expect(fetches).toBe(0);
			await act(async () => renderer?.unmount());
		} finally {
			Object.defineProperty(globalThis, "window", {
				configurable: true,
				writable: true,
				value: previousWindow,
			});
		}
	});
});
