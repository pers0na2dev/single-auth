import { describe, expect, test } from "bun:test";
import { atom } from "nanostores";
import { createRoot } from "solid-js";
import type { Accessor } from "solid-js";
import { createAuthClient } from "../src/solid/index.js";
import { useStore } from "../src/solid/solid-store.js";

describe("Solid client", () => {
	test("tracks Nano Stores values until the current Solid owner is disposed", () => {
		const store = atom({ count: 1 });
		let dispose = () => {};
		let state: Accessor<{ count: number }> = () => ({ count: 0 });

		createRoot((rootDispose) => {
			dispose = rootDispose;
			state = useStore(store);
		});

		expect(state()).toEqual({ count: 1 });
		expect(store.lc).toBe(1);

		store.set({ count: 2 });
		expect(state()).toEqual({ count: 2 });

		dispose();
		expect(store.lc).toBe(0);

		store.set({ count: 3 });
		expect(state()).toEqual({ count: 2 });
	});

	test("exposes session and plugin atoms as Solid accessors", () => {
		const counter = atom({ count: 1 });
		const client = createAuthClient({
			plugins: [
				{
					id: "counter",
					getAtoms: () => ({ counter }),
				},
			] as const,
		});
		let dispose = () => {};
		let state: Accessor<{ count: number }> = () => ({ count: 0 });
		let session: Accessor<{
			data: unknown;
			isPending: boolean;
			isRefetching: boolean;
			error: unknown;
		}> = () => ({
			data: undefined,
			isPending: false,
			isRefetching: false,
			error: undefined,
		});

		createRoot((rootDispose) => {
			dispose = rootDispose;
			state = client.useCounter();
			session = client.useSession();
		});

		expect(state()).toEqual({ count: 1 });
		expect(session()).toMatchObject({
			data: null,
			isPending: true,
			isRefetching: false,
			error: null,
		});

		counter.set({ count: 2 });
		expect(state()).toEqual({ count: 2 });
		dispose();
	});

	test("loads the configured auth URL environment for the Solid client", async () => {
		const previousURL = process.env.NEXT_PUBLIC_SINGLE_AUTH_URL;
		process.env.NEXT_PUBLIC_SINGLE_AUTH_URL = "https://solid.example";
		let requestedURL = "";

		try {
			const client = createAuthClient({
				fetchOptions: {
					customFetchImpl: async (input) => {
						requestedURL =
							input instanceof Request ? input.url : String(input);
						return Response.json({ ok: true });
					},
				},
			});

			await client.$fetch("/probe");
			expect(requestedURL).toBe("https://solid.example/api/auth/probe");
		} finally {
			if (previousURL === undefined) {
				delete process.env.NEXT_PUBLIC_SINGLE_AUTH_URL;
			} else {
				process.env.NEXT_PUBLIC_SINGLE_AUTH_URL = previousURL;
			}
		}
	});
});
