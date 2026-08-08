import { describe, expect, test } from "bun:test";
import { atom } from "nanostores";
import { effectScope, isReadonly, isRef, ref } from "vue";
import { createAuthClient } from "../src/vue/index.js";
import { useStore } from "../src/vue/vue-store.js";

describe("Vue client", () => {
	test("tracks Nano Stores values until the current Vue scope is disposed", () => {
		const store = atom({ count: 1 });
		const scope = effectScope();
		const state = scope.run(() => useStore(store));

		expect(state).toBeDefined();
		expect(state?.value).toEqual({ count: 1 });
		expect(store.lc).toBe(1);
		expect(isReadonly(state)).toBe(true);

		store.set({ count: 2 });
		expect(state?.value).toEqual({ count: 2 });

		scope.stop();
		expect(store.lc).toBe(0);

		store.set({ count: 3 });
		expect(state?.value).toEqual({ count: 2 });
	});

	test("exposes session and plugin atoms as scoped Vue refs", () => {
		const counter = atom({ count: 1 });
		const client = createAuthClient({
			plugins: [
				{
					id: "counter",
					getAtoms: () => ({ counter }),
				},
			] as const,
		});
		const scope = effectScope();
		const state = scope.run(() => client.useCounter());
		const session = scope.run(() => client.useSession());

		expect(isRef(state)).toBe(true);
		expect(state?.value).toEqual({ count: 1 });
		expect(session?.value).toMatchObject({
			data: null,
			isPending: true,
			isRefetching: false,
			error: null,
		});

		counter.set({ count: 2 });
		expect(state?.value).toEqual({ count: 2 });
		scope.stop();
	});

	test("supports Nuxt useFetch without loading auth URL environment variables", async () => {
		const previousURL = process.env.NEXT_PUBLIC_SINGLE_AUTH_URL;
		process.env.NEXT_PUBLIC_SINGLE_AUTH_URL =
			"https://environment.invalid/custom-auth";
		const scope = effectScope();

		try {
			const client = createAuthClient();
			let requestedURL = "";
			let refreshRef: { value: boolean } | undefined;
			const now = new Date("2026-08-11T00:00:00.000Z");
			const sessionData = {
				user: {
					id: "user-1",
					name: "Ada",
					email: "ada@example.com",
					emailVerified: true,
					createdAt: now,
					updatedAt: now,
				},
				session: {
					id: "session-1",
					userId: "user-1",
					expiresAt: now,
					token: "token",
					createdAt: now,
					updatedAt: now,
				},
			};
			const result = await scope.run(() =>
				client.useSession(
					async (url: string, options: { ref: { value: boolean } }) => {
						requestedURL = url;
						refreshRef = options.ref;
						return {
							data: ref(sessionData),
							error: ref(null),
						};
					},
				),
			);

			expect(requestedURL).toBe("/api/auth/get-session");
			expect(refreshRef?.value).toBe(false);
			expect(result?.isPending).toBe(false);
			expect(result?.data.value).toEqual(sessionData);
			expect(result?.error.value).toBeNull();

			client.$store.notify("$sessionSignal");
			expect(refreshRef?.value).toBe(true);
		} finally {
			scope.stop();
			if (previousURL === undefined) {
				delete process.env.NEXT_PUBLIC_SINGLE_AUTH_URL;
			} else {
				process.env.NEXT_PUBLIC_SINGLE_AUTH_URL = previousURL;
			}
		}
	});
});
