import type { BetterFetch, BetterFetchError } from "@better-fetch/fetch";
import { atom, onMount } from "nanostores";
import { isJsonEqual, withEquality } from "./equality.js";
import { createSessionRefreshManager } from "./session-refresh.js";
import type {
	AuthQueryAtom,
	AuthQueryState,
	BetterAuthClientOptions,
	SessionData,
	SessionQueryParams,
} from "./types.js";

type SessionResponse<O> =
	| (SessionData<O> & { needsRefresh?: boolean | undefined })
	| { session: null; user: null; needsRefresh?: boolean | undefined }
	| null;

interface SessionRequest {
	cancel(): void;
	promise: Promise<void>;
}

function normalizeResponse<O>(response: unknown): {
	data: SessionResponse<O>;
	error: unknown;
} {
	if (
		typeof response === "object" &&
		response !== null &&
		"data" in response &&
		"error" in response
	) {
		return response as { data: SessionResponse<O>; error: unknown };
	}
	return { data: response as SessionResponse<O>, error: null };
}

function normalizeData<O>(data: SessionResponse<O>): SessionData<O> | null {
	if (!data || (data.session === null && data.user === null)) return null;
	return data as SessionData<O>;
}

function statesEqual<O>(
	left: AuthQueryState<SessionData<O>>,
	right: AuthQueryState<SessionData<O>>,
): boolean {
	return (
		isJsonEqual(left.data, right.data) &&
		left.error === right.error &&
		left.isPending === right.isPending &&
		left.isRefetching === right.isRefetching &&
		left.refetch === right.refetch
	);
}

export function getSessionAtom<O extends BetterAuthClientOptions>(
	$fetch: BetterFetch,
	options?: O | undefined,
): {
	session: AuthQueryAtom<SessionData<O>>;
	$sessionSignal: ReturnType<typeof atom<boolean>>;
	broadcastSessionUpdate(
		trigger: "signout" | "getSession" | "updateUser",
	): void;
} {
	const $sessionSignal = atom(false);
	let activeRequest: SessionRequest | undefined;

	const refetch = (
		queryParams?: { query?: SessionQueryParams } | undefined,
	): Promise<void> => fetchSession(queryParams);
	const session = atom<AuthQueryState<SessionData<O>>>({
		data: null,
		error: null,
		isPending: true,
		isRefetching: false,
		refetch,
	});
	withEquality(session, statesEqual);

	const executeSessionFetch = async (
		signal: AbortSignal,
		queryParams?: { query?: SessionQueryParams } | undefined,
	): Promise<void> => {
		const current = session.value;
		session.set({
			...current,
			error: null,
			isPending: current.data === null,
			isRefetching: true,
			refetch,
		});
		if (signal.aborted) return;

		try {
			let normalized = normalizeResponse<O>(
				await $fetch<SessionResponse<O>>("/get-session", {
					method: "GET",
					query: queryParams?.query,
					signal,
				}),
			);
			if (signal.aborted) return;
			if (normalized.data?.needsRefresh) {
				try {
					normalized = normalizeResponse<O>(
						await $fetch<SessionResponse<O>>("/get-session", {
							method: "POST",
							signal,
						}),
					);
				} catch {
					if (signal.aborted) return;
				}
			}
			if (signal.aborted) return;
			if (normalized.error) {
				const latest = session.value;
				const unauthorized =
					(normalized.error as BetterFetchError).status === 401;
				session.set({
					data: unauthorized ? null : latest.data,
					error: normalized.error as BetterFetchError,
					isPending: false,
					isRefetching: false,
					refetch,
				});
				return;
			}
			const nextData = normalizeData(normalized.data);
			const latest = session.value;
			const stableData =
				latest.data !== null &&
				nextData !== null &&
				isJsonEqual(latest.data, nextData)
					? latest.data
					: nextData;
			session.set({
				data: stableData,
				error: null,
				isPending: false,
				isRefetching: false,
				refetch,
			});
		} catch (error) {
			if (signal.aborted) return;
			session.set({
				data: session.value.data,
				error: error as BetterFetchError,
				isPending: false,
				isRefetching: false,
				refetch,
			});
		}
	};

	const fetchSession = (
		queryParams?: { query?: SessionQueryParams } | undefined,
	): Promise<void> => {
		activeRequest?.cancel();
		const controller = new AbortController();
		const promise = Promise.resolve().then(() => {
			if (!controller.signal.aborted) {
				return executeSessionFetch(controller.signal, queryParams);
			}
		});
		const request: SessionRequest = {
			cancel: () => controller.abort(),
			promise,
		};
		activeRequest = request;
		const clear = () => {
			if (activeRequest === request) activeRequest = undefined;
		};
		void promise.then(clear, clear);
		return promise;
	};

	let broadcast: (
		trigger: "signout" | "getSession" | "updateUser",
	) => void = () => {};

	onMount(session, () => {
		let timeout: ReturnType<typeof setTimeout> | undefined;
		if (typeof window !== "undefined") {
			timeout = setTimeout(() => {
				void (activeRequest?.promise ?? fetchSession());
			}, 0);
		}
		const manager = createSessionRefreshManager({
			fetchSession,
			shouldPollSession: () => session.value.data !== null,
			sessionSignal: $sessionSignal,
			options,
		});
		manager.init();
		broadcast = manager.broadcastSessionUpdate;
		return () => {
			if (timeout !== undefined) clearTimeout(timeout);
			manager.cleanup();
		};
	});

	return {
		session,
		$sessionSignal,
		broadcastSessionUpdate: (trigger) => broadcast(trigger),
	};
}
