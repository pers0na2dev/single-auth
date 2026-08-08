import type { WritableAtom } from "nanostores";
import { getGlobalBroadcastChannel } from "./broadcast-channel.js";
import { getGlobalFocusManager } from "./focus-manager.js";
import { getGlobalOnlineManager } from "./online-manager.js";
import type { BetterAuthClientOptions } from "./types.js";

const now = () => Math.floor(Date.now() / 1000);
const FOCUS_REFETCH_RATE_LIMIT_SECONDS = 5;

export interface SessionRefreshOptions {
	fetchSession: () => Promise<void>;
	shouldPollSession?: (() => boolean) | undefined;
	sessionSignal: WritableAtom<boolean>;
	options?: BetterAuthClientOptions | undefined;
}

export function createSessionRefreshManager({
	fetchSession,
	shouldPollSession = () => true,
	sessionSignal,
	options = {},
}: SessionRefreshOptions) {
	const refetchInterval = options.sessionOptions?.refetchInterval ?? 0;
	const refetchOnWindowFocus =
		options.sessionOptions?.refetchOnWindowFocus ?? true;
	const refetchWhenOffline = options.sessionOptions?.refetchWhenOffline ?? false;
	let initialized = false;
	let lastSessionRequest = 0;
	let pollInterval: ReturnType<typeof setInterval> | undefined;
	const cleanups: Array<() => void> = [];

	const canRefetch = () =>
		refetchWhenOffline || getGlobalOnlineManager().isOnline;

	const triggerRefetch = (event?: {
		event?: "poll" | "visibilitychange" | "storage" | undefined;
	}): void => {
		if (!canRefetch()) return;
		if (event?.event === "visibilitychange") {
			if (now() - lastSessionRequest < FOCUS_REFETCH_RATE_LIMIT_SECONDS) return;
			lastSessionRequest = now();
		} else if (event?.event === "poll") {
			lastSessionRequest = now();
		}
		void fetchSession();
	};

	const broadcastSessionUpdate = (
		trigger: "signout" | "getSession" | "updateUser",
	): void => {
		getGlobalBroadcastChannel().post({
			event: "session",
			data: { trigger },
			clientId: Math.random().toString(36).slice(2),
		});
	};

	const init = (): void => {
		if (initialized) return;
		initialized = true;
		if (refetchInterval > 0) {
			pollInterval = setInterval(() => {
				if (shouldPollSession()) triggerRefetch({ event: "poll" });
			}, refetchInterval * 1000);
		}
		cleanups.push(
			getGlobalBroadcastChannel().subscribe(() =>
				triggerRefetch({ event: "storage" }),
			),
		);
		if (refetchOnWindowFocus) {
			cleanups.push(
				getGlobalFocusManager().subscribe(() =>
					triggerRefetch({ event: "visibilitychange" }),
				),
			);
		}
		cleanups.push(
			getGlobalOnlineManager().subscribe((online) => {
				if (online) triggerRefetch({ event: "visibilitychange" });
			}),
			sessionSignal.listen(() => void fetchSession()),
			getGlobalBroadcastChannel().setup(),
			getGlobalFocusManager().setup(),
			getGlobalOnlineManager().setup(),
		);
	};

	const cleanup = (): void => {
		if (!initialized) return;
		if (pollInterval !== undefined) {
			clearInterval(pollInterval);
			pollInterval = undefined;
		}
		for (const unsubscribe of cleanups.splice(0)) unsubscribe();
		initialized = false;
		lastSessionRequest = 0;
	};

	return { init, cleanup, triggerRefetch, broadcastSessionUpdate };
}
