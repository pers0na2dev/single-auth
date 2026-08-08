import type { BetterFetch, BetterFetchError } from "@better-fetch/fetch";
import type { PreinitializedWritableAtom } from "nanostores";
import { atom, onMount } from "nanostores";
import { isJsonEqual, withEquality } from "./equality.js";
import type {
	AuthQueryAtom,
	AuthQueryState,
	ClientFetchOption,
	SessionQueryParams,
} from "./types.js";

function isAuthQueryStateEqual<T>(
	left: AuthQueryState<T>,
	right: AuthQueryState<T>,
): boolean {
	return (
		isJsonEqual(left.data, right.data) &&
		left.error === right.error &&
		left.isPending === right.isPending &&
		left.isRefetching === right.isRefetching &&
		left.refetch === right.refetch
	);
}

export function useAuthQuery<T>(
	initializedAtom:
		| PreinitializedWritableAtom<any>
		| PreinitializedWritableAtom<any>[],
	path: string,
	$fetch: BetterFetch,
	options?:
		| ClientFetchOption
		| ((state: {
				data: T | null;
				error: BetterFetchError | null;
				isPending: boolean;
		  }) => ClientFetchOption)
		| undefined,
): AuthQueryAtom<T> {
	const value = atom<AuthQueryState<T>>({
		data: null,
		error: null,
		isPending: true,
		isRefetching: false,
		refetch: (queryParams) => fetchValue(queryParams),
	});
	withEquality(value, isAuthQueryStateEqual);

	const fetchValue = async (
		queryParams?: { query?: SessionQueryParams } | undefined,
	): Promise<void> => {
		const current = value.get();
		const requestOptions =
			typeof options === "function"
				? options({
						data: current.data,
						error: current.error,
						isPending: current.isPending,
					})
				: options;
		try {
			await $fetch<T>(path, {
				...requestOptions,
				query: { ...requestOptions?.query, ...queryParams?.query },
				async onRequest(context) {
					const latest = value.get();
					value.set({
						data: latest.data,
						error: null,
						isPending: latest.data === null,
						isRefetching: true,
						refetch: value.value.refetch,
					});
					await requestOptions?.onRequest?.(context);
				},
				async onSuccess(context) {
					const latest = value.get();
					const stableData =
						latest.data !== null &&
						context.data !== null &&
						isJsonEqual(latest.data, context.data)
							? latest.data
							: context.data;
					value.set({
						data: stableData,
						error: null,
						isPending: false,
						isRefetching: false,
						refetch: value.value.refetch,
					});
					await requestOptions?.onSuccess?.(context);
				},
				async onError(context) {
					const retryAttempts =
						typeof context.request.retry === "number"
							? context.request.retry
							: context.request.retry?.attempts;
					if (
						retryAttempts &&
						(context.request.retryAttempt ?? 0) < retryAttempts
					) {
						return;
					}
					value.set({
						data: context.error.status === 401 ? null : value.get().data,
						error: context.error,
						isPending: false,
						isRefetching: false,
						refetch: value.value.refetch,
					});
					await requestOptions?.onError?.(context);
				},
			});
		} catch (error) {
			value.set({
				data: value.get().data,
				error: error as BetterFetchError,
				isPending: false,
				isRefetching: false,
				refetch: value.value.refetch,
			});
		}
	};

	const signals = Array.isArray(initializedAtom)
		? initializedAtom
		: [initializedAtom];
	let mountFetchPending = false;
	let mounted = false;
	let refetchAfterPending = false;

	const fetchOnMount = () => {
		if (mountFetchPending) {
			refetchAfterPending = true;
			return;
		}
		mountFetchPending = true;
		void fetchValue().finally(() => {
			mountFetchPending = false;
			const shouldRefetch = refetchAfterPending && mounted;
			refetchAfterPending = false;
			if (shouldRefetch) fetchOnMount();
		});
	};

	onMount(value, () => {
		if (typeof window === "undefined") return;
		mounted = true;
		let initialized = false;
		let timeout: ReturnType<typeof setTimeout>;
		const cleanups = signals.map((signal) =>
			signal.listen(() => {
				if (initialized) void fetchValue();
				else {
					initialized = true;
					clearTimeout(timeout);
					fetchOnMount();
				}
			}),
		);
		timeout = setTimeout(() => {
			initialized = true;
			fetchOnMount();
		}, 0);
		return () => {
			mounted = false;
			for (const cleanup of cleanups) cleanup();
			clearTimeout(timeout);
		};
	});

	return value;
}
