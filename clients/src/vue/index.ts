import type { BetterFetch, BetterFetchError } from "@better-fetch/fetch";
import type { DeepReadonly, Ref } from "vue";
import { getClientConfig } from "../client/config.js";
import { BASE_ERROR_CODES } from "../client/error-codes.js";
import {
	createDynamicPathProxy,
	executeClientCall,
} from "../client/proxy.js";
import { capitalizeFirstLetter } from "../client/string.js";
import type {
	AuthQueryState,
	BetterAuthClientOptions,
	ClientFetchOption,
	ClientStore,
	CoreAuthAPI,
	DynamicClientCall,
	InferActions,
	InferPluginAtoms,
	InferPluginErrorCodes,
	InferUser,
	IsSignal,
	PrettifyDeep,
	SessionData,
} from "../client/types.js";
import { useStore } from "./vue-store.js";

function getAtomKey(value: string): string {
	return `use${capitalizeFirstLetter(value)}`;
}

type InferVueHooks<O> = {
	[Key in keyof InferPluginAtoms<O> as Key extends string
		? IsSignal<Key> extends true
			? never
			: `use${Capitalize<Key>}`
		: never]: InferPluginAtoms<O>[Key] extends {
		get(): infer Value;
	}
		? () => DeepReadonly<Ref<Value>>
		: never;
};

export type NuxtSessionError = {
	message?: string | undefined;
	status: number;
	statusText: string;
};

export type VueUseSession<Option extends BetterAuthClientOptions> = {
	(): DeepReadonly<Ref<AuthQueryState<SessionData<Option>>>>;
	<F extends (...args: any[]) => any>(
		useFetch: F,
	): Promise<{
		data: Ref<SessionData<Option> | null>;
		isPending: false;
		error: Ref<NuxtSessionError | null>;
	}>;
};

/** Vue client returned by `createAuthClient`. */
export type VueAuthClient<Option extends BetterAuthClientOptions> =
	CoreAuthAPI<Option> &
		InferActions<Option> &
		InferVueHooks<Option> & {
			useSession: VueUseSession<Option>;
			$Infer: {
				Session: SessionData<Option>;
				User: InferUser<Option>;
			};
			$fetch: BetterFetch;
			$store: ClientStore;
			$call: DynamicClientCall<Option>;
			$ERROR_CODES: PrettifyDeep<
				InferPluginErrorCodes<Option> & typeof BASE_ERROR_CODES
			>;
		};

/**
 * Create a Vue client for the native single-auth server.
 *
 * As in Better Auth's Vue adapter, normal auth URL environment variables are
 * deliberately ignored. This keeps Nuxt's server and browser URL resolution
 * explicit while preserving same-origin fallback.
 */
export function createAuthClient<
	const Option extends BetterAuthClientOptions = BetterAuthClientOptions,
>(options?: Option | undefined): VueAuthClient<Option> {
	const config = getClientConfig(options, false);
	const resolvedHooks: Record<string, () => unknown> = {};

	for (const [key, value] of Object.entries(config.pluginsAtoms)) {
		if (!key.startsWith("$")) {
			resolvedHooks[getAtomKey(key)] = () => useStore(value);
		}
	}

	function useSession(): DeepReadonly<
		Ref<AuthQueryState<SessionData<Option>>>
	>;
	function useSession<F extends (...args: any[]) => any>(
		useFetch: F,
	): Promise<{
		data: Ref<SessionData<Option> | null>;
		isPending: false;
		error: Ref<NuxtSessionError | null>;
	}>;
	function useSession<UseFetch extends (...args: any[]) => any>(
		useFetch?: UseFetch | undefined,
	) {
		if (useFetch) {
			const ref = useStore(config.pluginsAtoms.$sessionSignal!);
			return useFetch(`${config.baseURL}/get-session`, { ref }).then(
				(response: any) => ({
					data: response.data,
					isPending: false as const,
					error: response.error,
				}),
			);
		}

		return resolvedHooks.useSession!() as DeepReadonly<
			Ref<AuthQueryState<SessionData<Option>>>
		>;
	}
	const $call = ((
		path: string,
		input?: Parameters<DynamicClientCall<Option>>[1],
		fetchOptions?: ClientFetchOption,
	) =>
		executeClientCall(
			config.$fetch,
			path,
			input,
			fetchOptions,
			config.pluginPathMethods,
			config.pluginsAtoms,
			config.atomListeners,
		)) as DynamicClientCall<Option>;

	const routes = {
		...config.pluginsActions,
		...resolvedHooks,
		useSession,
		$fetch: config.$fetch,
		$store: config.$store,
		$call,
		$Infer: Object.freeze({}),
		$ERROR_CODES: Object.freeze({
			...BASE_ERROR_CODES,
			...config.pluginErrorCodes,
		}),
	};

	return createDynamicPathProxy(
		routes,
		config.$fetch,
		config.pluginPathMethods,
		config.pluginsAtoms,
		config.atomListeners,
	) as VueAuthClient<Option>;
}

export { useStore } from "./vue-store.js";
export type { BetterFetchError };
export type {
	BetterFetch,
	BetterFetchOption,
	BetterFetchPlugin,
	BetterFetchResponse,
} from "@better-fetch/fetch";
export type { Atom, Store, StoreValue, WritableAtom } from "nanostores";
export type {
	BetterAuthClientOptions,
	SessionData,
	SessionQueryParams,
	UnionToIntersection,
} from "../client/types.js";
