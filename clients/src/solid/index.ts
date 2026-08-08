import type { BetterFetch, BetterFetchError } from "@better-fetch/fetch";
import type { Accessor } from "solid-js";
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
import { useStore } from "./solid-store.js";

function getAtomKey(value: string): string {
	return `use${capitalizeFirstLetter(value)}`;
}

type InferSolidHooks<O> = {
	[Key in keyof InferPluginAtoms<O> as Key extends string
		? IsSignal<Key> extends true
			? never
			: `use${Capitalize<Key>}`
		: never]: InferPluginAtoms<O>[Key] extends {
		get(): infer Value;
	}
		? () => Accessor<Value>
		: never;
};

/** Solid client returned by `createAuthClient`. */
export type SolidAuthClient<Option extends BetterAuthClientOptions> =
	CoreAuthAPI<Option> &
		InferActions<Option> &
		InferSolidHooks<Option> & {
			useSession: () => Accessor<AuthQueryState<SessionData<Option>>>;
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

/** Create a Solid client for the native single-auth server. */
export function createAuthClient<
	const Option extends BetterAuthClientOptions = BetterAuthClientOptions,
>(options?: Option | undefined): SolidAuthClient<Option> {
	const config = getClientConfig(options);
	const resolvedHooks: Record<string, () => unknown> = {};

	for (const [key, value] of Object.entries(config.pluginsAtoms)) {
		if (!key.startsWith("$")) {
			resolvedHooks[getAtomKey(key)] = () => useStore(value);
		}
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
	) as SolidAuthClient<Option>;
}

export { useStore } from "./solid-store.js";
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
