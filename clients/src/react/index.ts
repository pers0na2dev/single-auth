import type { BetterFetch, BetterFetchError } from "@better-fetch/fetch";
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
	InferPluginErrorCodes,
	InferReactHooks,
	InferUser,
	PrettifyDeep,
	SessionData,
} from "../client/types.js";
import { useStore } from "./react-store.js";

export type ReactAuthClient<O extends BetterAuthClientOptions> = CoreAuthAPI<O> &
	InferActions<O> &
	InferReactHooks<O> & {
		useSession(): AuthQueryState<SessionData<O>>;
		$fetch: BetterFetch;
		$store: ClientStore;
		$call: DynamicClientCall<O>;
		$Infer: {
			Session: SessionData<O>;
			User: InferUser<O>;
		};
		$ERROR_CODES: PrettifyDeep<
			typeof BASE_ERROR_CODES & InferPluginErrorCodes<O>
		>;
	};

export function createAuthClient<
	const O extends BetterAuthClientOptions = BetterAuthClientOptions,
>(options?: O | undefined): ReactAuthClient<O> {
	const config = getClientConfig(options);
	const resolvedHooks: Record<string, () => unknown> = {};
	for (const [key, value] of Object.entries(config.pluginsAtoms)) {
		if (!key.startsWith("$")) {
			resolvedHooks[`use${capitalizeFirstLetter(key)}`] = () => useStore(value);
		}
	}
	const $call = ((
		path: string,
		input?: Parameters<DynamicClientCall<O>>[1],
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
		)) as DynamicClientCall<O>;
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
	) as ReactAuthClient<O>;
}

export { useStore } from "./react-store.js";
export type { BetterFetchError };
export type * from "../client/types.js";
export type {
	BetterFetch,
	BetterFetchOption,
	BetterFetchPlugin,
	BetterFetchResponse,
} from "@better-fetch/fetch";
export type { Atom, Store, StoreValue, WritableAtom } from "nanostores";
