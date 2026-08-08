import type { BetterFetch, BetterFetchError } from "@better-fetch/fetch";
import type { Atom } from "nanostores";
import { getClientConfig } from "./config.js";
import { BASE_ERROR_CODES } from "./error-codes.js";
import {
	createDynamicPathProxy,
	executeClientCall,
} from "./proxy.js";
import { capitalizeFirstLetter } from "./string.js";
import type {
	AuthQueryState,
	BetterAuthClientOptions,
	ClientFetchOption,
	ClientStore,
	CoreAuthAPI,
	DynamicClientCall,
	InferActions,
	InferPluginErrorCodes,
	InferUser,
	InferVanillaHooks,
	PrettifyDeep,
	SessionData,
} from "./types.js";

export type AuthClient<O extends BetterAuthClientOptions> = CoreAuthAPI<O> &
	InferActions<O> &
	InferVanillaHooks<O> & {
		useSession: Atom<AuthQueryState<SessionData<O>>>;
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
>(options?: O | undefined): AuthClient<O> {
	const config = getClientConfig(options);
	const resolvedAtoms: Record<string, Atom<unknown>> = {};
	for (const [key, value] of Object.entries(config.pluginsAtoms)) {
		if (!key.startsWith("$")) {
			resolvedAtoms[`use${capitalizeFirstLetter(key)}`] = value;
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
		...resolvedAtoms,
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
	) as AuthClient<O>;
}

export type { BetterFetchError };
