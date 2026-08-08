import { createFetch } from "@better-fetch/fetch";
import type { FetchHooks } from "@better-fetch/fetch";
import { defu } from "defu";
import type { WritableAtom } from "nanostores";
import { redirectPlugin } from "./fetch-plugins.js";
import { parseJSON } from "./parser.js";
import { getSessionAtom } from "./session-atom.js";
import { getBaseURL } from "./url.js";
import type {
	BetterAuthClientOptions,
	ClientAtomListener,
	ClientStore,
} from "./types.js";

export function getClientConfig<
	O extends BetterAuthClientOptions = BetterAuthClientOptions,
>(options?: O | undefined, loadEnv = true) {
	const baseURL = getBaseURL(options?.baseURL, options?.basePath, loadEnv);
	const credentialsSupported =
		typeof Request !== "undefined" && "credentials" in Request.prototype;
	const pluginFetchPlugins =
		options?.plugins?.flatMap((plugin) => plugin.fetchPlugins ?? []) ?? [];
	const lifecycleHooks: FetchHooks = {};
	if (options?.fetchOptions?.onSuccess) {
		lifecycleHooks.onSuccess = options.fetchOptions.onSuccess;
	}
	if (options?.fetchOptions?.onError) {
		lifecycleHooks.onError = options.fetchOptions.onError;
	}
	if (options?.fetchOptions?.onRequest) {
		lifecycleHooks.onRequest = options.fetchOptions.onRequest;
	}
	if (options?.fetchOptions?.onResponse) {
		lifecycleHooks.onResponse = options.fetchOptions.onResponse;
	}
	const lifecyclePlugin = {
		id: "single-auth-lifecycle-hooks",
		name: "single-auth lifecycle hooks",
		hooks: lifecycleHooks,
	};
	const {
		onSuccess: _onSuccess,
		onError: _onError,
		onRequest: _onRequest,
		onResponse: _onResponse,
		...fetchOptions
	} = options?.fetchOptions ?? {};

	const $fetch = createFetch({
		baseURL,
		...(credentialsSupported ? { credentials: "include" as const } : {}),
		method: "GET",
		jsonParser: (text) =>
			text ? parseJSON(text, { strict: false }) : (null as unknown),
		...(typeof globalThis.fetch === "function"
			? { customFetchImpl: globalThis.fetch }
			: {}),
		...fetchOptions,
		plugins: [
			lifecyclePlugin,
			...(fetchOptions.plugins ?? []),
			...(options?.disableDefaultFetchPlugins ? [] : [redirectPlugin]),
			...pluginFetchPlugins,
		],
	});

	const { session, $sessionSignal, broadcastSessionUpdate } = getSessionAtom(
		$fetch,
		options,
	);
	const pluginsAtoms: Record<string, WritableAtom<any>> = {
		$sessionSignal,
		session,
	};
	const pluginPathMethods: Record<string, "POST" | "GET"> = {
		"/get-session": "GET",
		"/list-sessions": "GET",
		"/list-accounts": "GET",
		"/account-info": "GET",
		"/verify-email": "GET",
		"/sign-out": "POST",
		"/update-user": "POST",
		"/update-session": "POST",
		"/revoke-sessions": "POST",
		"/revoke-other-sessions": "POST",
		"/delete-user": "POST",
	};
	const atomListeners: ClientAtomListener[] = [
		{
			signal: "$sessionSignal",
			matcher: (path) =>
				[
					"/sign-out",
					"/update-user",
					"/update-session",
					"/sign-up/email",
					"/sign-in/email",
					"/sign-in/social",
					"/delete-user",
					"/verify-email",
					"/revoke-sessions",
					"/revoke-session",
					"/revoke-other-sessions",
					"/change-email",
					"/change-password",
				].includes(path),
			callback(path) {
				if (path === "/sign-out") broadcastSessionUpdate("signout");
				else if (path === "/update-user" || path === "/update-session") {
					broadcastSessionUpdate("updateUser");
				}
			},
		},
	];

	for (const plugin of options?.plugins ?? []) {
		if (plugin.getAtoms) Object.assign(pluginsAtoms, plugin.getAtoms($fetch));
		if (plugin.pathMethods) Object.assign(pluginPathMethods, plugin.pathMethods);
		if (plugin.atomListeners) atomListeners.push(...plugin.atomListeners);
	}

	const $store: ClientStore = {
		atoms: pluginsAtoms,
		notify(signal = "$sessionSignal") {
			const atom = pluginsAtoms[signal];
			if (!atom) throw new TypeError(`Unknown single-auth signal: ${signal}`);
			atom.set(!atom.get());
		},
		listen(signal, listener) {
			const atom = pluginsAtoms[signal];
			if (!atom) throw new TypeError(`Unknown single-auth signal: ${signal}`);
			return atom.subscribe(listener);
		},
	};

	let pluginsActions: Record<string, any> = {};
	const pluginErrorCodes: Record<string, unknown> = {};
	for (const plugin of options?.plugins ?? []) {
		if (plugin.getActions) {
			pluginsActions = defu(
				plugin.getActions($fetch, $store, options) ?? {},
				pluginsActions,
			) as Record<string, any>;
		}
		if (plugin.$ERROR_CODES) Object.assign(pluginErrorCodes, plugin.$ERROR_CODES);
	}

	return {
		get baseURL() {
			return baseURL;
		},
		pluginsActions,
		pluginsAtoms,
		pluginPathMethods,
		atomListeners,
		pluginErrorCodes,
		$fetch,
		$store,
	};
}
