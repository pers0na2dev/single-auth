import type { BetterFetch } from "@better-fetch/fetch";
import type { Atom } from "nanostores";
import { isAtom } from "./is-atom.js";
import { toKebabCase } from "./string.js";
import type {
	ClientAtomListener,
	ClientFetchOption,
	ProxyRequest,
} from "./types.js";

function requestMethod(
	path: string,
	knownPathMethods: Record<string, "POST" | "GET">,
	input: ProxyRequest | undefined,
	callOptions: ClientFetchOption,
): string {
	if (callOptions.method) return callOptions.method;
	const known = knownPathMethods[path];
	if (known) return known;
	if (callOptions.body !== undefined) return "POST";
	if (!input) return "GET";
	const { query: _query, fetchOptions: _fetchOptions, ...body } = input;
	return Object.keys(body).length > 0 ? "POST" : "GET";
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
	if (value === null || typeof value !== "object" || Array.isArray(value)) {
		return false;
	}
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

export async function executeClientCall(
	client: BetterFetch,
	path: string,
	input: ProxyRequest | undefined,
	secondOptions: ClientFetchOption | undefined,
	knownPathMethods: Record<string, "POST" | "GET">,
	atoms: Record<string, Atom<unknown>>,
	atomListeners: ClientAtomListener[] | undefined,
): Promise<unknown> {
	const { query, fetchOptions: inlineOptions, ...body } = input ?? {};
	const options = { ...secondOptions, ...inlineOptions } as ClientFetchOption;
	const method = requestMethod(path, knownPathMethods, input, options);
	const hasInputBody = Object.keys(body).length > 0;
	let requestBody: unknown;
	if (method !== "GET") {
		if (options.body === undefined) requestBody = body;
		else if (hasInputBody && isPlainRecord(options.body)) {
			requestBody = { ...body, ...options.body };
		} else requestBody = options.body;
	}
	return client(path, {
		...options,
		method,
		body: requestBody,
		query: query ?? options.query,
		async onSuccess(context) {
			await options.onSuccess?.(context);
			if (options.disableSignal || !atomListeners) return;
			const visited = new Set<string>();
			for (const listener of atomListeners) {
				if (!listener.matcher(path) || visited.has(listener.signal)) continue;
				visited.add(listener.signal);
				const signal = atoms[listener.signal];
				if (!signal || !("set" in signal) || typeof signal.set !== "function") {
					continue;
				}
				const oldValue = signal.get();
				setTimeout(() => signal.set(!oldValue), 10);
				listener.callback?.(path);
			}
		},
	});
}

export function createDynamicPathProxy<T extends Record<string, any>>(
	routes: T,
	client: BetterFetch,
	knownPathMethods: Record<string, "POST" | "GET">,
	atoms: Record<string, Atom<unknown>>,
	atomListeners?: ClientAtomListener[] | undefined,
): T {
	const createProxy = (segments: string[] = []): any =>
		new Proxy(function () {}, {
			get(_target, property) {
				if (typeof property !== "string") return undefined;
				if (["then", "catch", "finally"].includes(property)) return undefined;
				const fullPath = [...segments, property];
				let current: unknown = routes;
				for (const segment of fullPath) {
					if (
						typeof current === "object" &&
						current !== null &&
						segment in current
					) {
						current = (current as Record<string, unknown>)[segment];
					} else {
						current = undefined;
						break;
					}
				}
				if (typeof current === "function" || isAtom(current)) return current;
				return createProxy(fullPath);
			},
			apply: async (_target, _thisValue, args: unknown[]) => {
				const path = `/${segments.map(toKebabCase).join("/")}`;
				return executeClientCall(
					client,
					path,
					(args[0] ?? undefined) as ProxyRequest | undefined,
					(args[1] ?? undefined) as ClientFetchOption | undefined,
					knownPathMethods,
					atoms,
					atomListeners,
				);
			},
		});

	return createProxy() as T;
}
