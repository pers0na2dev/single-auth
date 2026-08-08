import type { BetterFetchPlugin } from "@better-fetch/fetch";
import { isSafeURLScheme } from "./url.js";

export const redirectPlugin = {
	id: "single-auth-redirect",
	name: "single-auth redirect",
	hooks: {
		onSuccess(context) {
			const data = context.data as
				| { url?: unknown; redirect?: unknown }
				| null
				| undefined;
			if (
				typeof data?.url !== "string" ||
				data.redirect !== true ||
				!isSafeURLScheme(data.url)
			) {
				return;
			}
			if (typeof window !== "undefined" && window.location) {
				try {
					window.location.href = data.url;
				} catch {
					// Some embedded browser contexts expose a non-writable location.
				}
			}
		},
	},
} satisfies BetterFetchPlugin;
