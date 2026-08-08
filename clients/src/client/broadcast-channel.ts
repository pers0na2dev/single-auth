export interface BroadcastMessage {
	event?: "session" | undefined;
	data?:
		| { trigger?: "signout" | "getSession" | "updateUser" | undefined }
		| undefined;
	clientId: string;
	timestamp: number;
}

export type BroadcastListener = (message: BroadcastMessage) => void;

export interface AuthBroadcastChannel {
	post(message: Record<string, unknown>): void;
	subscribe(listener: BroadcastListener): () => void;
	setup(): () => void;
}

export const kBroadcastChannel = Symbol.for("single-auth:broadcast-channel");

class WindowBroadcastChannel implements AuthBroadcastChannel {
	readonly listeners = new Set<BroadcastListener>();

	constructor(private readonly name = "single-auth.message") {}

	subscribe(listener: BroadcastListener): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	post(message: Record<string, unknown>): void {
		if (typeof window === "undefined" || typeof localStorage === "undefined") {
			return;
		}
		try {
			localStorage.setItem(
				this.name,
				JSON.stringify({ ...message, timestamp: Math.floor(Date.now() / 1000) }),
			);
		} catch {
			// Storage can be unavailable in private/sandboxed browser contexts.
		}
	}

	setup(): () => void {
		if (typeof window === "undefined" || !window.addEventListener) return () => {};
		const handler = (event: StorageEvent) => {
			if (event.key !== this.name) return;
			try {
				const message = JSON.parse(event.newValue ?? "{}") as BroadcastMessage;
				if (message.event !== "session" || !message.data) return;
				for (const listener of this.listeners) listener(message);
			} catch {
				// Ignore malformed data written by unrelated scripts.
			}
		};
		window.addEventListener("storage", handler);
		return () => window.removeEventListener("storage", handler);
	}
}

export function getGlobalBroadcastChannel(
	name = "single-auth.message",
): AuthBroadcastChannel {
	const globals = globalThis as typeof globalThis & {
		[kBroadcastChannel]?: AuthBroadcastChannel;
	};
	globals[kBroadcastChannel] ??= new WindowBroadcastChannel(name);
	return globals[kBroadcastChannel];
}
