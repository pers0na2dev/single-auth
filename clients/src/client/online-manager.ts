export type OnlineListener = (online: boolean) => void;

export interface OnlineManager {
	setOnline(online: boolean): void;
	readonly isOnline: boolean;
	subscribe(listener: OnlineListener): () => void;
	setup(): () => void;
}

export const kOnlineManager = Symbol.for("single-auth:online-manager");

class WindowOnlineManager implements OnlineManager {
	readonly listeners = new Set<OnlineListener>();
	isOnline = typeof navigator === "undefined" ? true : navigator.onLine;

	setOnline(online: boolean): void {
		this.isOnline = online;
		for (const listener of this.listeners) listener(online);
	}

	subscribe(listener: OnlineListener): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	setup(): () => void {
		if (typeof window === "undefined" || !window.addEventListener) return () => {};
		const onOnline = () => this.setOnline(true);
		const onOffline = () => this.setOnline(false);
		window.addEventListener("online", onOnline, false);
		window.addEventListener("offline", onOffline, false);
		return () => {
			window.removeEventListener("online", onOnline, false);
			window.removeEventListener("offline", onOffline, false);
		};
	}
}

export function getGlobalOnlineManager(): OnlineManager {
	const globals = globalThis as typeof globalThis & {
		[kOnlineManager]?: OnlineManager;
	};
	globals[kOnlineManager] ??= new WindowOnlineManager();
	return globals[kOnlineManager];
}
