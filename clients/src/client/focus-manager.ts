export type FocusListener = (focused: boolean) => void;

export interface FocusManager {
	setFocused(focused: boolean): void;
	subscribe(listener: FocusListener): () => void;
	setup(): () => void;
}

export const kFocusManager = Symbol.for("single-auth:focus-manager");

class WindowFocusManager implements FocusManager {
	readonly listeners = new Set<FocusListener>();

	setFocused(focused: boolean): void {
		for (const listener of this.listeners) listener(focused);
	}

	subscribe(listener: FocusListener): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	setup(): () => void {
		if (typeof document === "undefined" || !document.addEventListener) {
			return () => {};
		}
		const handler = () => {
			if (document.visibilityState === "visible") this.setFocused(true);
		};
		document.addEventListener("visibilitychange", handler, false);
		return () => document.removeEventListener("visibilitychange", handler, false);
	}
}

export function getGlobalFocusManager(): FocusManager {
	const globals = globalThis as typeof globalThis & {
		[kFocusManager]?: FocusManager;
	};
	globals[kFocusManager] ??= new WindowFocusManager();
	return globals[kFocusManager];
}
