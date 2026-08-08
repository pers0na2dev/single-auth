import type { Store, StoreValue } from "nanostores";
import { onSet } from "nanostores";

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (typeof value !== "object" || value === null) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

export function isJsonEqual(left: unknown, right: unknown): boolean {
	if (left === right) return true;
	if (left instanceof Date && right instanceof Date) {
		return left.getTime() === right.getTime();
	}
	if (Array.isArray(left) && Array.isArray(right)) {
		if (left.length !== right.length) return false;
		return left.every((value, index) => isJsonEqual(value, right[index]));
	}
	if (isPlainObject(left) && isPlainObject(right)) {
		const leftKeys = Object.keys(left);
		if (leftKeys.length !== Object.keys(right).length) return false;
		return leftKeys.every(
			(key) => key in right && isJsonEqual(left[key], right[key]),
		);
	}
	return false;
}

export function withEquality<S extends Store>(
	store: S,
	isEqual: (left: StoreValue<S>, right: StoreValue<S>) => boolean,
): () => void {
	return onSet(store, ({ newValue, abort }) => {
		if (isEqual(store.value, newValue)) abort();
	});
}
