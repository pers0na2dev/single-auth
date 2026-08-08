import type { Store, StoreValue } from "nanostores";
import { listenKeys } from "nanostores";
import type { DependencyList } from "react";
import { useCallback, useRef, useSyncExternalStore } from "react";

type StoreKeys<T> = T extends { setKey(key: infer Key, value: any): unknown }
	? Key
	: never;

export interface UseStoreOptions<SomeStore> {
	deps?: DependencyList | undefined;
	keys?: StoreKeys<SomeStore>[] | undefined;
}

export function useStore<SomeStore extends Store>(
	store: SomeStore,
	options: UseStoreOptions<SomeStore> = {},
): StoreValue<SomeStore> {
	const snapshot = useRef<StoreValue<SomeStore>>(store.get());
	const { keys, deps = [store, keys] } = options;
	const subscribe = useCallback((onChange: () => void) => {
		const emit = (value: StoreValue<SomeStore>) => {
			if (snapshot.current === value) return;
			snapshot.current = value;
			onChange();
		};
		emit(store.value);
		return keys?.length
			? listenKeys(store as any, keys, emit)
			: store.listen(emit);
	}, deps);
	const getSnapshot = () => snapshot.current;
	return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}
