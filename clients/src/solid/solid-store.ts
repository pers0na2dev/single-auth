import type { Store, StoreValue } from "nanostores";
import type { Accessor } from "solid-js";
import { onCleanup } from "solid-js";
import { createStore, reconcile } from "solid-js/store";

/**
 * Subscribe to a Nano Stores store for the lifetime of the current Solid owner.
 */
export function useStore<
	SomeStore extends Store,
	Value extends StoreValue<SomeStore>,
>(store: SomeStore): Accessor<Value> {
	// Nano Stores needs to be activated before Solid captures its initial value.
	const unbindActivation = store.listen(() => {});
	const [state, setState] = createStore({ value: store.get() as Value });
	const unsubscribe = store.subscribe((newValue) => {
		setState("value", reconcile(newValue as Value));
	});

	onCleanup(unsubscribe);
	// The real subscription above now keeps the store active.
	unbindActivation();

	return () => state.value as Value;
}
