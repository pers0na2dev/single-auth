import type { Store, StoreValue } from "nanostores";
import type { DeepReadonly, ShallowRef, UnwrapNestedRefs } from "vue";
import {
	getCurrentInstance,
	getCurrentScope,
	onScopeDispose,
	readonly,
	shallowRef,
} from "vue";

function registerStore(store: Store): void {
	const instance = getCurrentInstance();
	if (instance?.proxy) {
		const vm = instance.proxy as typeof instance.proxy & {
			_nanostores?: Store[];
		};
		(vm._nanostores ??= []).push(store);
	}
}

/**
 * Subscribe to a Nano Stores store for the lifetime of the current Vue scope.
 */
export function useStore<
	SomeStore extends Store,
	Value extends StoreValue<SomeStore>,
>(store: SomeStore): DeepReadonly<UnwrapNestedRefs<ShallowRef<Value>>> {
	const state = shallowRef<Value>() as ShallowRef<Value>;
	const unsubscribe = store.subscribe((value) => {
		state.value = value as Value;
	});

	if (getCurrentScope()) {
		onScopeDispose(unsubscribe);
	}

	if (process.env.NODE_ENV !== "production") {
		registerStore(store);
		return readonly(state) as DeepReadonly<
			UnwrapNestedRefs<ShallowRef<Value>>
		>;
	}

	return state as DeepReadonly<UnwrapNestedRefs<ShallowRef<Value>>>;
}
