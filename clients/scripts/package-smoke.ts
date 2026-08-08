const [browser, react, next, vue, solid] = await Promise.all([
	import("@pers0na2dev/single-auth"),
	import("@pers0na2dev/single-auth/react"),
	import("@pers0na2dev/single-auth/next-js"),
	import("@pers0na2dev/single-auth/vue"),
	import("@pers0na2dev/single-auth/solid"),
]);

const expectedFunctions: Array<[string, unknown]> = [
	["browser createAuthClient", browser.createAuthClient],
	["React createAuthClient", react.createAuthClient],
	["Next toNextJsHandler", next.toNextJsHandler],
	["Next createNextJsProxyHandler", next.createNextJsProxyHandler],
	["Next getNextSession", next.getNextSession],
	["Vue createAuthClient", vue.createAuthClient],
	["Solid createAuthClient", solid.createAuthClient],
];

for (const [name, value] of expectedFunctions) {
	if (typeof value !== "function") {
		throw new TypeError(`${name} is missing from the built package`);
	}
}

console.log("single-auth client package exports: ok");
