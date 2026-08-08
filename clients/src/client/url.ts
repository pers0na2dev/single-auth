const DEFAULT_BASE_PATH = "/api/auth";

function normalizeBasePath(path = DEFAULT_BASE_PATH): string {
	if (path === "/") return "/";
	if (!path.startsWith("/")) path = `/${path}`;
	if (
		path.includes("\\") ||
		path.includes("?") ||
		path.includes("#") ||
		path.split("/").includes("..")
	) {
		throw new TypeError(`Invalid single-auth base path: ${path}`);
	}
	return path.replace(/\/+$/, "") || "/";
}

function withPath(value: string, path?: string): string {
	let url: URL;
	try {
		url = new URL(value);
	} catch (cause) {
		throw new TypeError(`Invalid single-auth base URL: ${value}`, { cause });
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new TypeError(
			`Invalid single-auth base URL protocol: ${url.protocol || "unknown"}`,
		);
	}
	if (url.username || url.password || url.search || url.hash) {
		throw new TypeError(
			"single-auth base URL cannot contain credentials, a query, or a fragment",
		);
	}

	const existingPath = url.pathname.replace(/\/+$/, "");
	if (existingPath && existingPath !== "/") {
		url.pathname = existingPath;
		return url.toString().replace(/\/$/, "");
	}

	const normalizedPath = normalizeBasePath(path);
	url.pathname = normalizedPath;
	return url.toString().replace(/\/$/, normalizedPath === "/" ? "" : "");
}

function configuredURL(): string | undefined {
	if (typeof process === "undefined") return undefined;
	return (
		process.env.NEXT_PUBLIC_SINGLE_AUTH_URL ??
		(typeof window === "undefined" ? process.env.SINGLE_AUTH_URL : undefined)
	);
}

export function getBaseURL(
	baseURL?: string | undefined,
	basePath?: string | undefined,
	loadEnv = true,
): string {
	if (baseURL) return withPath(baseURL, basePath);

	if (loadEnv) {
		const fromEnvironment = configuredURL();
		if (fromEnvironment) return withPath(fromEnvironment, basePath);
	}

	if (typeof window !== "undefined" && window.location?.origin) {
		return withPath(window.location.origin, basePath);
	}

	return normalizeBasePath(basePath);
}

export function isSafeURLScheme(value: string): boolean {
	let parsed: URL;
	try {
		parsed = new URL(value, "https://single-auth.invalid");
	} catch {
		return false;
	}
	return !["javascript:", "data:", "vbscript:"].includes(parsed.protocol);
}
