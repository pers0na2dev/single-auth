const PROTOTYPE_POLLUTION_PATTERNS = [
	/"(?:_|\\u0{2}5[Ff]){2}(?:p|\\u0{2}70)(?:r|\\u0{2}72)(?:o|\\u0{2}6[Ff])(?:t|\\u0{2}74)(?:o|\\u0{2}6[Ff])(?:_|\\u0{2}5[Ff]){2}"\s*:/,
	/"(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:/,
	/"__proto__"\s*:/,
	/"constructor"\s*:/,
] as const;

const JSON_SIGNATURE =
	/^\s*["[{]|^\s*-?\d{1,16}(\.\d{1,17})?([Ee][+-]?\d+)?\s*$/;

const SPECIAL_VALUES = {
	true: true,
	false: false,
	null: null,
	undefined: undefined,
	nan: Number.NaN,
	infinity: Number.POSITIVE_INFINITY,
	"-infinity": Number.NEGATIVE_INFINITY,
} as const;

const ISO_DATE =
	/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

export interface ParseJSONOptions {
	strict?: boolean | undefined;
	warnings?: boolean | undefined;
	reviver?: ((key: string, value: any) => any) | undefined;
	parseDates?: boolean | undefined;
}

function parseISODate(value: string): Date | null {
	const match = ISO_DATE.exec(value);
	if (!match) return null;
	const [, year, month, day, hour, minute, second, millis, sign, offsetHour, offsetMinute] =
		match;
	const date = new Date(
		Date.UTC(
			Number.parseInt(year!, 10),
			Number.parseInt(month!, 10) - 1,
			Number.parseInt(day!, 10),
			Number.parseInt(hour!, 10),
			Number.parseInt(minute!, 10),
			Number.parseInt(second!, 10),
			millis ? Number.parseInt(millis.padEnd(3, "0").slice(0, 3), 10) : 0,
		),
	);
	if (sign) {
		const offset =
			(Number.parseInt(offsetHour!, 10) * 60 +
				Number.parseInt(offsetMinute!, 10)) *
			(sign === "+" ? -1 : 1);
		date.setUTCMinutes(date.getUTCMinutes() + offset);
	}
	return Number.isNaN(date.getTime()) ? null : date;
}

export function parseJSON<T = unknown>(
	value: unknown,
	options: ParseJSONOptions = { strict: true },
): T {
	const {
		strict = false,
		warnings = false,
		reviver,
		parseDates = true,
	} = options;
	if (typeof value !== "string") return value as T;

	const trimmed = value.trim();
	const lower = trimmed.toLowerCase();
	if (lower.length <= 9 && lower in SPECIAL_VALUES) {
		return SPECIAL_VALUES[lower as keyof typeof SPECIAL_VALUES] as T;
	}
	if (!JSON_SIGNATURE.test(trimmed)) {
		if (strict) throw new SyntaxError("[single-auth-json] Invalid JSON");
		return value as T;
	}

	const suspicious = PROTOTYPE_POLLUTION_PATTERNS.some((pattern) =>
		pattern.test(trimmed),
	);
	if (suspicious && strict) {
		throw new Error(
			"[single-auth-json] Potential prototype pollution attempt detected",
		);
	}
	if (suspicious && warnings) {
		console.warn(
			"[single-auth-json] Dropping a potential prototype pollution key",
		);
	}

	try {
		return JSON.parse(trimmed, (key, parsedValue) => {
			if (
				key === "__proto__" ||
				(key === "constructor" &&
					parsedValue &&
					typeof parsedValue === "object" &&
					"prototype" in parsedValue)
			) {
				return undefined;
			}
			if (parseDates && typeof parsedValue === "string") {
				const date = parseISODate(parsedValue);
				if (date) return date;
			}
			return reviver ? reviver(key, parsedValue) : parsedValue;
		}) as T;
	} catch (error) {
		if (strict) throw error;
		return value as T;
	}
}
