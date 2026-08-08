const WORD_PATTERN =
	/[\p{Ll}\d]+|\p{Lu}+(?!\p{Ll})|\p{Lu}[\p{Ll}\d]+|\p{Lo}+/gu;
const APOSTROPHE_PATTERN = /['\u2019]/g;

function splitWords(input: string): string[] {
	return input.replace(APOSTROPHE_PATTERN, "").match(WORD_PATTERN) ?? [];
}

export function capitalizeFirstLetter(value: string): string {
	return value.charAt(0).toUpperCase() + value.slice(1);
}

export function toKebabCase(value: string): string {
	return splitWords(value)
		.map((word) => word.toLowerCase())
		.join("-");
}
