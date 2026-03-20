type ApiRecord = Record<string, unknown>;

export function requireApi<
	TApi extends ApiRecord,
	const TKeys extends readonly (keyof TApi)[],
>(
	api: TApi,
	keys: TKeys,
	message = "Missing required API endpoints for test.",
): TApi & { [K in TKeys[number]]-?: NonNullable<TApi[K]> } {
	for (const key of keys) {
		if (!api[key]) {
			throw new Error(message);
		}
	}
	return api as TApi & { [K in TKeys[number]]-?: NonNullable<TApi[K]> };
}
