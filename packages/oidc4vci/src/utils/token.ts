import { createHash } from "@better-auth/utils/hash";
import type { StoreTokens, StoreTokenType } from "../types";

export function resolveStoreTokens(ctx: {
	context: {
		getPlugin: (id: string) => { options?: { storeTokens?: unknown } } | null;
	};
}): StoreTokens {
	const plugin = ctx.context.getPlugin("oauth-provider");
	const storeTokens = plugin?.options?.storeTokens;
	if (!storeTokens || storeTokens === "hashed") {
		return "hashed";
	}
	if (
		typeof storeTokens === "object" &&
		storeTokens &&
		"hash" in storeTokens &&
		typeof (storeTokens as { hash?: unknown }).hash === "function"
	) {
		return storeTokens as StoreTokens;
	}
	return "hashed";
}

export async function storeTokenIdentifier(
	storeTokens: StoreTokens,
	token: string,
	type: StoreTokenType,
) {
	if (storeTokens === "hashed") {
		return createHash("SHA-256", "base64urlnopad").digest(token);
	}
	return await storeTokens.hash(token, type);
}
