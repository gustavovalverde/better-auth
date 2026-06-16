import { createAuthEndpoint } from "better-auth/api";
import { setNoStore } from "../error";
import { createNonce, NONCE_TTL_SECONDS } from "../utils/nonce";
import { resolveStoreTokens } from "../utils/token";

export function createNonceEndpoint() {
	return createAuthEndpoint(
		"/oidc4vci/nonce",
		{
			method: "POST",
		},
		async (ctx) => {
			setNoStore(ctx);
			const storeTokens = resolveStoreTokens(ctx);
			const cNonce = await createNonce({
				context: ctx.context,
				storeTokens,
			});

			return {
				c_nonce: cNonce,
				c_nonce_expires_in: NONCE_TTL_SECONDS,
			};
		},
	);
}
