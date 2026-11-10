import { createAuthEndpoint } from "better-auth/api";
import { createNonce } from "../utils/nonce";

/**
 * Nonce Endpoint (OID4VCI 1.0 §7). The `c_nonce` it returns is the only
 * source of proof nonces; the token and credential responses carry none.
 */
export function createNonceEndpoint() {
	return createAuthEndpoint(
		"/oidc4vci/nonce",
		{
			method: "POST",
			metadata: { noStore: true },
		},
		async (ctx) => {
			return ctx.json({ c_nonce: await createNonce(ctx) });
		},
	);
}
