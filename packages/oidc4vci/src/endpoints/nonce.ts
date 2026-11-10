import { createAuthEndpoint } from "better-auth/api";
import { createNonce } from "../utils/nonce";

/**
 * Nonce Endpoint (OID4VCI 1.0 §7). The `c_nonce` it returns is the only
 * source of proof nonces; the token and credential responses carry none.
 * The Nonce Request is a POST with no body and no Content-Type (§7.1), so
 * the body is never parsed.
 */
export function createNonceEndpoint() {
	return createAuthEndpoint(
		"/oidc4vci/nonce",
		{
			method: "POST",
			disableBody: true,
			metadata: { noStore: true },
		},
		async (ctx) => {
			return ctx.json({ c_nonce: await createNonce(ctx) });
		},
	);
}
