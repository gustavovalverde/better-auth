import type { GenericEndpointContext } from "@better-auth/core";
import { generateRandomString } from "better-auth/crypto";
import { VERIFICATION_TYPES } from "../constants";
import { hashIssuerToken } from "./token";

const NONCE_TTL_SECONDS = 300;

/** Issues a single-use `c_nonce` (OID4VCI 1.0 §7). */
export async function createNonce(ctx: GenericEndpointContext) {
	const now = new Date();
	const cNonce = generateRandomString(32, "a-z", "A-Z", "0-9");
	await ctx.context.internalAdapter.createVerificationValue({
		identifier: await hashIssuerToken(ctx, cNonce, "c_nonce"),
		value: JSON.stringify({ type: VERIFICATION_TYPES.C_NONCE }),
		createdAt: now,
		updatedAt: now,
		expiresAt: new Date(now.getTime() + NONCE_TTL_SECONDS * 1000),
	});
	return cNonce;
}
