import { VERIFICATION_TYPES } from "../constants";
import type { StoreTokens } from "../types";
import { storeTokenIdentifier } from "./token";

export const NONCE_TTL_SECONDS = 300;

export async function createNonce(ctx: {
	context: {
		internalAdapter: {
			createVerificationValue: (data: {
				identifier: string;
				value: string;
				createdAt: Date;
				updatedAt: Date;
				expiresAt: Date;
			}) => Promise<unknown>;
		};
	};
	storeTokens: StoreTokens;
}) {
	const now = new Date();
	const expiresAt = new Date(now.getTime() + NONCE_TTL_SECONDS * 1000);

	const cNonce = crypto.randomUUID().replaceAll("-", "");
	const identifier = await storeTokenIdentifier(
		ctx.storeTokens,
		cNonce,
		"c_nonce",
	);
	await ctx.context.internalAdapter.createVerificationValue({
		identifier,
		value: JSON.stringify({
			type: VERIFICATION_TYPES.C_NONCE,
		}),
		createdAt: now,
		updatedAt: now,
		expiresAt,
	});

	return cNonce;
}
