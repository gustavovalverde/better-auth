import { APIError, createAuthEndpoint } from "better-auth/api";
import type { JWK } from "jose";
import * as z from "zod";
import { VERIFICATION_TYPES } from "../constants";
import { throwBearerTokenError, throwOidc4vciCredentialError } from "../error";
import { issueCredential } from "../issuance";
import type { Oidc4vciOptions } from "../types";
import { verifyCredentialAuthorization } from "../utils/credential-request";
import { requireCredentialAccessToken } from "../utils/proof";
import { resolveDeferredEndpoint } from "../utils/resolvers";
import { hashIssuerToken } from "../utils/token";
import { buildIssuerMetadataResult, getOpenid4vciIssuer } from "./metadata";

type DeferredValue = {
	type?: string;
	userId?: string;
	clientId?: string;
	credentialConfigurationId?: unknown;
	credentialIdentifier?: string;
	jwk?: JWK;
	extraCnf?: Record<string, unknown>;
};

function invalidTransaction(description = "invalid transaction_id"): never {
	throwOidc4vciCredentialError("invalid_transaction_id", description);
}

/**
 * Deferred Credential Endpoint (OID4VCI 1.0 §9). A transaction that is not
 * ready yet answers 202 with `interval`; a ready one issues the credential
 * and invalidates the `transaction_id`.
 */
export function createDeferredCredentialEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/credential/deferred",
		{
			method: "POST",
			requireRequest: true,
			body: z.record(z.string(), z.unknown()),
			metadata: { noStore: true },
		},
		async (ctx) => {
			if (typeof options.deferredIssuance?.shouldDefer !== "function") {
				throw new APIError("NOT_FOUND");
			}

			const { tokenPayload, subject } = await requireCredentialAccessToken(
				ctx,
				options,
				resolveDeferredEndpoint(ctx, options),
			);
			const requestBody = ctx.body;

			try {
				await getOpenid4vciIssuer().parseDeferredCredentialRequest({
					deferredCredentialRequest: requestBody,
					contentType: "application/json",
					issuerMetadata: buildIssuerMetadataResult(ctx, options),
				});
			} catch (error) {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					error instanceof Error
						? error.message
						: "invalid deferred credential request",
				);
			}

			const transactionId = requestBody.transaction_id;
			if (!transactionId || typeof transactionId !== "string") {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"transaction_id is required",
				);
			}

			const identifier = await hashIssuerToken(
				ctx,
				transactionId,
				"transaction_id",
			);
			const verification =
				await ctx.context.internalAdapter.findVerificationValue(identifier);
			if (!verification?.expiresAt || verification.expiresAt <= new Date()) {
				invalidTransaction("invalid or expired transaction_id");
			}
			let value: DeferredValue;
			try {
				value = JSON.parse(verification.value) as DeferredValue;
			} catch {
				invalidTransaction();
			}
			const azp =
				typeof tokenPayload.azp === "string" ? tokenPayload.azp : undefined;
			if (
				value.type !== VERIFICATION_TYPES.DEFERRED_CREDENTIAL ||
				typeof value.credentialConfigurationId !== "string" ||
				!value.jwk ||
				(value.userId && value.userId !== subject) ||
				(value.clientId && azp && value.clientId !== azp)
			) {
				invalidTransaction();
			}
			const cfg = options.credentialConfigurations.find(
				(c) => c.id === value.credentialConfigurationId,
			);
			if (!cfg) {
				invalidTransaction();
			}

			const authorizationDetails = Array.isArray(
				tokenPayload.authorization_details,
			)
				? (tokenPayload.authorization_details as Record<string, unknown>[])
				: [];
			const authError = verifyCredentialAuthorization({
				authorizationDetails,
				credentialConfigurationId: cfg.id,
				credentialIdentifier: value.credentialIdentifier,
				credentialScope: cfg.scope,
				tokenPayload: tokenPayload as Record<string, unknown>,
			});
			if (authError) {
				throwBearerTokenError({
					status: "FORBIDDEN",
					error: authError.error,
					errorDescription: authError.errorDescription,
				});
			}

			if (typeof options.deferredIssuance?.isReady === "function") {
				const ready = await options.deferredIssuance.isReady({
					credentialConfigurationId: cfg.id,
					userId: subject,
					clientId: azp,
				});
				if (!ready) {
					ctx.setStatus(202);
					return ctx.json({
						transaction_id: transactionId,
						interval: options.deferredIssuance.intervalSeconds ?? 3600,
					});
				}
			}

			const user = await ctx.context.internalAdapter.findUserById(subject);
			if (!user) {
				throw new APIError("BAD_REQUEST", { message: "user not found" });
			}
			if (
				!(await ctx.context.internalAdapter.consumeVerificationValue(
					identifier,
				))
			) {
				invalidTransaction();
			}

			const credential = await issueCredential(ctx, options, {
				cfg,
				user,
				subject,
				binding: { jwk: value.jwk, extraCnf: value.extraCnf },
				authorizationDetails,
				credentialIdentifier: value.credentialIdentifier,
			});
			return ctx.json({ credentials: [{ credential }] });
		},
	);
}
