import { APIError, createAuthEndpoint } from "better-auth/api";
import type { JwtOptions } from "better-auth/plugins";
import * as z from "zod";
import { VERIFICATION_TYPES } from "../constants";
import {
	setNoStore,
	throwBearerTokenError,
	throwOidc4vciCredentialError,
} from "../error";
import { getNextStatusListIndex } from "../status-list";
import type { Oidc4vciOptions } from "../types";
import {
	filterClaimsForRequest,
	resolveClaimsForUser,
	resolveRequestedClaims,
} from "../utils/claims";
import { createNonce, NONCE_TTL_SECONDS } from "../utils/nonce";
import { requireCredentialAccessToken } from "../utils/proof";
import {
	getStatusListUri,
	resolveCredentialIssuer,
	resolveStatusListOptions,
} from "../utils/resolvers";
import { buildDisclosureFrame, issueSdJwtCredential } from "../utils/sd-jwt";
import { resolveStoreTokens, storeTokenIdentifier } from "../utils/token";
import { getOpenid4vciIssuer } from "./metadata";

export function createDeferredCredentialEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/credential/deferred",
		{
			method: "POST",
			requireRequest: true,
			body: z.any(),
		},
		async (ctx) => {
			if (typeof options.deferredIssuance?.shouldDefer !== "function") {
				throw new APIError("NOT_FOUND");
			}

			const { tokenPayload, subject } = await requireCredentialAccessToken(
				ctx,
				options,
			);

			const requestBody = ctx.body as Record<string, unknown> | null;
			if (!requestBody || typeof requestBody !== "object") {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"invalid request body",
				);
			}

			try {
				getOpenid4vciIssuer().parseDeferredCredentialRequest({
					deferredCredentialRequest: requestBody,
				});
			} catch (error) {
				const message =
					error instanceof Error
						? error.message
						: "invalid deferred credential request";
				throwOidc4vciCredentialError("invalid_credential_request", message);
			}

			const transactionId = requestBody.transaction_id;
			if (!transactionId || typeof transactionId !== "string") {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"transaction_id is required",
				);
			}

			const storeTokens = resolveStoreTokens(ctx);
			const identifier = await storeTokenIdentifier(
				storeTokens,
				transactionId,
				"transaction_id",
			);
			const verification =
				await ctx.context.internalAdapter.findVerificationValue(identifier);
			if (!verification?.expiresAt || verification.expiresAt < new Date()) {
				throwOidc4vciCredentialError(
					"invalid_transaction_id",
					"invalid or expired transaction_id",
				);
			}

			let verificationValue: any = null;
			try {
				verificationValue = JSON.parse(verification.value);
			} catch {
				throwOidc4vciCredentialError(
					"invalid_transaction_id",
					"invalid transaction_id",
				);
			}

			if (
				verificationValue?.type !== VERIFICATION_TYPES.DEFERRED_CREDENTIAL ||
				typeof verificationValue.credentialConfigurationId !== "string" ||
				typeof verificationValue.cnfJkt !== "string"
			) {
				throwOidc4vciCredentialError(
					"invalid_transaction_id",
					"invalid transaction_id",
				);
			}

			if (verificationValue.userId && verificationValue.userId !== subject) {
				throwOidc4vciCredentialError(
					"invalid_transaction_id",
					"invalid transaction_id",
				);
			}

			const azp = tokenPayload.azp;
			if (
				verificationValue.clientId &&
				typeof azp === "string" &&
				verificationValue.clientId !== azp
			) {
				throwOidc4vciCredentialError(
					"invalid_transaction_id",
					"invalid transaction_id",
				);
			}

			const cfg =
				options.credentialConfigurations.find(
					(c) => c.id === verificationValue.credentialConfigurationId,
				) ?? null;
			if (!cfg) {
				throwOidc4vciCredentialError(
					"invalid_transaction_id",
					"invalid transaction_id",
				);
			}

			const authorizationDetails = Array.isArray(
				(tokenPayload as any).authorization_details,
			)
				? ((tokenPayload as any).authorization_details as Record<
						string,
						unknown
					>[])
				: [];

			if (authorizationDetails.length) {
				const isAuthorized = authorizationDetails.some((detail) => {
					if (
						!detail ||
						typeof detail !== "object" ||
						(detail as { type?: string }).type !== "openid_credential"
					) {
						return false;
					}
					const typed = detail;
					return (
						typeof typed.credential_configuration_id === "string" &&
						typed.credential_configuration_id === cfg.id
					);
				});
				if (!isAuthorized) {
					throwBearerTokenError({
						status: "FORBIDDEN",
						error: "insufficient_scope",
						errorDescription:
							"access token not authorized for requested credential configuration",
					});
				}
			} else {
				const authorizedCredentialConfigurationId =
					tokenPayload.credential_configuration_id;
				if (
					typeof authorizedCredentialConfigurationId !== "string" ||
					authorizedCredentialConfigurationId !== cfg.id
				) {
					throwBearerTokenError({
						status: "FORBIDDEN",
						error: "insufficient_scope",
						errorDescription:
							"access token not authorized for requested credential configuration",
					});
				}
			}

			if (typeof options.deferredIssuance?.isReady === "function") {
				const clientId =
					typeof tokenPayload.azp === "string" ? tokenPayload.azp : undefined;
				const ready = await options.deferredIssuance.isReady({
					credentialConfigurationId: cfg.id,
					userId: subject,
					clientId,
				});
				if (!ready) {
					setNoStore(ctx);
					throwOidc4vciCredentialError(
						"issuance_pending",
						"credential issuance is pending",
						{
							interval: options.deferredIssuance.intervalSeconds ?? 5,
						},
					);
				}
			}

			const user = await ctx.context.internalAdapter.findUserById(subject);
			if (!user) {
				throw new APIError("BAD_REQUEST", { message: "user not found" });
			}

			const now = Math.floor(Date.now() / 1000);
			const exp = now + (options.credentialExpiresInSeconds ?? 31536000);
			const issuer = resolveCredentialIssuer(ctx, options);
			const jwtPlugin = ctx.context.getPlugin("jwt") as {
				options?: JwtOptions;
			} | null;
			if (!jwtPlugin) {
				throw new APIError("INTERNAL_SERVER_ERROR", {
					message: "jwt plugin is required",
				});
			}
			const statusListOptions = resolveStatusListOptions(options);
			const statusListId = statusListOptions.listId;
			const statusListIndex = await getNextStatusListIndex(ctx, statusListId);
			const statusListUri = getStatusListUri(ctx, options, statusListId);
			const requestedClaims = resolveRequestedClaims(authorizationDetails, {
				credentialConfigurationId: cfg.id,
			});
			const resolvedClaims = await resolveClaimsForUser(options, {
				user,
				credentialConfigurationId: cfg.id,
				requestedClaims,
			});
			const { claims: defaultClaims, missingMandatory } =
				filterClaimsForRequest(resolvedClaims, requestedClaims);
			if (missingMandatory.length) {
				throwOidc4vciCredentialError(
					"credential_request_denied",
					`missing required claims: ${missingMandatory.join(", ")}`,
				);
			}

			const sdJwtPayload = {
				iss: issuer,
				sub: subject,
				vct: cfg.vct,
				iat: now,
				exp,
				status: {
					status_list: {
						idx: statusListIndex,
						uri: statusListUri,
					},
				},
				cnf: {
					jkt: verificationValue.cnfJkt,
				},
				...defaultClaims,
			};

			const effectiveFormat = cfg.format ?? "dc+sd-jwt";
			const disclosureFrame = buildDisclosureFrame(
				cfg,
				sdJwtPayload,
				requestedClaims,
			);
			const { key: signingKey, alg: signingAlg } = await (
				await import("../utils/jwt")
			).getOrCreateSigningKey(ctx, jwtPlugin.options);
			const additionalHeaders = options.resolveCredentialHeaders
				? await options.resolveCredentialHeaders({
						kid: signingKey.id,
						alg: signingAlg,
						format: effectiveFormat,
						credentialConfigurationId: cfg.id,
					})
				: undefined;
			const credential = await issueSdJwtCredential(ctx, {
				payload: sdJwtPayload,
				jwtOptions: jwtPlugin.options,
				disclosureFrame,
				format: effectiveFormat,
				additionalHeaders,
				credentialSigner: options.credentialSigner,
			});

			await ctx.context.internalAdapter.deleteVerificationByIdentifier(
				verification.identifier,
			);

			await ctx.context.adapter.create({
				model: "oidc4vciIssuedCredential",
				data: {
					userId: user.id,
					credentialConfigurationId: cfg.id,
					format: effectiveFormat,
					statusListId,
					statusListIndex,
					status: 0,
					credential,
					createdAt: new Date(),
				},
			});

			const freshNonce = await createNonce({
				context: ctx.context,
				storeTokens,
			});

			setNoStore(ctx);
			return {
				credential,
				c_nonce: freshNonce,
				c_nonce_expires_in: NONCE_TTL_SECONDS,
			};
		},
	);
}
