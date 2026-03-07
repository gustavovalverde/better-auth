import { APIError, createAuthEndpoint } from "better-auth/api";
import type { JwtOptions } from "better-auth/plugins";
import {
	calculateJwkThumbprint,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";
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
import {
	matchCredentialConfigurationByFormat,
	verifyCredentialAuthorization,
} from "../utils/credential-request";
import { createNonce, NONCE_TTL_SECONDS } from "../utils/nonce";
import { requireCredentialAccessToken } from "../utils/proof";
import {
	getStatusListUri,
	resolveCredentialIssuer,
	resolveStatusListOptions,
} from "../utils/resolvers";
import { buildDisclosureFrame, issueSdJwtCredential } from "../utils/sd-jwt";
import { resolveStoreTokens, storeTokenIdentifier } from "../utils/token";
import { buildIssuerMetadataResult, getOpenid4vciIssuer } from "./metadata";

export function createCredentialEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/credential",
		{
			method: "POST",
			requireRequest: true,
			body: z.any(),
		},
		async (ctx) => {
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

			const credentialIdentifier = requestBody.credential_identifier;
			const requestedCredentialConfigurationId =
				requestBody.credential_configuration_id;
			const requestedFormat = requestBody.format;
			const requestedVct = requestBody.vct;
			const requestedDocType = requestBody.doctype;
			const requestedCredentialDefinition = requestBody.credential_definition;

			if (
				credentialIdentifier &&
				requestedCredentialConfigurationId !== undefined
			) {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"credential_configuration_id must not be provided when credential_identifier is used",
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

			const storeTokens = resolveStoreTokens(ctx);
			let resolvedCredentialConfigurationId: string | null = null;
			let credentialIdentifierVerificationIdentifier: string | null = null;
			let cfg: (typeof options.credentialConfigurations)[number] | null = null;

			if (typeof credentialIdentifier === "string" && credentialIdentifier) {
				const identifier = await storeTokenIdentifier(
					storeTokens,
					credentialIdentifier,
					"credential_identifier",
				);
				const verification =
					await ctx.context.internalAdapter.findVerificationValue(identifier);
				if (!verification?.expiresAt || verification.expiresAt < new Date()) {
					throwOidc4vciCredentialError(
						"unknown_credential_identifier",
						"credential_identifier is not recognized",
					);
				}

				let verificationValue: any = null;
				try {
					verificationValue = JSON.parse(verification.value);
				} catch {
					throwOidc4vciCredentialError(
						"unknown_credential_identifier",
						"credential_identifier is not recognized",
					);
				}
				if (
					verificationValue?.type !==
						VERIFICATION_TYPES.CREDENTIAL_IDENTIFIER ||
					typeof verificationValue.credentialConfigurationId !== "string"
				) {
					throwOidc4vciCredentialError(
						"unknown_credential_identifier",
						"credential_identifier is not recognized",
					);
				}

				if (verificationValue.userId && verificationValue.userId !== subject) {
					throwOidc4vciCredentialError(
						"unknown_credential_identifier",
						"credential_identifier is not recognized",
					);
				}

				const azp = tokenPayload.azp;
				if (
					verificationValue.clientId &&
					typeof azp === "string" &&
					verificationValue.clientId !== azp
				) {
					throwOidc4vciCredentialError(
						"unknown_credential_identifier",
						"credential_identifier is not recognized",
					);
				}

				resolvedCredentialConfigurationId =
					verificationValue.credentialConfigurationId;
				credentialIdentifierVerificationIdentifier = verification.identifier;

				cfg =
					options.credentialConfigurations.find(
						(c) => c.id === resolvedCredentialConfigurationId,
					) ?? null;
				if (!cfg) {
					throwOidc4vciCredentialError(
						"unknown_credential_configuration",
						"unsupported credential configuration",
					);
				}

				const authError = verifyCredentialAuthorization({
					authorizationDetails,
					credentialConfigurationId: resolvedCredentialConfigurationId!,
					credentialIdentifier:
						typeof credentialIdentifier === "string"
							? credentialIdentifier
							: undefined,
					tokenPayload: tokenPayload as Record<string, unknown>,
				});
				if (authError) {
					throwBearerTokenError({
						status: "FORBIDDEN",
						error: authError.error,
						errorDescription: authError.errorDescription,
					});
				}
			} else {
				if (
					requestedCredentialConfigurationId &&
					typeof requestedCredentialConfigurationId === "string"
				) {
					resolvedCredentialConfigurationId =
						requestedCredentialConfigurationId;

					cfg =
						options.credentialConfigurations.find(
							(c) => c.id === resolvedCredentialConfigurationId,
						) ?? null;
					if (!cfg) {
						throwOidc4vciCredentialError(
							"unknown_credential_configuration",
							"unsupported credential configuration",
						);
					}
				} else if (requestedFormat && typeof requestedFormat === "string") {
					cfg = matchCredentialConfigurationByFormat(
						options.credentialConfigurations,
						{
							format: requestedFormat,
							vct: requestedVct,
							doctype: requestedDocType,
							credentialDefinition: requestedCredentialDefinition,
						},
					);

					if (!cfg) {
						throwOidc4vciCredentialError(
							"unsupported_credential_format",
							"no credential configuration matches the requested format",
						);
					}
					resolvedCredentialConfigurationId = cfg.id;
				} else {
					throwOidc4vciCredentialError(
						"invalid_credential_request",
						"credential_configuration_id or format is required",
					);
				}

				const authError = verifyCredentialAuthorization({
					authorizationDetails,
					credentialConfigurationId: resolvedCredentialConfigurationId,
					tokenPayload: tokenPayload as Record<string, unknown>,
				});
				if (authError) {
					throwBearerTokenError({
						status: "FORBIDDEN",
						error: authError.error,
						errorDescription: authError.errorDescription,
					});
				}
			}

			if (!cfg) {
				throwOidc4vciCredentialError(
					"unknown_credential_configuration",
					"unsupported credential configuration",
				);
			}

			if (requestedCredentialConfigurationId || credentialIdentifier) {
				try {
					const issuerMetadata = buildIssuerMetadataResult(ctx, options);
					getOpenid4vciIssuer().parseCredentialRequest({
						issuerMetadata,
						credentialRequest: requestBody,
					});
				} catch (error) {
					const message =
						error instanceof Error
							? error.message
							: "invalid credential request";
					throwOidc4vciCredentialError("invalid_credential_request", message);
				}
			}

			if (requestedFormat && typeof requestedFormat !== "string") {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"invalid format",
				);
			}
			const effectiveFormat = cfg.format ?? "dc+sd-jwt";
			if (requestedFormat && requestedFormat !== effectiveFormat) {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"unsupported format",
				);
			}

			const proofsObj = requestBody.proofs as
				| { jwt?: unknown }
				| undefined
				| null;
			const proofObj = requestBody.proof as
				| { proof_type?: unknown; jwt?: unknown; [key: string]: unknown }
				| undefined
				| null;

			const issuerAudience = resolveCredentialIssuer(ctx, options);
			const azpForProof =
				typeof tokenPayload.azp === "string" ? tokenPayload.azp : undefined;

			let cnfJkt: string;
			let cNonce: string;
			let extraCnf: Record<string, unknown> | undefined;

			const proofType =
				proofObj && typeof proofObj.proof_type === "string"
					? proofObj.proof_type
					: undefined;
			const customValidator =
				proofType &&
				proofType !== "jwt" &&
				options.proofValidators?.[proofType];

			if (customValidator) {
				const result = await customValidator({
					proof: proofObj as Record<string, unknown>,
					nonce: "",
					audience: issuerAudience,
					userId: subject,
					clientId: azpForProof,
				});
				cnfJkt = result.jkt;
				cNonce = result.cNonce;
				extraCnf = result.extraCnf;
			} else {
				const proofJwt =
					(proofsObj &&
					Array.isArray((proofsObj as any).jwt) &&
					(proofsObj as any).jwt.length &&
					typeof (proofsObj as any).jwt[0] === "string"
						? ((proofsObj as any).jwt[0] as string)
						: undefined) ??
					(proofObj &&
					typeof (proofObj as any).jwt === "string" &&
					(proofObj as any).proof_type === "jwt"
						? ((proofObj as any).jwt as string)
						: undefined);

				if (!proofJwt) {
					throwOidc4vciCredentialError("invalid_proof", "missing proof");
				}

				if (proofObj && (proofObj as any).proof_type !== "jwt") {
					throwOidc4vciCredentialError(
						"invalid_proof",
						"unsupported proof_type",
					);
				}

				let header: ReturnType<typeof decodeProtectedHeader>;
				try {
					header = decodeProtectedHeader(proofJwt);
				} catch {
					throwOidc4vciCredentialError("invalid_proof", "invalid proof");
				}
				if (header.typ !== "openid4vci-proof+jwt") {
					throwOidc4vciCredentialError("invalid_proof", "invalid proof typ");
				}

				if (!header.jwk) {
					throwOidc4vciCredentialError(
						"invalid_proof",
						"missing proof jwk header",
					);
				}
				const alg = typeof header.alg === "string" ? header.alg : undefined;
				if (!alg || alg === "none" || alg.startsWith("HS")) {
					throwOidc4vciCredentialError("invalid_proof", "invalid proof alg");
				}

				let verifiedProof: {
					payload: {
						nonce?: string;
						aud?: string;
						iat?: number;
					};
				};
				try {
					const key = await importJWK(header.jwk as any, alg);
					verifiedProof = await jwtVerify(proofJwt, key, {
						audience: issuerAudience,
					});
				} catch {
					throwOidc4vciCredentialError("invalid_proof", "invalid proof");
				}

				if (!verifiedProof.payload.nonce) {
					throwOidc4vciCredentialError("invalid_proof", "missing proof nonce");
				}
				if (typeof verifiedProof.payload.iat !== "number") {
					throwOidc4vciCredentialError("invalid_proof", "missing proof iat");
				}

				cnfJkt = await calculateJwkThumbprint(header.jwk as any);
				cNonce = verifiedProof.payload.nonce;
			}

			const nonceIdentifier = await storeTokenIdentifier(
				storeTokens,
				cNonce,
				"c_nonce",
			);
			const verification =
				await ctx.context.internalAdapter.findVerificationValue(
					nonceIdentifier,
				);
			if (!verification?.expiresAt || verification.expiresAt < new Date()) {
				throwOidc4vciCredentialError(
					"invalid_nonce",
					"invalid or expired c_nonce",
				);
			}

			let verificationValue: any = null;
			try {
				verificationValue = JSON.parse(verification.value);
			} catch {
				throwOidc4vciCredentialError("invalid_nonce", "invalid c_nonce");
			}

			if (verificationValue?.type !== VERIFICATION_TYPES.C_NONCE) {
				throwOidc4vciCredentialError("invalid_nonce", "invalid c_nonce");
			}

			if (verificationValue.userId && verificationValue.userId !== subject) {
				throwOidc4vciCredentialError("invalid_nonce", "invalid c_nonce");
			}

			if (
				verificationValue.clientId &&
				typeof azpForProof === "string" &&
				verificationValue.clientId !== azpForProof
			) {
				throwOidc4vciCredentialError("invalid_nonce", "invalid c_nonce");
			}

			await ctx.context.internalAdapter.deleteVerificationByIdentifier(
				verification.identifier,
			);
			if (credentialIdentifierVerificationIdentifier) {
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(
					credentialIdentifierVerificationIdentifier,
				);
			}

			const user = await ctx.context.internalAdapter.findUserById(subject);
			if (!user) {
				throw new APIError("BAD_REQUEST", { message: "user not found" });
			}

			const now = Math.floor(Date.now() / 1000);
			const exp = now + (options.credentialExpiresInSeconds ?? 31536000);

			const issuer = issuerAudience;
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

			const shouldDefer = options.deferredIssuance?.shouldDefer;
			if (typeof shouldDefer === "function") {
				const clientId =
					typeof tokenPayload.azp === "string" ? tokenPayload.azp : undefined;
				const defer = await shouldDefer({
					credentialConfigurationId: cfg.id,
					userId: subject,
					clientId,
				});
				if (defer) {
					const nowDate = new Date();
					const expiresInSeconds =
						options.deferredIssuance?.transactionExpiresInSeconds ?? 3600;
					const expiresAt = new Date(
						nowDate.getTime() + expiresInSeconds * 1000,
					);
					const transactionId = crypto.randomUUID().replaceAll("-", "");
					const storeTokens = resolveStoreTokens(ctx);
					const identifier = await storeTokenIdentifier(
						storeTokens,
						transactionId,
						"transaction_id",
					);

					await ctx.context.internalAdapter.createVerificationValue({
						identifier,
						value: JSON.stringify({
							type: VERIFICATION_TYPES.DEFERRED_CREDENTIAL,
							userId: subject,
							clientId,
							credentialConfigurationId: cfg.id,
							cnfJkt,
						}),
						createdAt: nowDate,
						updatedAt: nowDate,
						expiresAt,
					});

					setNoStore(ctx);
					ctx.setStatus(202);
					return ctx.json({
						transaction_id: transactionId,
						interval: options.deferredIssuance?.intervalSeconds ?? 3600,
					});
				}
			}

			const requestedClaims = resolveRequestedClaims(authorizationDetails, {
				credentialConfigurationId: cfg.id,
				credentialIdentifier:
					typeof credentialIdentifier === "string"
						? credentialIdentifier
						: undefined,
			});
			const resolvedClaims = await resolveClaimsForUser(options, {
				user,
				credentialConfigurationId: cfg.id,
				credentialIdentifier:
					typeof credentialIdentifier === "string"
						? credentialIdentifier
						: undefined,
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
					jkt: cnfJkt,
					...extraCnf,
				},
				...defaultClaims,
			};

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
