import type { GenericEndpointContext } from "@better-auth/core";
import { APIError, createAuthEndpoint } from "better-auth/api";
import type { JWK } from "jose";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import * as z from "zod";
import { SUPPORTED_PROOF_ALGS, VERIFICATION_TYPES } from "../constants";
import { throwBearerTokenError, throwOidc4vciCredentialError } from "../error";
import type { HolderBinding } from "../issuance";
import { issueCredential } from "../issuance";
import type { CredentialConfiguration, Oidc4vciOptions } from "../types";
import { verifyCredentialAuthorization } from "../utils/credential-request";
import { requireCredentialAccessToken } from "../utils/proof";
import {
	resolveCredentialEndpoint,
	resolveCredentialIssuer,
} from "../utils/resolvers";
import { hashIssuerToken } from "../utils/token";
import { buildIssuerMetadataResult, getOpenid4vciIssuer } from "./metadata";

const JWT_PROOF_TYP = "openid4vci-proof+jwt";
const JWK_PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const PROOF_CLOCK_TOLERANCE_SECONDS = 5;

function parseJson<T>(raw: string): T | null {
	try {
		return JSON.parse(raw) as T;
	} catch {
		return null;
	}
}

function getAuthorizationDetails(tokenPayload: Record<string, unknown>) {
	return Array.isArray(tokenPayload.authorization_details)
		? (tokenPayload.authorization_details as Record<string, unknown>[])
		: [];
}

function isPublicJwk(value: unknown): value is JWK {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const jwk = value as JWK;
	return (
		typeof jwk.kty === "string" &&
		jwk.kty !== "oct" &&
		!JWK_PRIVATE_MEMBERS.some((member) => member in jwk)
	);
}

/**
 * Validates a `jwt` proof (OID4VCI 1.0 Appendix F.1): typed, signed with an
 * asymmetric algorithm by the key in its `jwk` header, addressed to this
 * Credential Issuer, fresh, and carrying a `c_nonce`.
 */
async function validateJwtProof(
	proofJwt: unknown,
	audience: string,
	maxAgeSeconds: number,
) {
	if (typeof proofJwt !== "string") {
		throwOidc4vciCredentialError(
			"invalid_proof",
			"proof must be a compact JWT",
		);
	}
	let header: ReturnType<typeof decodeProtectedHeader>;
	try {
		header = decodeProtectedHeader(proofJwt);
	} catch {
		throwOidc4vciCredentialError("invalid_proof", "invalid proof");
	}
	if (header.typ !== JWT_PROOF_TYP) {
		throwOidc4vciCredentialError("invalid_proof", "invalid proof typ");
	}
	const alg = typeof header.alg === "string" ? header.alg : undefined;
	if (!alg || !(SUPPORTED_PROOF_ALGS as readonly string[]).includes(alg)) {
		throwOidc4vciCredentialError("invalid_proof", "invalid proof alg");
	}
	if (!isPublicJwk(header.jwk)) {
		throwOidc4vciCredentialError(
			"invalid_proof",
			"proof must carry the holder public key in its jwk header",
		);
	}
	let payload: { nonce?: unknown; iat?: unknown };
	try {
		const key = await importJWK(header.jwk, alg);
		({ payload } = await jwtVerify(proofJwt, key, {
			audience,
			algorithms: [alg],
			clockTolerance: PROOF_CLOCK_TOLERANCE_SECONDS,
		}));
	} catch {
		throwOidc4vciCredentialError("invalid_proof", "invalid proof");
	}
	if (typeof payload.iat !== "number") {
		throwOidc4vciCredentialError("invalid_proof", "missing proof iat");
	}
	const now = Math.floor(Date.now() / 1000);
	if (
		payload.iat > now + PROOF_CLOCK_TOLERANCE_SECONDS ||
		now - payload.iat > maxAgeSeconds + PROOF_CLOCK_TOLERANCE_SECONDS
	) {
		throwOidc4vciCredentialError("invalid_proof", "proof iat is not fresh");
	}
	if (typeof payload.nonce !== "string" || !payload.nonce) {
		throwOidc4vciCredentialError("invalid_proof", "missing proof nonce");
	}
	return { jwk: header.jwk, cNonce: payload.nonce };
}

/**
 * Resolves the holder binding from the `proofs` parameter. Batch issuance is
 * not supported, so exactly one proof of one type is accepted. The singular
 * `proof` parameter was removed in OID4VCI 1.0 and is rejected.
 */
async function resolveHolderBinding(
	options: Oidc4vciOptions,
	requestBody: Record<string, unknown>,
	context: { audience: string; userId: string; clientId?: string },
): Promise<HolderBinding & { cNonce: string }> {
	if (requestBody.proof !== undefined) {
		throwOidc4vciCredentialError(
			"invalid_credential_request",
			"the proof parameter is not supported; use proofs",
		);
	}
	const proofs = requestBody.proofs;
	if (!proofs || typeof proofs !== "object" || Array.isArray(proofs)) {
		throwOidc4vciCredentialError("invalid_proof", "missing proofs");
	}
	const entries = Object.entries(proofs as Record<string, unknown>);
	if (entries.length !== 1) {
		throwOidc4vciCredentialError(
			"invalid_proof",
			"proofs must contain exactly one proof type",
		);
	}
	const [proofType, values] = entries[0]!;
	if (!Array.isArray(values) || values.length !== 1) {
		throwOidc4vciCredentialError(
			"invalid_proof",
			"exactly one proof is supported; batch issuance is not enabled",
		);
	}
	const proof = values[0];

	if (proofType === "jwt") {
		return validateJwtProof(
			proof,
			context.audience,
			options.proofMaxAgeSeconds ?? 300,
		);
	}
	const validator = options.proofValidators?.[proofType];
	if (!validator) {
		throwOidc4vciCredentialError("invalid_proof", "unsupported proof type");
	}
	try {
		const result = await validator({
			proof,
			proofType,
			audience: context.audience,
			userId: context.userId,
			clientId: context.clientId,
		});
		if (!isPublicJwk(result.jwk) || typeof result.cNonce !== "string") {
			throw new Error("proof validator returned no holder key or nonce");
		}
		return {
			jwk: result.jwk,
			cNonce: result.cNonce,
			extraCnf: result.extraCnf,
		};
	} catch (error) {
		if (error instanceof APIError) throw error;
		throwOidc4vciCredentialError(
			"invalid_proof",
			error instanceof Error ? error.message : "invalid proof",
		);
	}
}

/**
 * Peeks at a `c_nonce` and returns its identifier. The nonce is claimed only
 * after every other check passes.
 */
async function checkNonce(ctx: GenericEndpointContext, cNonce: string) {
	const identifier = await hashIssuerToken(ctx, cNonce, "c_nonce");
	const verification =
		await ctx.context.internalAdapter.findVerificationValue(identifier);
	const value = verification
		? parseJson<{ type?: string }>(verification.value)
		: null;
	if (
		!verification?.expiresAt ||
		verification.expiresAt <= new Date() ||
		value?.type !== VERIFICATION_TYPES.C_NONCE
	) {
		throwOidc4vciCredentialError("invalid_nonce", "invalid or expired c_nonce");
	}
	return identifier;
}

type CredentialIdentifierValue = {
	type?: string;
	credentialConfigurationId?: unknown;
	userId?: string;
	clientId?: string;
};

export function createCredentialEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/credential",
		{
			method: "POST",
			requireRequest: true,
			body: z.record(z.string(), z.unknown()),
			metadata: { noStore: true },
		},
		async (ctx) => {
			const { tokenPayload, subject } = await requireCredentialAccessToken(
				ctx,
				options,
				resolveCredentialEndpoint(ctx, options),
			);
			const requestBody = ctx.body;
			const azp =
				typeof tokenPayload.azp === "string" ? tokenPayload.azp : undefined;

			if (requestBody.format !== undefined) {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"format-based credential requests are not supported; use credential_configuration_id or credential_identifier",
				);
			}

			const credentialIdentifier = requestBody.credential_identifier;
			const requestedConfigurationId = requestBody.credential_configuration_id;
			if (
				credentialIdentifier !== undefined &&
				requestedConfigurationId !== undefined
			) {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"credential_configuration_id must not be provided when credential_identifier is used",
				);
			}

			const authorizationDetails = getAuthorizationDetails(
				tokenPayload as Record<string, unknown>,
			);
			let cfg: CredentialConfiguration | undefined;
			let credentialIdentifierRecord: string | undefined;

			if (typeof credentialIdentifier === "string" && credentialIdentifier) {
				const identifier = await hashIssuerToken(
					ctx,
					credentialIdentifier,
					"credential_identifier",
				);
				const verification =
					await ctx.context.internalAdapter.findVerificationValue(identifier);
				const value = verification
					? parseJson<CredentialIdentifierValue>(verification.value)
					: null;
				if (
					!verification?.expiresAt ||
					verification.expiresAt <= new Date() ||
					value?.type !== VERIFICATION_TYPES.CREDENTIAL_IDENTIFIER ||
					typeof value.credentialConfigurationId !== "string" ||
					(value.userId && value.userId !== subject) ||
					(value.clientId && azp && value.clientId !== azp)
				) {
					throwOidc4vciCredentialError(
						"unknown_credential_identifier",
						"credential_identifier is not recognized",
					);
				}
				cfg = options.credentialConfigurations.find(
					(c) => c.id === value.credentialConfigurationId,
				);
				credentialIdentifierRecord = identifier;
			} else if (
				typeof requestedConfigurationId === "string" &&
				requestedConfigurationId
			) {
				cfg = options.credentialConfigurations.find(
					(c) => c.id === requestedConfigurationId,
				);
			} else {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					"credential_configuration_id or credential_identifier is required",
				);
			}
			if (!cfg) {
				throwOidc4vciCredentialError(
					"unknown_credential_configuration",
					"unsupported credential configuration",
				);
			}

			const authError = verifyCredentialAuthorization({
				authorizationDetails,
				credentialConfigurationId: cfg.id,
				credentialIdentifier:
					typeof credentialIdentifier === "string"
						? credentialIdentifier
						: undefined,
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

			try {
				await getOpenid4vciIssuer().parseCredentialRequest({
					issuerMetadata: buildIssuerMetadataResult(ctx, options),
					credentialRequest: requestBody,
					contentType: "application/json",
				});
			} catch (error) {
				throwOidc4vciCredentialError(
					"invalid_credential_request",
					error instanceof Error ? error.message : "invalid credential request",
				);
			}

			const binding = await resolveHolderBinding(options, requestBody, {
				audience: resolveCredentialIssuer(ctx, options),
				userId: subject,
				clientId: azp,
			});
			const nonceIdentifier = await checkNonce(ctx, binding.cNonce);

			const user = await ctx.context.internalAdapter.findUserById(subject);
			if (!user) {
				throw new APIError("BAD_REQUEST", { message: "user not found" });
			}

			// Single-use state is claimed only after every check passed, so a
			// rejected request leaves the nonce for a corrected retry, and two
			// concurrent requests with one nonce yield one credential.
			if (
				!(await ctx.context.internalAdapter.consumeVerificationValue(
					nonceIdentifier,
				))
			) {
				throwOidc4vciCredentialError(
					"invalid_nonce",
					"invalid or expired c_nonce",
				);
			}
			if (
				credentialIdentifierRecord &&
				!(await ctx.context.internalAdapter.consumeVerificationValue(
					credentialIdentifierRecord,
				))
			) {
				throwOidc4vciCredentialError(
					"unknown_credential_identifier",
					"credential_identifier is not recognized",
				);
			}

			const shouldDefer = options.deferredIssuance?.shouldDefer;
			if (
				typeof shouldDefer === "function" &&
				(await shouldDefer({
					credentialConfigurationId: cfg.id,
					userId: subject,
					clientId: azp,
				}))
			) {
				const now = new Date();
				const transactionId = crypto.randomUUID().replaceAll("-", "");
				await ctx.context.internalAdapter.createVerificationValue({
					identifier: await hashIssuerToken(
						ctx,
						transactionId,
						"transaction_id",
					),
					value: JSON.stringify({
						type: VERIFICATION_TYPES.DEFERRED_CREDENTIAL,
						userId: subject,
						clientId: azp,
						credentialConfigurationId: cfg.id,
						credentialIdentifier:
							typeof credentialIdentifier === "string"
								? credentialIdentifier
								: undefined,
						jwk: binding.jwk,
						extraCnf: binding.extraCnf,
					}),
					createdAt: now,
					updatedAt: now,
					expiresAt: new Date(
						now.getTime() +
							(options.deferredIssuance?.transactionExpiresInSeconds ?? 3600) *
								1000,
					),
				});
				ctx.setStatus(202);
				return ctx.json({
					transaction_id: transactionId,
					interval: options.deferredIssuance?.intervalSeconds ?? 3600,
				});
			}

			const credential = await issueCredential(ctx, options, {
				cfg,
				user,
				subject,
				binding,
				authorizationDetails,
				credentialIdentifier:
					typeof credentialIdentifier === "string"
						? credentialIdentifier
						: undefined,
			});
			return ctx.json({ credentials: [{ credential }] });
		},
	);
}
