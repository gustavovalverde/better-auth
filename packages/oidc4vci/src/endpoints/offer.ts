import {
	APIError,
	createAuthEndpoint,
	sessionMiddleware,
} from "better-auth/api";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import * as z from "zod";
import { VERIFICATION_TYPES } from "../constants";
import type { Oidc4vciOptions } from "../types";
import {
	resolveAuthorizationServers,
	resolveCredentialEndpoint,
	resolveCredentialIssuer,
	resolveCredentialOfferUri,
} from "../utils/resolvers";
import { resolveStoreTokens, storeTokenIdentifier } from "../utils/token";

const offerBodySchema = z.object({
	client_id: z.string().optional(),
	userId: z.string(),
	credential_configuration_id: z.string(),
	issuer_state: z.string().optional(),
	tx_code: z.string().optional(),
	tx_code_input_mode: z.enum(["numeric", "text"]).optional(),
	tx_code_length: z.number().int().positive().optional(),
	expires_in: z.number().int().positive().max(3600).optional(),
	claims: z
		.array(
			z.object({
				path: z.array(z.string()).min(1),
				mandatory: z.boolean().optional(),
			}),
		)
		.optional(),
});

const offerQuerySchema = z.object({
	offer_id: z.string(),
});

export function createCredentialOfferEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/credential-offer",
		{
			method: "POST",
			use: [sessionMiddleware],
			body: offerBodySchema,
		},
		async (ctx) => {
			const cfg = options.credentialConfigurations.find(
				(c) => c.id === ctx.body.credential_configuration_id,
			);
			if (!cfg) {
				throw new APIError("BAD_REQUEST", {
					message: "unknown credential_configuration_id",
				});
			}

			const user = await ctx.context.internalAdapter.findUserById(
				ctx.body.userId,
			);
			if (!user) {
				throw new APIError("BAD_REQUEST", { message: "user not found" });
			}

			const now = new Date();
			const expiresInSeconds = ctx.body.expires_in ?? 600;
			const expiresAt = new Date(now.getTime() + expiresInSeconds * 1000);

			const clientId = ctx.body.client_id ?? options.defaultWalletClientId;
			if (!clientId) {
				throw new APIError("BAD_REQUEST", {
					message: "client_id is required",
				});
			}

			const preAuthorizedCode = crypto.randomUUID().replaceAll("-", "");
			const storeTokens = resolveStoreTokens(ctx);
			const identifier = await storeTokenIdentifier(
				storeTokens,
				preAuthorizedCode,
				"pre_authorized_code",
			);

			const txCodeHash = ctx.body.tx_code
				? await storeTokenIdentifier(storeTokens, ctx.body.tx_code, "tx_code")
				: undefined;
			const authorizationDetails = ctx.body.claims?.length
				? [
						{
							type: "openid_credential",
							credential_configuration_id: cfg.id,
							claims: ctx.body.claims,
						},
					]
				: undefined;

			await ctx.context.internalAdapter.createVerificationValue({
				identifier,
				value: JSON.stringify({
					type: VERIFICATION_TYPES.PRE_AUTH_CODE,
					clientId,
					userId: user.id,
					credentialConfigurationId: cfg.id,
					issuerState: ctx.body.issuer_state,
					txCodeHash,
					authorizationDetails,
					credentialAudience:
						options.credentialAudience ??
						resolveCredentialEndpoint(ctx, options),
				}),
				createdAt: now,
				updatedAt: now,
				expiresAt,
			});

			const encrypted = await symmetricEncrypt({
				key: ctx.context.secret,
				data: preAuthorizedCode,
			});

			const txCodeInputMode = ctx.body.tx_code
				? (ctx.body.tx_code_input_mode ?? "numeric")
				: undefined;
			const txCodeLength = ctx.body.tx_code
				? (ctx.body.tx_code_length ?? ctx.body.tx_code.length)
				: undefined;

			const offer = await ctx.context.adapter.create({
				model: "oidc4vciOffer",
				data: {
					walletClientId: clientId,
					userId: user.id,
					credentialConfigurationId: cfg.id,
					preAuthorizedCodeEncrypted: encrypted,
					txCodeHash,
					txCodeInputMode,
					txCodeLength,
					issuerState: ctx.body.issuer_state,
					expiresAt,
					createdAt: now,
				},
			});

			const issuerIdentifier = resolveCredentialIssuer(ctx, options);
			const credentialOfferUri = resolveCredentialOfferUri(
				ctx,
				options,
				offer.id,
			);
			const authorizationServers = resolveAuthorizationServers(options);
			const authorizationServer = authorizationServers?.length
				? authorizationServers[0]
				: undefined;
			const credentialOffer = {
				credential_issuer: issuerIdentifier,
				credential_configuration_ids: [cfg.id],
				grants: {
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
						"pre-authorized_code": preAuthorizedCode,
						...(authorizationServer
							? { authorization_server: authorizationServer }
							: {}),
						...(ctx.body.tx_code
							? {
									tx_code: {
										input_mode: txCodeInputMode,
										length: txCodeLength,
									},
								}
							: {}),
					},
				},
			};

			return ctx.json({
				offer_id: offer.id,
				credential_offer_uri: credentialOfferUri,
				credential_offer: credentialOffer,
			});
		},
	);
}

export function createGetCredentialOfferEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/credential-offer",
		{
			method: "GET",
			query: offerQuerySchema,
		},
		async (ctx) => {
			const offer = await ctx.context.adapter.findOne<{
				id: string;
				walletClientId: string;
				userId: string;
				credentialConfigurationId: string;
				preAuthorizedCodeEncrypted: string;
				txCodeHash?: string | null;
				txCodeInputMode?: string | null;
				txCodeLength?: number | null;
				issuerState?: string | null;
				expiresAt: Date;
			}>({
				model: "oidc4vciOffer",
				where: [{ field: "id", value: ctx.query.offer_id }],
			});

			if (!offer || offer.expiresAt < new Date()) {
				throw new APIError("NOT_FOUND");
			}

			const preAuthorizedCode = await symmetricDecrypt({
				key: ctx.context.secret,
				data: offer.preAuthorizedCodeEncrypted,
			});

			const issuerIdentifier = resolveCredentialIssuer(ctx, options);
			const authorizationServers = resolveAuthorizationServers(options);
			const authorizationServer = authorizationServers?.length
				? authorizationServers[0]
				: undefined;
			return ctx.json({
				credential_issuer: issuerIdentifier,
				credential_configuration_ids: [offer.credentialConfigurationId],
				grants: {
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
						"pre-authorized_code": preAuthorizedCode,
						...(authorizationServer
							? { authorization_server: authorizationServer }
							: {}),
						...(offer.txCodeHash
							? {
									tx_code: {
										input_mode: offer.txCodeInputMode ?? "numeric",
										length: offer.txCodeLength ?? 8,
									},
								}
							: {}),
					},
				},
			});
		},
	);
}
