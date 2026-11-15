import { extendOAuthProvider } from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import * as z from "zod";
import { HAIP_DPOP_SIGNING_ALGORITHMS } from "./dpop";
import { schema } from "./schema";
import type { HaipOptions } from "./types";
import { createVpSession, getVpRequestObject } from "./vp-request";
import {
	createWalletAttestationStrategy,
	issueAttestationChallenge,
	WALLET_ATTESTATION_AUTH_METHOD,
	WALLET_ATTESTATION_TYPE,
} from "./wallet-attestation";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		haip: {
			creator: typeof haip;
		};
	}
}

export type {
	DcqlMatcherPresentation,
	DcqlMatchResult,
	DcqlQuery,
} from "./dcql";
export { createDcqlMatcher } from "./dcql";
export { HAIP_DPOP_SIGNING_ALGORITHMS } from "./dpop";
export type { JarmDecryptionResult, JarmHandlerOptions } from "./jarm";
export { createJarmHandler } from "./jarm";
export type { KeyAttestationOptions } from "./key-attestation";
export { createKeyAttestationValidator } from "./key-attestation";
export { schema } from "./schema";
export type { TrustedIssuer } from "./trust";
export type { Awaitable, HaipOptions } from "./types";
export type {
	HaipVerifierOptions,
	VpAuthorizationRequest,
	VpResponseMode,
} from "./vp-request";
export { createVpSessionResolver, getVerifierClientId } from "./vp-request";
export type { WalletAttestationOptions } from "./wallet-attestation";
export {
	createWalletAttestationStrategy,
	WALLET_ATTESTATION_AUTH_METHOD,
	WALLET_ATTESTATION_TYPE,
} from "./wallet-attestation";
export { computeX509Hash, createX5cHeaders } from "./x5c";

const REQUIRED_PEER_PLUGINS = ["oauth-provider", "jwt", "oidc4vci"] as const;
const CHALLENGE_PATH = "/oauth2/attestation-challenge";
const REQUEST_OBJECT_PATH = "/haip/vp/request-object";

export function haip(options?: HaipOptions) {
	const walletAttestation = options?.walletAttestation;
	const authenticateWalletAttestation = walletAttestation
		? createWalletAttestationStrategy(walletAttestation)
		: undefined;
	const attestationAlgorithms = walletAttestation?.signingAlgorithms ?? [
		"ES256",
	];

	return {
		id: "haip",
		schema,
		options,
		init(ctx) {
			const pluginIds = new Set(ctx.options.plugins?.map((p) => p.id) ?? []);
			for (const required of REQUIRED_PEER_PLUGINS) {
				if (!pluginIds.has(required)) {
					throw new Error(
						`@better-auth/haip requires the "${required}" plugin. Add it to your plugins array.`,
					);
				}
			}
			// HAIP §4.1 requires PAR. The provider serves it, so it must be enabled
			// there, where its endpoint and rate limit are configured.
			if (
				!ctx.getPlugin("oauth-provider")?.options.pushedAuthorizationRequests
					?.enabled
			) {
				throw new Error(
					"@better-auth/haip requires pushed authorization requests. Set `pushedAuthorizationRequests: { enabled: true, required: true }` in oauthProvider().",
				);
			}

			// HAIP's DPoP profile for the credential endpoints: bound tokens and
			// ES256 proofs, unless the oidc4vci plugin sets its own policy.
			const oidc4vci = ctx.getPlugin("oidc4vci");
			if (oidc4vci && !oidc4vci.options.dpop) {
				oidc4vci.options.dpop = {
					required: options?.requireDpop ?? true,
					signingAlgorithms:
						options?.dpopSigningAlgorithms ?? HAIP_DPOP_SIGNING_ALGORITHMS,
				};
			}

			extendOAuthProvider(ctx, {
				metadata: ({ ctx: endpointCtx }) => ({
					authorization_details_types_supported: ["openid_credential"],
					...(walletAttestation
						? {
								challenge_endpoint: `${endpointCtx.context.baseURL}${CHALLENGE_PATH}`,
								client_attestation_signing_alg_values_supported:
									attestationAlgorithms,
								client_attestation_pop_signing_alg_values_supported:
									attestationAlgorithms,
							}
						: {}),
				}),
				...(authenticateWalletAttestation
					? {
							clientAuthentication: {
								[WALLET_ATTESTATION_AUTH_METHOD]: {
									assertionTypes: [WALLET_ATTESTATION_TYPE],
									authenticate: authenticateWalletAttestation,
								},
							},
						}
					: {}),
			});
		},
		endpoints: {
			/**
			 * Creates a VP request: a session plus a signed request object
			 * (HAIP §5.1) that wallets fetch from `request_uri`. Server-only,
			 * because the request object is signed with the verifier identity.
			 */
			createHaipVpRequest: createAuthEndpoint.serverOnly(
				{
					method: "POST",
					body: z.object({
						dcql_query: z.unknown(),
						response_mode: z
							.enum(["direct_post", "direct_post.jwt"])
							.optional(),
					}),
				},
				async (ctx) => {
					if (!options?.verifier) {
						throw new APIError("BAD_REQUEST", {
							error: "invalid_request",
							error_description:
								"haip verifier options are required to create VP requests",
						});
					}
					return createVpSession(ctx, options.verifier, {
						dcqlQuery: ctx.body.dcql_query,
						responseMode: ctx.body.response_mode ?? "direct_post.jwt",
						expiresInSeconds: options.vpRequestExpiresInSeconds ?? 300,
					});
				},
			),
			/**
			 * Serves a VP session's signed request object
			 * (`application/oauth-authz-req+jwt`) at its `request_uri`.
			 */
			getHaipVpRequestObject: createAuthEndpoint(
				REQUEST_OBJECT_PATH,
				{
					method: "GET",
					query: z.object({ session_id: z.string() }),
				},
				async (ctx) => {
					const requestObject = await getVpRequestObject(
						ctx,
						ctx.query.session_id,
					);
					if (!requestObject) {
						throw new APIError("NOT_FOUND", {
							error: "invalid_request_uri",
							error_description: "VP request not found or expired",
						});
					}
					return new Response(requestObject, {
						status: 200,
						headers: {
							"content-type": "application/oauth-authz-req+jwt",
							"cache-control": "no-store",
						},
					});
				},
			),
			...(walletAttestation
				? {
						/**
						 * Attestation challenge endpoint
						 * (draft-ietf-oauth-attestation-based-client-auth §8).
						 */
						haipAttestationChallenge: createAuthEndpoint(
							CHALLENGE_PATH,
							{
								method: "POST",
								metadata: { noStore: true },
							},
							async (ctx) => {
								const challenge = await issueAttestationChallenge(
									ctx,
									walletAttestation.challengeExpiresInSeconds ?? 300,
								);
								return ctx.json({ attestation_challenge: challenge });
							},
						),
					}
				: {}),
		},
		rateLimit: [
			{
				pathMatcher: (path: string) => path === CHALLENGE_PATH,
				window: 60,
				max: 30,
			},
			{
				pathMatcher: (path: string) => path === REQUEST_OBJECT_PATH,
				window: 60,
				max: 60,
			},
		],
	} satisfies BetterAuthPlugin;
}
