import type { BetterAuthPlugin } from "better-auth";
import {
	APIError,
	createAuthEndpoint,
	createAuthMiddleware,
} from "better-auth/api";
import * as z from "zod";
import { storePushedRequest } from "./par";
import { schema } from "./schema";
import type { HaipOptions } from "./types";
import { createVpSession, resolveVpSession } from "./vp-initiation";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		haip: {
			creator: typeof haip;
		};
	}
}

export type { DcqlClaimQuery, DcqlCredentialQuery, DcqlQuery } from "./dcql";
export { buildDcqlQuery, createDcqlMatcher } from "./dcql";
export {
	createDpopAccessTokenValidator,
	createDpopTokenBinding,
} from "./dpop";
export { createJarmHandler } from "./jarm";
export { createKeyAttestationValidator } from "./key-attestation";
export { createParResolver } from "./par";
export { schema } from "./schema";
export * from "./types";
export {
	createWalletAttestationStrategy,
	WALLET_ATTESTATION_TYPE,
} from "./wallet-attestation";
export { createX5cHeaders } from "./x5c";

const REQUIRED_PEER_PLUGINS = ["oauth-provider", "jwt", "oidc4vci"] as const;

export function haip(options?: HaipOptions) {
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
		},
		endpoints: {
			haipPar: createAuthEndpoint(
				"/oauth2/par",
				{
					method: "POST",
					body: z
						.object({
							client_id: z.string(),
							response_type: z.string(),
							redirect_uri: z.string(),
							scope: z.string().optional(),
							state: z.string().optional(),
							code_challenge: z.string().optional(),
							code_challenge_method: z.string().optional(),
							nonce: z.string().optional(),
							authorization_details: z.string().optional(),
						})
						.catchall(z.string()),
				},
				async (ctx) => {
					const { client_id } = ctx.body;

					// Verify the client exists
					const client = await ctx.context.adapter.findOne({
						model: "oauthClient",
						where: [{ field: "clientId", value: client_id }],
					});
					if (!client) {
						throw new APIError("BAD_REQUEST", {
							error: "invalid_client",
							error_description: "client not found",
						});
					}

					return storePushedRequest(
						ctx,
						client_id,
						ctx.body as Record<string, string>,
						options?.parExpiresInSeconds ?? 60,
					);
				},
			),
			haipVpRequest: createAuthEndpoint(
				"/haip/vp/request",
				{
					method: "POST",
					body: z.object({
						dcql_query: z.any(),
						client_id: z.string().optional(),
						client_id_scheme: z.string().optional(),
						response_mode: z.string().optional(),
					}),
				},
				async (ctx) => {
					return createVpSession(
						ctx,
						{
							dcqlQuery: ctx.body.dcql_query,
							clientId: ctx.body.client_id,
							clientIdScheme: ctx.body.client_id_scheme,
							responseMode: ctx.body.response_mode,
						},
						ctx.context.baseURL,
						options?.vpRequestExpiresInSeconds ?? 300,
					);
				},
			),
			haipVpResolve: createAuthEndpoint(
				"/haip/vp/resolve",
				{
					method: "POST",
					body: z.object({
						session_id: z.string(),
					}),
				},
				async (ctx) => {
					const session = await resolveVpSession(ctx, ctx.body.session_id);
					if (!session) {
						throw new APIError("BAD_REQUEST", {
							error: "invalid_request",
							error_description: "VP request session not found or expired",
						});
					}
					return session;
				},
			),
		},
		hooks: {
			after: [
				{
					matcher: (ctx) =>
						ctx.path === "/.well-known/openid-configuration" ||
						ctx.path === "/.well-known/oauth-authorization-server",
					handler: createAuthMiddleware(async (ctx) => {
						const returned = ctx.context.returned as
							| Record<string, unknown>
							| undefined;
						if (!returned || typeof returned !== "object") return;
						ctx.context.returned = {
							...returned,
							pushed_authorization_request_endpoint: `${ctx.context.baseURL}/oauth2/par`,
							require_pushed_authorization_requests:
								options?.requirePar ?? true,
							dpop_signing_alg_values_supported:
								options?.dpopSigningAlgValues ?? ["ES256"],
							authorization_details_types_supported: ["openid_credential"],
						};
					}),
				},
			],
		},
	} satisfies BetterAuthPlugin;
}
