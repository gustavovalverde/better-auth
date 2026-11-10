import {
	APIError,
	createAuthEndpoint,
	sensitiveSessionMiddleware,
} from "better-auth/api";
import * as z from "zod";
import { buildStatusListJwt } from "../status-list";
import type { Oidc4vciOptions } from "../types";
import { resolveStatusListOptions } from "../utils/resolvers";

const statusListQuerySchema = z.object({
	list_id: z.string().optional(),
});

const credentialStatusBodySchema = z.object({
	credential_id: z.string(),
	status: z.number().int().min(0).max(255).optional(),
});

export function createStatusListEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/status-list",
		{
			method: "GET",
			query: statusListQuerySchema,
		},
		async (ctx) => {
			const statusListOptions = resolveStatusListOptions(options);
			const listId = ctx.query?.list_id ?? statusListOptions.listId;
			const jwt = await buildStatusListJwt(ctx, options, listId);
			return new Response(jwt, {
				status: 200,
				headers: {
					"content-type": "application/statuslist+jwt",
					"cache-control": `public, max-age=${statusListOptions.ttlSeconds}`,
				},
			});
		},
	);
}

/**
 * Changes the status of an issued credential. By default a holder may revoke
 * their own credentials; restoring one, or changing another user's, requires
 * `authorizeCredentialStatusUpdate`.
 */
export function createUpdateCredentialStatusEndpoint(options: Oidc4vciOptions) {
	return createAuthEndpoint(
		"/oidc4vci/credential/status",
		{
			method: "POST",
			use: [sensitiveSessionMiddleware],
			body: credentialStatusBodySchema,
		},
		async (ctx) => {
			const session = ctx.context.session;
			const credentialId = ctx.body.credential_id;
			const nextStatus = ctx.body.status ?? 1;
			const bits = resolveStatusListOptions(options).bits;
			if (nextStatus >= 2 ** bits) {
				throw new APIError("BAD_REQUEST", {
					message: `status must fit in ${bits} bit(s)`,
				});
			}

			const credential = await ctx.context.adapter.findOne<{
				id: string;
				userId: string;
				status: number;
			}>({
				model: "oidc4vciIssuedCredential",
				where: [{ field: "id", value: credentialId }],
			});
			if (!credential) {
				throw new APIError("NOT_FOUND");
			}

			const authorized = options.authorizeCredentialStatusUpdate
				? await options.authorizeCredentialStatusUpdate({
						session,
						credential,
						status: nextStatus,
						ctx,
					})
				: credential.userId === session.user.id && nextStatus !== 0;
			if (!authorized) {
				// Another user's credential looks unknown.
				throw new APIError(
					credential.userId === session.user.id ? "FORBIDDEN" : "NOT_FOUND",
				);
			}

			await ctx.context.adapter.update({
				model: "oidc4vciIssuedCredential",
				where: [{ field: "id", value: credentialId }],
				update: {
					status: nextStatus,
					revokedAt: nextStatus === 0 ? null : new Date(),
				},
			});

			return ctx.json({
				credential_id: credentialId,
				status: nextStatus,
			});
		},
	);
}
