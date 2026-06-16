import {
	APIError,
	createAuthEndpoint,
	sessionMiddleware,
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
	status: z.number().int().min(0).max(1).optional(),
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

export function createUpdateCredentialStatusEndpoint() {
	return createAuthEndpoint(
		"/oidc4vci/credential/status",
		{
			method: "POST",
			use: [sessionMiddleware],
			body: credentialStatusBodySchema,
		},
		async (ctx) => {
			const credentialId = ctx.body.credential_id;
			const nextStatus = ctx.body.status ?? 1;

			const existing = await ctx.context.adapter.findMany<{
				id: string;
			}>({
				model: "oidc4vciIssuedCredential",
				where: [
					{
						field: "id",
						value: credentialId,
					},
				],
				limit: 1,
			});

			if (!existing.length) {
				throw new APIError("NOT_FOUND");
			}

			await ctx.context.adapter.update({
				model: "oidc4vciIssuedCredential",
				where: [
					{
						field: "id",
						value: credentialId,
					},
				],
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
