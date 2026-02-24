import type { GenericEndpointContext } from "@better-auth/core";
import { generateRandomString } from "better-auth/crypto";

const PAR_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

/**
 * Creates a PAR request resolver that looks up stored pushed requests.
 *
 * Used as `requestUriResolver` in oauth-provider config.
 */
export function createParResolver() {
	return async (input: {
		requestUri: string;
		clientId: string;
		ctx: GenericEndpointContext;
	}): Promise<Record<string, string> | null> => {
		if (!input.requestUri.startsWith(PAR_URI_PREFIX)) {
			return null;
		}

		const requestId = input.requestUri.slice(PAR_URI_PREFIX.length);
		const record = await input.ctx.context.adapter.findOne<{
			id: string;
			requestId: string;
			clientId: string;
			requestParams: string;
			expiresAt: Date;
		}>({
			model: "haipPushedRequest",
			where: [{ field: "requestId", value: requestId }],
		});

		if (!record) return null;
		if (record.expiresAt < new Date()) {
			await input.ctx.context.adapter.delete({
				model: "haipPushedRequest",
				where: [{ field: "id", value: record.id }],
			});
			return null;
		}

		if (record.clientId !== input.clientId) {
			return null;
		}

		// One-time use: delete after resolution
		await input.ctx.context.adapter.delete({
			model: "haipPushedRequest",
			where: [{ field: "id", value: record.id }],
		});

		return JSON.parse(record.requestParams);
	};
}

/**
 * Stores a pushed authorization request and returns the request_uri.
 */
export async function storePushedRequest(
	ctx: GenericEndpointContext,
	clientId: string,
	params: Record<string, string>,
	expiresInSeconds = 60,
): Promise<{ request_uri: string; expires_in: number }> {
	const requestId = generateRandomString(32);
	const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

	await ctx.context.adapter.create({
		model: "haipPushedRequest",
		data: {
			requestId,
			clientId,
			requestParams: JSON.stringify(params),
			expiresAt,
		},
	});

	return {
		request_uri: `${PAR_URI_PREFIX}${requestId}`,
		expires_in: expiresInSeconds,
	};
}
