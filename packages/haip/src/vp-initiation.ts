import type { GenericEndpointContext } from "@better-auth/core";
import { generateRandomString } from "better-auth/crypto";

type VpSessionInput = {
	dcqlQuery: unknown;
	clientId?: string;
	clientIdScheme?: string;
	responseMode?: string;
};

type VpSessionRecord = {
	id: string;
	sessionId: string;
	nonce: string;
	state: string;
	dcqlQuery: string;
	responseUri: string;
	clientId: string;
	clientIdScheme: string;
	responseMode: string;
	expiresAt: Date;
};

/**
 * Creates a VP authorization request session.
 *
 * The returned `request_uri` can be given to a wallet (via QR code, deep link, etc.)
 * to fetch the full authorization request.
 */
export async function createVpSession(
	ctx: GenericEndpointContext,
	input: VpSessionInput,
	baseUrl: string,
	expiresInSeconds = 300,
) {
	const sessionId = generateRandomString(32);
	const nonce = generateRandomString(32);
	const state = generateRandomString(32);
	const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);
	const responseUri = `${baseUrl}/oidc4vp/response`;

	await ctx.context.adapter.create({
		model: "haipVpSession",
		data: {
			sessionId,
			nonce,
			state,
			dcqlQuery: JSON.stringify(input.dcqlQuery),
			responseUri,
			clientId: input.clientId ?? "",
			clientIdScheme: input.clientIdScheme ?? "",
			responseMode: input.responseMode ?? "direct_post",
			expiresAt,
		},
	});

	return {
		request_uri: `${baseUrl}/haip/vp/resolve`,
		session_id: sessionId,
		nonce,
		state,
		expires_in: expiresInSeconds,
	};
}

/**
 * Resolves a VP session by ID and returns the authorization request object.
 *
 * Returns `null` if the session is not found or expired.
 */
export async function resolveVpSession(
	ctx: GenericEndpointContext,
	sessionId: string,
) {
	const record = await ctx.context.adapter.findOne<VpSessionRecord>({
		model: "haipVpSession",
		where: [{ field: "sessionId", value: sessionId }],
	});

	if (!record) return null;

	if (record.expiresAt < new Date()) {
		await ctx.context.adapter.delete({
			model: "haipVpSession",
			where: [{ field: "id", value: record.id }],
		});
		return null;
	}

	const request: Record<string, unknown> = {
		response_type: "vp_token",
		response_uri: record.responseUri,
		response_mode: record.responseMode,
		nonce: record.nonce,
		state: record.state,
		dcql_query: JSON.parse(record.dcqlQuery),
	};

	if (record.clientId) {
		request.client_id = record.clientId;
	}
	if (record.clientIdScheme) {
		request.client_id_scheme = record.clientIdScheme;
	}

	return request;
}
