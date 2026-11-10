import type { GenericEndpointContext } from "@better-auth/core";
import { isLoopbackIP } from "@better-auth/core/utils/host";
import { generateRandomString } from "better-auth/crypto";

const PAR_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
const PAR_MODEL = "haipPushedRequest";

/**
 * Client authentication parameters are consumed at the PAR endpoint and must
 * not be persisted with the pushed request (RFC 9126 §2.1).
 */
const CLIENT_AUTHENTICATION_PARAMETERS = new Set([
	"client_secret",
	"client_assertion",
	"client_assertion_type",
]);

type PushedRequestRecord = {
	id: string;
	requestId: string;
	clientId: string;
	requestParams: string;
	expiresAt: Date;
};

function stripLoopbackRedirectPort(uri: string): string | undefined {
	let parsed: URL;
	try {
		parsed = new URL(uri);
	} catch {
		return undefined;
	}
	const isLoopback =
		isLoopbackIP(parsed.hostname) || parsed.hostname === "localhost";
	if (parsed.protocol !== "http:" || !isLoopback) return undefined;
	const schemeSeparatorIndex = uri.indexOf("://");
	if (schemeSeparatorIndex < 0) return undefined;
	const authorityStart = schemeSeparatorIndex + 3;
	const authorityEndOffset = uri.slice(authorityStart).search(/[/?#]/u);
	const authorityEnd =
		authorityEndOffset >= 0 ? authorityStart + authorityEndOffset : uri.length;
	const authority = uri.slice(authorityStart, authorityEnd);
	let portStart: number;
	if (authority.startsWith("[")) {
		const closingBracket = authority.indexOf("]");
		if (closingBracket < 0) return undefined;
		if (authority[closingBracket + 1] !== ":") return uri;
		portStart = closingBracket + 1;
	} else {
		portStart = authority.lastIndexOf(":");
		if (portStart < 0) return uri;
	}
	if (!/^\d*$/u.test(authority.slice(portStart + 1))) return undefined;
	return `${uri.slice(0, authorityStart + portStart)}${uri.slice(authorityEnd)}`;
}

/**
 * Matches a requested redirect URI against the client's registered URIs with
 * the same rules the oauth-provider authorization endpoint applies: exact
 * match, except that loopback HTTP redirects may vary by port (RFC 8252 §7.3).
 */
export function findRegisteredRedirectUri(
	registered: string[] | undefined | null,
	requested: string,
): string | undefined {
	if (!registered) return undefined;
	let requestedUrl: URL;
	try {
		requestedUrl = new URL(requested);
	} catch {
		return undefined;
	}
	if (
		requested.includes("#") ||
		requestedUrl.username.length > 0 ||
		requestedUrl.password.length > 0
	) {
		return undefined;
	}
	const requestedWithoutPort = stripLoopbackRedirectPort(requested);
	return registered.find(
		(url) =>
			url === requested ||
			(requestedWithoutPort !== undefined &&
				stripLoopbackRedirectPort(url) === requestedWithoutPort),
	);
}

/**
 * Creates a PAR request resolver that looks up stored pushed requests.
 *
 * Used as `requestUriResolver` in oauth-provider config. A `request_uri` is
 * bound to the client that pushed it and redeemed at most once.
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
		const { adapter } = input.ctx.context;
		const record = await adapter.findOne<PushedRequestRecord>({
			model: PAR_MODEL,
			where: [{ field: "requestId", value: requestId }],
		});
		if (!record) return null;
		if (new Date(record.expiresAt) <= new Date()) {
			await adapter.delete({
				model: PAR_MODEL,
				where: [{ field: "id", value: record.id }],
			});
			return null;
		}
		// Another client's request_uri looks unknown, and is left in place so
		// presenting it cannot burn the pushing client's request.
		if (record.clientId !== input.clientId) {
			return null;
		}
		const consumed = await adapter.consumeOne<PushedRequestRecord>({
			model: PAR_MODEL,
			where: [{ field: "id", value: record.id }],
		});
		if (!consumed) return null;
		return JSON.parse(consumed.requestParams) as Record<string, string>;
	};
}

/**
 * Stores a pushed authorization request and returns the request_uri.
 */
export async function storePushedRequest(
	ctx: GenericEndpointContext,
	clientId: string,
	params: Record<string, unknown>,
	expiresInSeconds = 60,
): Promise<{ request_uri: string; expires_in: number }> {
	const requestId = generateRandomString(32);
	const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);
	const requestParams = Object.fromEntries(
		Object.entries(params).filter(
			([name]) => !CLIENT_AUTHENTICATION_PARAMETERS.has(name),
		),
	);

	await ctx.context.adapter.create({
		model: PAR_MODEL,
		data: {
			requestId,
			clientId,
			requestParams: JSON.stringify(requestParams),
			expiresAt,
		},
	});

	return {
		request_uri: `${PAR_URI_PREFIX}${requestId}`,
		expires_in: expiresInSeconds,
	};
}
