import { APIError } from "better-auth/api";
import { verifyJwsAccessToken } from "better-auth/oauth2";
import type { JSONWebKeySet } from "jose";
import { throwBearerTokenError } from "../error";
import type { Oidc4vciOptions } from "../types";
import { getLocalJwks } from "./jwt";
import {
	resolveCredentialEndpoint,
	resolveCredentialIssuer,
} from "./resolvers";

export async function requireCredentialAccessToken(
	ctx: {
		body?: Record<string, unknown> | null;
		headers?: Headers;
		request?: Request;
		context: { baseURL: string; getPlugin: (id: string) => unknown };
	},
	options: Oidc4vciOptions,
) {
	const authorization = ctx.headers?.get("authorization");
	const authToken = authorization?.startsWith("Bearer ")
		? authorization.slice("Bearer ".length)
		: authorization?.startsWith("DPoP ")
			? authorization.slice("DPoP ".length)
			: null;
	const bodyToken =
		options.allowAccessTokenInBody && ctx.body
			? (ctx.body.access_token as string | undefined)
			: undefined;
	const accessToken = authToken ?? bodyToken;
	if (!accessToken) {
		throwBearerTokenError({
			status: "UNAUTHORIZED",
			error: "invalid_token",
			errorDescription: "missing bearer token",
		});
	}

	const jwtPlugin = ctx.context.getPlugin("jwt") as {
		options?: {
			jwks?: { jwksPath?: string };
			jwt?: { issuer?: string };
		};
	} | null;
	if (!jwtPlugin) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			message: "jwt plugin is required",
		});
	}

	const issuer =
		options.accessTokenIssuer ?? resolveCredentialIssuer(ctx, options);
	const audience =
		options.accessTokenAudience ??
		options.credentialAudience ??
		resolveCredentialEndpoint(ctx, options);

	const accessTokenJwksUrl = options.accessTokenJwksUrl;
	const jwksFetch: string | (() => Promise<JSONWebKeySet | undefined>) =
		accessTokenJwksUrl
			? async () => {
					const res = await fetch(accessTokenJwksUrl);
					if (!res.ok) {
						throw new Error("jwks fetch failed");
					}
					const body = (await res.json()) as Record<string, unknown>;
					return {
						keys: Array.isArray(body.keys) ? body.keys : [],
					} satisfies JSONWebKeySet;
				}
			: async () => await getLocalJwks(ctx as any, jwtPlugin);

	const tokenPayload = await verifyJwsAccessToken(accessToken, {
		jwksFetch,
		verifyOptions: { audience, issuer },
	}).catch(() => null);
	if (!tokenPayload) {
		throwBearerTokenError({
			status: "UNAUTHORIZED",
			error: "invalid_token",
			errorDescription: "invalid access token",
		});
	}

	if (options.accessTokenValidator && ctx.request) {
		await options.accessTokenValidator({
			request: ctx.request,
			tokenPayload: tokenPayload as Record<string, unknown>,
		});
	}

	const subject = tokenPayload.sub;
	if (!subject || typeof subject !== "string") {
		throwBearerTokenError({
			status: "UNAUTHORIZED",
			error: "invalid_token",
			errorDescription: "token missing sub",
		});
	}

	return { tokenPayload, subject };
}
