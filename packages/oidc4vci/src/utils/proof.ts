import type { GenericEndpointContext } from "@better-auth/core";
import type {
	AccessTokenAuthorization,
	DpopBindingErrorCode,
} from "@better-auth/core/oauth2";
import {
	createDpopReplayStore,
	enforceDpopBinding,
	getDpopJktFromPayload,
	isDpopBindingError,
	parseAccessTokenAuthorization,
	verifyJwsAccessToken,
} from "@better-auth/core/oauth2";
import { APIError } from "better-auth/api";
import type { JWTPayload } from "jose";
import { throwBearerTokenError } from "../error";
import type { Oidc4vciOptions } from "../types";
import { getLocalJwks } from "./jwt";
import {
	resolveCredentialEndpoint,
	resolveCredentialIssuer,
} from "./resolvers";

function throwDpopError(
	error: DpopBindingErrorCode,
	description: string,
): never {
	const safeDescription = description.replaceAll('"', "'");
	throw new APIError(
		"UNAUTHORIZED",
		{ error, error_description: description },
		{
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			"WWW-Authenticate": `DPoP error="${error}", error_description="${safeDescription}"`,
		},
	);
}

function resolveDpopSigningAlgorithms(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
) {
	if (options.dpop?.signingAlgorithms) return options.dpop.signingAlgorithms;
	const provider = ctx.context.getPlugin("oauth-provider");
	return provider?.options.dpop?.signingAlgorithms;
}

/**
 * Authenticates a credential-endpoint request: verifies the JWT access token
 * for this Credential Issuer, then enforces its sender constraint (RFC 9449
 * §7) with Better Auth core's DPoP verification, a database-backed replay
 * store, and the endpoint URL the wallet signs as `htu`.
 */
export async function requireCredentialAccessToken(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	endpointUrl: string,
) {
	const headerAuthorization = parseAccessTokenAuthorization(
		ctx.headers?.get("authorization"),
	);
	const body = ctx.body as Record<string, unknown> | undefined;
	const bodyToken =
		options.allowAccessTokenInBody && typeof body?.access_token === "string"
			? body.access_token
			: undefined;
	const authorization: AccessTokenAuthorization | undefined =
		headerAuthorization?.token
			? headerAuthorization
			: bodyToken
				? { scheme: "Bearer", token: bodyToken }
				: undefined;
	if (!authorization?.token) {
		throwBearerTokenError({
			status: "UNAUTHORIZED",
			error: "invalid_token",
			errorDescription: "missing access token",
		});
	}
	if (authorization.scheme === "Unknown") {
		throwBearerTokenError({
			status: "UNAUTHORIZED",
			error: "invalid_token",
			errorDescription: "authorization scheme must be Bearer or DPoP",
		});
	}

	const jwtPlugin = ctx.context.getPlugin("jwt");
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

	const tokenPayload: JWTPayload | null = await verifyJwsAccessToken(
		authorization.token,
		{
			jwksFetch:
				options.accessTokenJwksUrl ??
				(async () => await getLocalJwks(ctx, jwtPlugin)),
			verifyOptions: { audience, issuer },
		},
	).catch(() => null);
	if (!tokenPayload) {
		throwBearerTokenError({
			status: "UNAUTHORIZED",
			error: "invalid_token",
			errorDescription: "invalid access token",
		});
	}

	if (options.dpop?.required && !getDpopJktFromPayload(tokenPayload)) {
		throwDpopError("invalid_token", "DPoP-bound access token required");
	}
	try {
		await enforceDpopBinding({
			payload: tokenPayload,
			authorization,
			proofJwt: ctx.headers?.get("dpop"),
			method: ctx.request?.method ?? "POST",
			url: endpointUrl,
			replayStore: createDpopReplayStore(ctx.context.internalAdapter),
			signingAlgorithms: resolveDpopSigningAlgorithms(ctx, options),
			proofMaxAgeSeconds: options.dpop?.proofMaxAgeSeconds,
		});
	} catch (error) {
		if (isDpopBindingError(error)) {
			throwDpopError(error.code, error.message);
		}
		throw error;
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
