import type { GenericEndpointContext } from "@better-auth/core";
import type {
	AccessTokenAuthorization,
	DpopBindingErrorCode,
	DpopNonceOptions,
} from "@better-auth/core/oauth2";
import {
	createDpopNonce,
	createDpopReplayStore,
	DPOP_NONCE_HEADER,
	enforceDpopBinding,
	getDpopJktFromPayload,
	isDpopBindingError,
	parseAccessTokenAuthorization,
	verifyJwsAccessToken,
} from "@better-auth/core/oauth2";
import { createResourceServerChallenge } from "@better-auth/oauth-provider";
import { withExposedHeaders } from "@better-auth/oauth-provider/internal";
import { APIError } from "better-auth/api";
import type { JWTPayload } from "jose";
import { throwBearerTokenError } from "../error";
import type { Oidc4vciOptions } from "../types";
import { getLocalJwks } from "./jwt";
import {
	resolveCredentialEndpoint,
	resolveCredentialIssuer,
} from "./resolvers";

// RFC 6750 §3 limits error_description to printable ASCII without `"` or
// `\`, and core DPoP messages can quote values (`typ must be "dpop+jwt"`).
const AUTH_PARAM_UNSAFE = /[^\x20-\x21\x23-\x5b\x5d-\x7e]/g;

function resolveDpopSigningAlgorithms(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
) {
	if (options.dpop?.signingAlgorithms) return options.dpop.signingAlgorithms;
	const provider = ctx.context.getPlugin("oauth-provider");
	return provider?.options.dpop?.signingAlgorithms;
}

/**
 * The oauth-provider's DPoP nonce settings, keyed from the auth secret as its
 * token endpoint's are. The credential endpoints run in the same instance, so
 * they require nonces when it does and accept the nonces it issues.
 */
function resolveDpopNonce(
	ctx: GenericEndpointContext,
): DpopNonceOptions | undefined {
	const nonce = ctx.context.getPlugin("oauth-provider")?.options.dpop?.nonce;
	if (!nonce?.required) return undefined;
	return {
		secret: ctx.context.secret,
		...(nonce.expiresIn !== undefined ? { expiresIn: nonce.expiresIn } : {}),
	};
}

/**
 * Refuses a DPoP-bound request with the RFC 9449 §7.1 `DPoP` challenge. A
 * `use_dpop_nonce` refusal also carries the nonce to retry with (§9).
 */
async function throwDpopError(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	endpointUrl: string,
	failure: { code: DpopBindingErrorCode; message: string },
	nonce: DpopNonceOptions | undefined,
): Promise<never> {
	const challenge = createResourceServerChallenge(
		new APIError(
			"UNAUTHORIZED",
			{
				error: failure.code,
				error_description:
					failure.message.replaceAll('"', "'").replace(AUTH_PARAM_UNSAFE, "") ||
					"invalid DPoP proof",
			},
			failure.code === "use_dpop_nonce" && nonce
				? { [DPOP_NONCE_HEADER]: await createDpopNonce(nonce) }
				: undefined,
		),
		endpointUrl,
		{ dpopSigningAlgorithms: resolveDpopSigningAlgorithms(ctx, options) },
	);
	throw new APIError(
		"UNAUTHORIZED",
		{ error: failure.code, error_description: failure.message },
		{
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			...Object.fromEntries(new Headers(challenge?.headers)),
		},
	);
}

/**
 * Sends the next DPoP nonce on this response and any error thrown after it
 * (RFC 9449 §8.2), uncached and readable by cross-origin wallets.
 */
async function setNextDpopNonce(
	ctx: GenericEndpointContext,
	nonce: DpopNonceOptions,
) {
	ctx.setHeader("Cache-Control", "no-store");
	ctx.setHeader(DPOP_NONCE_HEADER, await createDpopNonce(nonce));
	ctx.setHeader(
		"Access-Control-Expose-Headers",
		withExposedHeaders(
			ctx.responseHeaders?.get("access-control-expose-headers"),
			DPOP_NONCE_HEADER,
		),
	);
}

/**
 * Authenticates a credential-endpoint request: verifies the JWT access token
 * for this Credential Issuer, then enforces its sender constraint (RFC 9449
 * §7) with Better Auth core's DPoP verification, a database-backed replay
 * store, the endpoint URL the wallet signs as `htu`, and a server-provided
 * nonce when the oauth-provider requires them.
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

	const nonce = resolveDpopNonce(ctx);
	const dpopBound = !!getDpopJktFromPayload(tokenPayload);
	if (options.dpop?.required && !dpopBound) {
		await throwDpopError(
			ctx,
			options,
			endpointUrl,
			{ code: "invalid_token", message: "DPoP-bound access token required" },
			nonce,
		);
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
			nonce,
		});
	} catch (error) {
		if (isDpopBindingError(error)) {
			await throwDpopError(ctx, options, endpointUrl, error, nonce);
		}
		throw error;
	}
	if (nonce && dpopBound) {
		await setNextDpopNonce(ctx, nonce);
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
