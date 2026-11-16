import type { GenericEndpointContext } from "@better-auth/core";
import { getDpopJktFromPayload } from "@better-auth/core/oauth2";
import { createResourceServerChallenge } from "@better-auth/oauth-provider";
import { APIError } from "better-auth/api";
import { decodeProtectedHeader } from "jose";
import { throwBearerTokenError } from "../error";
import type { Oidc4vciOptions } from "../types";
import { resolveCredentialEndpoint } from "./resolvers";
import { getProviderApi } from "./token";

function resolveDpopSigningAlgorithms(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
) {
	if (options.dpop?.signingAlgorithms) return options.dpop.signingAlgorithms;
	const provider = ctx.context.getPlugin("oauth-provider");
	return provider?.options.dpop?.signingAlgorithms;
}

/** Refuses a request with the RFC 9449 §7.1 `DPoP` challenge. */
function throwDpopError(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	endpointUrl: string,
	failure: { code: "invalid_token" | "invalid_dpop_proof"; message: string },
): never {
	const challenge = createResourceServerChallenge(
		new APIError("UNAUTHORIZED", {
			error: failure.code,
			error_description: failure.message,
		}),
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

function dpopProofAlgorithm(ctx: GenericEndpointContext) {
	const proof = ctx.headers?.get("dpop");
	if (!proof) return undefined;
	try {
		return decodeProtectedHeader(proof).alg;
	} catch {
		return undefined;
	}
}

/**
 * Authenticates a credential-endpoint request through the oauth-provider's
 * `verifyResourceRequest`, which checks the access token's signature,
 * audience, client, revocation, and DPoP binding with the provider's nonce
 * policy, and returns the user id in `sub` even when the token's own `sub` is
 * pairwise. The plugin's DPoP options can only narrow the provider's: they
 * require a bound token and limit the proof algorithms.
 */
export async function requireCredentialAccessToken(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	endpointUrl: string,
) {
	const tokenPayload = await getProviderApi(ctx).verifyResourceRequest({
		audience:
			options.accessTokenAudience ??
			options.credentialAudience ??
			resolveCredentialEndpoint(ctx, options),
	});

	const dpopBound = !!getDpopJktFromPayload(tokenPayload);
	if (options.dpop?.required && !dpopBound) {
		throwDpopError(ctx, options, endpointUrl, {
			code: "invalid_token",
			message: "DPoP-bound access token required",
		});
	}
	const algorithms = options.dpop?.signingAlgorithms;
	if (dpopBound && algorithms) {
		const alg = dpopProofAlgorithm(ctx);
		if (!alg || !algorithms.includes(alg)) {
			throwDpopError(ctx, options, endpointUrl, {
				code: "invalid_dpop_proof",
				message: "DPoP proof algorithm is not allowed",
			});
		}
	}

	const clientId =
		typeof tokenPayload.client_id === "string"
			? tokenPayload.client_id
			: undefined;
	const userId = tokenPayload.sub;
	// A token issued without a user names its client in `sub`.
	if (typeof userId !== "string" || !userId || userId === clientId) {
		throwBearerTokenError({
			status: "UNAUTHORIZED",
			error: "invalid_token",
			errorDescription: "access token does not name a user",
		});
	}

	if (options.accessTokenValidator && ctx.request) {
		await options.accessTokenValidator({
			request: ctx.request,
			tokenPayload: tokenPayload as Record<string, unknown>,
		});
	}

	return { tokenPayload, userId, clientId };
}
