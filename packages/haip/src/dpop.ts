import type { DpopReplayStore } from "@better-auth/core/oauth2";
import {
	createInMemoryDpopReplayStore,
	enforceDpopBinding,
	getDpopJktFromPayload,
	isDpopBindingError,
	parseAccessTokenAuthorization,
} from "@better-auth/core/oauth2";
import { APIError } from "better-auth/api";
import type { JWTPayload } from "jose";

/** HAIP requires ES256 for DPoP proofs. */
export const HAIP_DPOP_SIGNING_ALGORITHMS = ["ES256"] as const;

export type DpopAccessTokenValidatorOptions = {
	/**
	 * Reject access tokens that are not DPoP-bound (no `cnf.jkt`).
	 *
	 * @default false
	 */
	requireDpop?: boolean;
	/**
	 * JWS algorithms accepted for DPoP proofs.
	 *
	 * @default ["ES256"]
	 */
	signingAlgorithms?: readonly string[];
	/** Maximum proof age in seconds (RFC 9449 §11.1). Defaults to core's 300. */
	proofMaxAgeSeconds?: number;
	/**
	 * Store that rejects replayed proof `jti` values. Defaults to a
	 * process-local store, which only protects a single instance; pass
	 * `createDpopReplayStore(auth.$context.internalAdapter)` (from
	 * `@better-auth/core/oauth2`) or another shared store for multi-instance
	 * deployments.
	 */
	replayStore?: DpopReplayStore;
};

export type DpopAccessTokenValidatorInput = {
	request: Request;
	/** The access-token payload, already verified by JWKS or introspection. */
	tokenPayload: Record<string, unknown>;
	/**
	 * Request URL the client signed as `htu`. Defaults to `request.url`; pass
	 * the public URL when a proxy rewrites the request URL.
	 */
	url?: string;
};

function challenge(
	error: "invalid_token" | "invalid_dpop_proof",
	message: string,
) {
	const description = message.replaceAll('"', "'");
	return new APIError(
		"UNAUTHORIZED",
		{ error, error_description: message },
		{
			"WWW-Authenticate": `DPoP error="${error}", error_description="${description}"`,
		},
	);
}

/**
 * Creates a resource-server validator that enforces RFC 9449 sender
 * constraint for an already-verified access token: a DPoP-bound token requires
 * the `DPoP` authorization scheme and a proof whose method, URL, age, `jti`,
 * `ath`, and key all match. Verification is delegated to Better Auth core's
 * `enforceDpopBinding`.
 */
export function createDpopAccessTokenValidator(
	options?: DpopAccessTokenValidatorOptions,
) {
	const replayStore = options?.replayStore ?? createInMemoryDpopReplayStore();
	const signingAlgorithms =
		options?.signingAlgorithms ?? HAIP_DPOP_SIGNING_ALGORITHMS;

	return async (input: DpopAccessTokenValidatorInput) => {
		const payload = input.tokenPayload as JWTPayload;
		if (!getDpopJktFromPayload(payload) && options?.requireDpop) {
			throw challenge("invalid_token", "DPoP-bound access token required");
		}
		const authorization = parseAccessTokenAuthorization(
			input.request.headers.get("authorization"),
		);
		if (!authorization?.token) {
			throw challenge("invalid_token", "missing access token");
		}
		try {
			await enforceDpopBinding({
				payload,
				authorization,
				proofJwt: input.request.headers.get("dpop"),
				method: input.request.method,
				url: input.url ?? input.request.url,
				replayStore,
				signingAlgorithms,
				proofMaxAgeSeconds: options?.proofMaxAgeSeconds,
			});
		} catch (error) {
			if (isDpopBindingError(error)) {
				throw challenge(error.code, error.message);
			}
			throw error;
		}
	};
}
