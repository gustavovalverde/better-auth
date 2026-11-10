import type { GenericEndpointContext } from "@better-auth/core";
import type {
	OAuthClientAuthenticationInput,
	OAuthClientAuthenticationResult,
} from "@better-auth/oauth-provider";
import { consumeClientAssertion, getIssuer } from "@better-auth/oauth-provider";
import { APIError } from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import type { JWK, JWTPayload } from "jose";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import type { TrustedIssuer } from "./trust";
import { assertTrustedIssuers, verifyTrustedJwt } from "./trust";

/** `client_assertion_type` for OAuth 2.0 Attestation-Based Client Authentication. */
export const WALLET_ATTESTATION_TYPE =
	"urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";

/** `token_endpoint_auth_method` for Attestation-Based Client Authentication. */
export const WALLET_ATTESTATION_AUTH_METHOD = "attest_jwt_client_auth";

const ATTESTATION_TYP = "oauth-client-attestation+jwt";
const ATTESTATION_POP_TYP = "oauth-client-attestation-pop+jwt";
const CHALLENGE_PREFIX = "haip-attestation-challenge:";
const JWK_PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

export type WalletAttestationOptions = {
	/**
	 * Wallet providers whose Client Attestations are accepted. Each entry
	 * supplies the keys the attestation must verify against: an inline JWK
	 * Set, a `jwksUri`, or X.509 `trustAnchors` for attestations that carry an
	 * `x5c` chain. A header `jwk` is never trusted.
	 */
	trustedIssuers: TrustedIssuer[];
	/**
	 * JWS algorithms accepted for the Client Attestation and its PoP.
	 *
	 * @default ["ES256"]
	 */
	signingAlgorithms?: string[];
	/**
	 * Maximum age of the Client Attestation PoP JWT, measured from `iat`.
	 *
	 * @default 300
	 */
	popMaxAgeSeconds?: number;
	/**
	 * Clock skew tolerated for `iat`, `nbf`, and `exp`.
	 *
	 * @default 5
	 */
	clockToleranceSeconds?: number;
	/**
	 * Require the PoP to carry a `challenge` obtained from the challenge
	 * endpoint. A PoP that carries a challenge is always checked against an
	 * issued, unused one.
	 *
	 * @default false
	 */
	requireChallenge?: boolean;
	/**
	 * Lifetime of challenges issued by the challenge endpoint, in seconds.
	 *
	 * @default 300
	 */
	challengeExpiresInSeconds?: number;
};

function invalidClient(description: string): never {
	throw new APIError("BAD_REQUEST", {
		error: "invalid_client",
		error_description: description,
	});
}

function asPublicJwk(value: unknown): JWK | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return undefined;
	}
	const jwk = value as JWK;
	if (typeof jwk.kty !== "string" || jwk.kty === "oct") return undefined;
	if (JWK_PRIVATE_MEMBERS.some((member) => member in jwk)) return undefined;
	return jwk;
}

function normalizeTyp(typ: string | undefined) {
	return typ?.toLowerCase().replace(/^application\//, "");
}

/** Issues a single-use attestation challenge (draft-ietf-oauth-attestation-based-client-auth §8). */
export async function issueAttestationChallenge(
	ctx: GenericEndpointContext,
	expiresInSeconds: number,
) {
	const challenge = generateRandomString(32);
	await ctx.context.internalAdapter.createVerificationValue({
		identifier: `${CHALLENGE_PREFIX}${challenge}`,
		value: "attestation_challenge",
		expiresAt: new Date(Date.now() + expiresInSeconds * 1000),
	});
	return challenge;
}

async function consumeAttestationChallenge(
	ctx: GenericEndpointContext,
	challenge: string,
) {
	const consumed = await ctx.context.internalAdapter.consumeVerificationValue(
		`${CHALLENGE_PREFIX}${challenge}`,
	);
	return consumed?.value === "attestation_challenge";
}

/**
 * Attestation-Based Client Authentication strategy
 * (draft-ietf-oauth-attestation-based-client-auth, HAIP §4.4.1).
 *
 * The `client_assertion` carries the Client Attestation JWT and the Client
 * Attestation PoP JWT joined by `~`. The attestation must verify against a
 * configured trusted issuer; its `cnf.jwk` (the wallet instance key) must sign
 * the PoP. The PoP is bound to this authorization server, fresh, single-use,
 * and, when a challenge is presented or required, to an issued challenge.
 */
export function createWalletAttestationStrategy(
	options: WalletAttestationOptions,
) {
	assertTrustedIssuers("walletAttestation", options?.trustedIssuers);
	const algorithms = options.signingAlgorithms ?? ["ES256"];
	const popMaxAgeSeconds = options.popMaxAgeSeconds ?? 300;
	const clockTolerance = options.clockToleranceSeconds ?? 5;

	return async (
		input: OAuthClientAuthenticationInput,
	): Promise<OAuthClientAuthenticationResult> => {
		const parts = input.assertion.split("~");
		if (parts.length !== 2 || !parts[0] || !parts[1]) {
			invalidClient("client_assertion must contain two JWTs separated by '~'");
		}
		const [attestationJwt, popJwt] = parts as [string, string];

		let attestation: JWTPayload;
		try {
			({ payload: attestation } = await verifyTrustedJwt(attestationJwt, {
				trustedIssuers: options.trustedIssuers,
				types: [ATTESTATION_TYP],
				algorithms,
				clockToleranceSeconds: clockTolerance,
			}));
		} catch (error) {
			invalidClient(
				`invalid client attestation: ${error instanceof Error ? error.message : "verification failed"}`,
			);
		}
		const clientId = attestation.sub;
		if (typeof clientId !== "string" || !clientId) {
			invalidClient("client attestation must include sub");
		}
		if (typeof attestation.exp !== "number") {
			invalidClient("client attestation must include exp");
		}
		if (input.clientId && input.clientId !== clientId) {
			invalidClient("client attestation sub does not match client_id");
		}
		const instanceKey = asPublicJwk(
			(attestation.cnf as { jwk?: unknown } | undefined)?.jwk,
		);
		if (!instanceKey) {
			invalidClient("client attestation must include a public cnf.jwk");
		}

		let pop: JWTPayload;
		try {
			const header = decodeProtectedHeader(popJwt);
			if (normalizeTyp(header.typ) !== ATTESTATION_POP_TYP) {
				throw new Error(`unexpected typ: ${header.typ ?? "(missing)"}`);
			}
			if (!header.alg || !algorithms.includes(header.alg)) {
				throw new Error(`unsupported algorithm: ${header.alg ?? "none"}`);
			}
			const key = await importJWK(instanceKey, header.alg);
			({ payload: pop } = await jwtVerify(popJwt, key, {
				algorithms,
				clockTolerance,
			}));
		} catch (error) {
			invalidClient(
				`invalid client attestation PoP: ${error instanceof Error ? error.message : "verification failed"}`,
			);
		}

		const issuer = getIssuer(input.ctx, input.opts);
		const audiences = Array.isArray(pop.aud)
			? pop.aud
			: pop.aud
				? [pop.aud]
				: [];
		const audience = [issuer, input.expectedAudience].find(
			(candidate): candidate is string =>
				typeof candidate === "string" && audiences.includes(candidate),
		);
		if (!audience) {
			invalidClient(
				"client attestation PoP aud must be the authorization server issuer",
			);
		}
		if (pop.iss !== undefined && pop.iss !== clientId) {
			invalidClient("client attestation PoP iss does not match the client");
		}
		const now = Math.floor(Date.now() / 1000);
		if (typeof pop.iat !== "number") {
			invalidClient("client attestation PoP must include iat");
		}
		if (pop.iat > now + clockTolerance) {
			invalidClient("client attestation PoP iat is in the future");
		}
		if (now - pop.iat > popMaxAgeSeconds + clockTolerance) {
			invalidClient("client attestation PoP is too old");
		}

		const challenge =
			typeof pop.challenge === "string"
				? pop.challenge
				: typeof pop.nonce === "string"
					? pop.nonce
					: undefined;
		if (challenge) {
			if (!(await consumeAttestationChallenge(input.ctx, challenge))) {
				throw new APIError("BAD_REQUEST", {
					error: "use_attestation_challenge",
					error_description:
						"client attestation challenge is invalid or expired",
				});
			}
		} else if (options.requireChallenge) {
			throw new APIError("BAD_REQUEST", {
				error: "use_attestation_challenge",
				error_description: "client attestation PoP must include a challenge",
			});
		}

		// Single-use jti and audience binding, shared with the built-in
		// private_key_jwt path. The jti tombstone only has to outlive the window
		// in which this PoP passes the iat check above, so a PoP without exp (the
		// draft makes it optional) is bounded by its iat.
		await consumeClientAssertion(input.ctx, input.opts, {
			namespace: `${WALLET_ATTESTATION_TYPE}:${clientId}`,
			payload: {
				aud: audience,
				iat: pop.iat,
				jti: pop.jti,
				exp: Math.min(
					typeof pop.exp === "number" ? pop.exp : Number.POSITIVE_INFINITY,
					pop.iat + popMaxAgeSeconds + clockTolerance,
					now + (input.opts.assertionMaxLifetime ?? 300),
				),
			},
			expectedAudience: audience,
		});

		return { clientId };
	};
}
