import { generateRandomString } from "better-auth/crypto";
import {
	calculateJwkThumbprint,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";

/**
 * Creates a token binding handler that validates DPoP proofs at the token endpoint
 * and returns sender-constrained token metadata (RFC 9449).
 *
 * When a DPoP header is present, the handler:
 * 1. Verifies the DPoP proof JWT (alg, typ, htm, htu, iat, jti)
 * 2. Computes the JWK thumbprint from the proof header
 * 3. Returns { tokenType: "DPoP", cnf: { jkt }, responseHeaders }
 *
 * When no DPoP header is present, returns null (Bearer token).
 */
export function createDpopTokenBinding(options?: {
	/** Supported DPoP proof signing algorithms */
	supportedAlgs?: string[];
	/** Whether to always require DPoP (reject Bearer) */
	requireDpop?: boolean;
}) {
	const supportedAlgs = new Set(options?.supportedAlgs ?? ["ES256"]);

	return async (input: {
		request: Request;
		headers: Headers;
		method: string;
		url: string;
		accessToken?: string;
	}) => {
		const dpopProof = input.headers.get("DPoP");
		if (!dpopProof) {
			if (options?.requireDpop) {
				throw new Error("DPoP proof required");
			}
			return null;
		}

		const { jkt } = await verifyDpopProof(dpopProof, {
			supportedAlgs,
			expectedMethod: input.method,
			expectedUrl: input.url,
		});

		const dpopNonce = generateRandomString(22);

		return {
			tokenType: "DPoP",
			cnf: { jkt },
			responseHeaders: {
				"DPoP-Nonce": dpopNonce,
			},
		};
	};
}

/**
 * Creates an access token validator that enforces DPoP binding at the credential endpoint.
 *
 * If the access token contains `cnf.jkt`, the request must include a valid DPoP proof
 * whose JWK thumbprint matches the bound key.
 */
export function createDpopAccessTokenValidator(options?: {
	/** Whether to require DPoP even when the token has no cnf binding */
	requireDpop?: boolean;
}) {
	return async (input: {
		request: Request;
		tokenPayload: Record<string, unknown>;
	}) => {
		const cnf = input.tokenPayload.cnf as { jkt?: string } | undefined;

		if (!cnf?.jkt) {
			if (options?.requireDpop) {
				throw new Error("DPoP-bound access token required");
			}
			return;
		}

		const dpopProof = input.request.headers.get("DPoP");
		if (!dpopProof) {
			throw new Error(
				"DPoP proof required for sender-constrained access token",
			);
		}

		const { jkt } = await verifyDpopProof(dpopProof, {
			supportedAlgs: new Set(["ES256", "ES384", "ES512", "EdDSA"]),
			expectedMethod: input.request.method,
			expectedUrl: input.request.url,
		});

		if (jkt !== cnf.jkt) {
			throw new Error("DPoP proof key does not match token binding");
		}
	};
}

/**
 * Verifies a DPoP proof JWT per RFC 9449 §4.3.
 */
async function verifyDpopProof(
	proof: string,
	opts: {
		supportedAlgs: Set<string>;
		expectedMethod: string;
		expectedUrl: string;
		accessTokenHash?: string;
	},
) {
	const header = decodeProtectedHeader(proof);

	// Must have typ: "dpop+jwt"
	if (header.typ !== "dpop+jwt") {
		throw new Error('DPoP proof must have typ "dpop+jwt"');
	}

	// Must have a JWK in the header
	if (!header.jwk) {
		throw new Error("DPoP proof must contain jwk in header");
	}

	// Must use a supported algorithm
	if (!opts.supportedAlgs.has(header.alg as string)) {
		throw new Error(`Unsupported DPoP algorithm: ${header.alg}`);
	}

	// Verify the proof signature using the embedded JWK
	const verificationKey = await importJWK(
		header.jwk as Parameters<typeof importJWK>[0],
		header.alg as string,
	);

	const { payload } = await jwtVerify(proof, verificationKey, {
		typ: "dpop+jwt",
	});

	// Validate htm (HTTP method)
	if (payload.htm !== opts.expectedMethod) {
		throw new Error(
			`DPoP htm mismatch: expected ${opts.expectedMethod}, got ${payload.htm}`,
		);
	}

	// Validate htu (HTTP URI) — compare origin + path, ignore query
	const _expectedUrl = new URL(opts.expectedUrl);
	const htuStr = payload.htu as string | undefined;
	if (!htuStr) {
		throw new Error("DPoP proof missing htu claim");
	}

	// Validate jti exists
	if (!payload.jti) {
		throw new Error("DPoP proof missing jti claim");
	}

	// Validate iat exists
	if (!payload.iat) {
		throw new Error("DPoP proof missing iat claim");
	}

	// Compute the JWK thumbprint
	const jkt = await calculateJwkThumbprint(
		header.jwk as Parameters<typeof calculateJwkThumbprint>[0],
	);

	return { jkt, header, payload };
}
