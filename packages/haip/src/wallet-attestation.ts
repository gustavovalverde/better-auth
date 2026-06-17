import type {
	OAuthClientAuthenticationInput,
	OAuthClientAuthenticationResult,
} from "@better-auth/oauth-provider";
import { consumeClientAssertion } from "@better-auth/oauth-provider";
import { decodeProtectedHeader, importJWK, importX509, jwtVerify } from "jose";

/** The standard assertion type URN for wallet attestation */
export const WALLET_ATTESTATION_TYPE =
	"urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";

/**
 * HAIP Wallet Attestation client authentication strategy.
 *
 * Implements `attest_jwt_client_auth` (OID4VCI HAIP §6.3).
 * The client_assertion is two JWTs concatenated with `~`:
 *   1. Client Attestation JWT — signed by a trusted issuer (wallet manufacturer)
 *   2. Client Attestation PoP JWT — signed by the wallet instance key
 */
export function createWalletAttestationStrategy(options?: {
	trustedIssuers?: string[];
}) {
	return async (
		input: OAuthClientAuthenticationInput,
	): Promise<OAuthClientAuthenticationResult> => {
		const parts = input.assertion.split("~");
		if (parts.length !== 2 || !parts[0] || !parts[1]) {
			throw new Error(
				"client_assertion must contain two JWTs separated by '~'",
			);
		}

		const [clientAttestationJwt, popJwt] = parts as [string, string];

		// 1. Verify Client Attestation JWT (signed by wallet manufacturer)
		const caHeader = decodeProtectedHeader(clientAttestationJwt);

		let caVerificationKey: CryptoKey | Uint8Array;
		if (caHeader.x5c?.length) {
			const leafCertPem = `-----BEGIN CERTIFICATE-----\n${caHeader.x5c[0]}\n-----END CERTIFICATE-----`;
			caVerificationKey = await importX509(leafCertPem, caHeader.alg as string);
		} else if (caHeader.jwk) {
			caVerificationKey = await importJWK(
				caHeader.jwk as Parameters<typeof importJWK>[0],
				caHeader.alg as string,
			);
		} else {
			throw new Error("Client Attestation JWT header must contain x5c or jwk");
		}

		const { payload: caPayload } = await jwtVerify(
			clientAttestationJwt,
			caVerificationKey,
		);

		if (
			options?.trustedIssuers?.length &&
			(typeof caPayload.iss !== "string" ||
				!options.trustedIssuers.includes(caPayload.iss))
		) {
			throw new Error("Client Attestation issuer is not trusted");
		}

		// 2. Extract the wallet instance public key from cnf.jwk
		const cnf = caPayload.cnf as { jwk?: Record<string, unknown> } | undefined;
		if (!cnf?.jwk) {
			throw new Error(
				"Client Attestation JWT missing cnf.jwk (wallet instance key)",
			);
		}

		// 3. Verify PoP JWT (signed by the wallet instance key from cnf.jwk)
		const popVerificationKey = await importJWK(
			cnf.jwk as Parameters<typeof importJWK>[0],
			decodeProtectedHeader(popJwt).alg as string,
		);
		const { payload: popPayload } = await jwtVerify(popJwt, popVerificationKey);

		// 4. Derive client identity from the request or the attestation's sub claim
		const walletClientId =
			input.clientId || (caPayload.sub as string | undefined);
		if (!walletClientId) {
			throw new Error(
				"Cannot determine client_id: not in request and not in attestation sub",
			);
		}

		// 5. Enforce RFC 7523 assertion hygiene on the PoP (audience binding,
		// bounded exp, single-use jti) so this method matches the built-in
		// private_key_jwt path and cannot be forged or replayed.
		await consumeClientAssertion(input.ctx, input.opts, {
			namespace: `${WALLET_ATTESTATION_TYPE}:${walletClientId}`,
			payload: popPayload,
			expectedAudience:
				input.expectedAudience ?? `${input.ctx.context.baseURL}/oauth2/token`,
		});

		// The provider resolves and authorizes the client record itself.
		return { clientId: walletClientId };
	};
}
