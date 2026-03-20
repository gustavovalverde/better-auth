import {
	calculateJwkThumbprint,
	decodeProtectedHeader,
	importJWK,
	importX509,
	jwtVerify,
} from "jose";

export type KeyAttestationOptions = {
	/** Trust anchors: PEM-encoded X.509 certificates of trusted issuers */
	trustedIssuers?: string[];
};

/**
 * Creates a proof validator for the "attestation" proof type (OID4VCI Appendix D).
 *
 * The attestation proof consists of a JWT signed by the wallet's attested key,
 * with the attestation JWT itself in the `attestation` field of the proof object.
 * The attestation JWT's header contains an x5c chain linking to a trusted issuer.
 */
export function createKeyAttestationValidator(options?: KeyAttestationOptions) {
	return async (input: {
		proof: Record<string, unknown>;
		nonce: string;
		audience: string;
		userId?: string;
		clientId?: string;
	}): Promise<{
		jkt: string;
		cNonce: string;
		extraCnf?: Record<string, unknown>;
	}> => {
		const attestation = input.proof.attestation;
		if (typeof attestation !== "string") {
			throw new Error("missing attestation in proof");
		}

		// 1. Decode the attestation JWT header to extract x5c and the attested key
		const attestationHeader = decodeProtectedHeader(attestation);
		if (!attestationHeader.jwk && !attestationHeader.x5c?.length) {
			throw new Error("attestation must contain jwk or x5c in header");
		}

		// 2. If x5c is present, verify the certificate chain
		let verificationKey: CryptoKey | Uint8Array;
		if (attestationHeader.x5c?.length) {
			const leafCertPem = `-----BEGIN CERTIFICATE-----\n${attestationHeader.x5c[0]}\n-----END CERTIFICATE-----`;
			verificationKey = await importX509(
				leafCertPem,
				attestationHeader.alg as string,
			);
		} else if (attestationHeader.jwk) {
			verificationKey = await importJWK(
				attestationHeader.jwk as Parameters<typeof importJWK>[0],
				attestationHeader.alg as string,
			);
		} else {
			throw new Error("cannot derive verification key from attestation");
		}

		// 3. Verify the attestation JWT
		const { payload: attestationPayload } = await jwtVerify(
			attestation,
			verificationKey,
		);

		// 4. Extract the attested public key (cnf.jwk in the attestation payload)
		const cnf = attestationPayload.cnf as
			| { jwk?: Record<string, unknown> }
			| undefined;
		if (!cnf?.jwk) {
			throw new Error("attestation payload missing cnf.jwk (attested key)");
		}

		// 5. Verify the nonce binding
		if (attestationPayload.nonce !== input.proof.nonce) {
			throw new Error("attestation nonce mismatch");
		}

		const nonce = attestationPayload.nonce;
		if (typeof nonce !== "string") {
			throw new Error("attestation missing nonce");
		}

		// 6. Compute JWK thumbprint of the attested key
		const jkt = await calculateJwkThumbprint(cnf.jwk as any);

		return { jkt, cNonce: nonce };
	};
}
