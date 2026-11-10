import type {
	ProofValidationResult,
	ProofValidator,
} from "@better-auth/oidc4vci";
import type { JWK } from "jose";
import type { TrustedIssuer } from "./trust";
import { assertTrustedIssuers, verifyTrustedJwt } from "./trust";

const KEY_ATTESTATION_TYP = "key-attestation+jwt";
const JWK_PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

export type KeyAttestationOptions = {
	/**
	 * Key attestation issuers (wallet providers or WSCD vendors) whose
	 * attestations are accepted, identified by configured keys or X.509 trust
	 * anchors. A key attestation is never verified with a key from its own
	 * header `jwk`.
	 */
	trustedIssuers: TrustedIssuer[];
	/**
	 * JWS algorithms accepted for key attestations.
	 *
	 * @default ["ES256"]
	 */
	signingAlgorithms?: string[];
	/**
	 * Maximum age of the key attestation, measured from `iat`.
	 *
	 * @default 300
	 */
	maxAgeSeconds?: number;
	/**
	 * Clock skew tolerated for `iat`, `nbf`, and `exp`.
	 *
	 * @default 5
	 */
	clockToleranceSeconds?: number;
};

function asPublicJwk(value: unknown): JWK | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return undefined;
	}
	const jwk = value as JWK;
	if (typeof jwk.kty !== "string" || jwk.kty === "oct") return undefined;
	if (JWK_PRIVATE_MEMBERS.some((member) => member in jwk)) return undefined;
	return jwk;
}

/**
 * Creates a proof validator for the `attestation` proof type
 * (OpenID4VCI 1.0 §F.3 and Appendix D): the proof is a Key Attestation JWT
 * that a trusted issuer signed over the attested keys and the `c_nonce`.
 *
 * Register it as `proofValidators.attestation` in the oidc4vci plugin.
 * Batch issuance is not supported, so the attestation must attest exactly one
 * key, which the issued credential is bound to.
 */
export function createKeyAttestationValidator(
	options: KeyAttestationOptions,
): ProofValidator {
	assertTrustedIssuers("keyAttestation", options?.trustedIssuers);
	const algorithms = options.signingAlgorithms ?? ["ES256"];
	const maxAgeSeconds = options.maxAgeSeconds ?? 300;
	const clockTolerance = options.clockToleranceSeconds ?? 5;

	return async (input): Promise<ProofValidationResult> => {
		if (typeof input.proof !== "string") {
			throw new Error("attestation proof must be a compact JWT");
		}
		const { payload } = await verifyTrustedJwt(input.proof, {
			trustedIssuers: options.trustedIssuers,
			types: [KEY_ATTESTATION_TYP],
			algorithms,
			clockToleranceSeconds: clockTolerance,
		});

		const now = Math.floor(Date.now() / 1000);
		if (typeof payload.iat !== "number") {
			throw new Error("key attestation must include iat");
		}
		if (
			payload.iat > now + clockTolerance ||
			now - payload.iat > maxAgeSeconds + clockTolerance
		) {
			throw new Error("key attestation iat is outside the accepted window");
		}
		const nonce = payload.nonce;
		if (typeof nonce !== "string" || !nonce) {
			throw new Error("key attestation must include the c_nonce");
		}
		const attestedKeys = payload.attested_keys;
		if (!Array.isArray(attestedKeys) || attestedKeys.length === 0) {
			throw new Error("key attestation must include attested_keys");
		}
		if (attestedKeys.length !== 1) {
			throw new Error(
				"key attestation must attest exactly one key; batch issuance is not supported",
			);
		}
		const jwk = asPublicJwk(attestedKeys[0]);
		if (!jwk) {
			throw new Error("attested key must be a public JWK");
		}
		return { jwk, cNonce: nonce };
	};
}
