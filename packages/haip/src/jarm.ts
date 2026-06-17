import { compactDecrypt, importJWK } from "jose";
import type { Awaitable } from "./types";

export type JarmHandlerOptions = {
	/** ECDH-ES decryption key (JWK with private key material) or async resolver. */
	decryptionKey: JsonWebKey | (() => Awaitable<JsonWebKey>);
	/** Allowed key agreement algorithms. Default: ["ECDH-ES"] */
	supportedAlgs?: string[];
	/** Allowed content encryption algorithms. Default: ["A128GCM", "A256GCM"] */
	supportedEnc?: string[];
};

/**
 * Creates a JARM handler that decrypts JWE-encrypted VP authorization responses.
 *
 * Used as `responseModeHandlers["direct_post.jwt"]` in oidc4vp config.
 */
export function createJarmHandler(options: JarmHandlerOptions) {
	const allowedAlgs = options.supportedAlgs ?? ["ECDH-ES"];
	const allowedEnc = options.supportedEnc ?? ["A128GCM", "A256GCM"];

	return async (input: {
		response: string;
	}): Promise<Record<string, unknown>> => {
		const jwk =
			typeof options.decryptionKey === "function"
				? await options.decryptionKey()
				: options.decryptionKey;

		const key = await importJWK(jwk, "ECDH-ES");

		const { plaintext, protectedHeader } = await compactDecrypt(
			input.response,
			key,
		);

		if (!allowedAlgs.includes(protectedHeader.alg)) {
			throw new Error(
				`Unsupported JWE algorithm: ${protectedHeader.alg}. Allowed: ${allowedAlgs.join(", ")}`,
			);
		}
		if (!allowedEnc.includes(protectedHeader.enc)) {
			throw new Error(
				`Unsupported JWE encryption: ${protectedHeader.enc}. Allowed: ${allowedEnc.join(", ")}`,
			);
		}

		const decoded = new TextDecoder().decode(plaintext);
		return JSON.parse(decoded) as Record<string, unknown>;
	};
}
