import type { JWK } from "jose";
import { compactDecrypt, importJWK } from "jose";
import type { Awaitable } from "./types";

const JWK_PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

export type JarmHandlerOptions = {
	/**
	 * Private key that decrypts `direct_post.jwt` responses (an EC JWK with
	 * `d`), or a resolver for it. Its public part is the key advertised in the
	 * request's `client_metadata.jwks`.
	 */
	decryptionKey: JWK | (() => Awaitable<JWK>);
	/**
	 * Accepted key management algorithms.
	 *
	 * @default ["ECDH-ES"]
	 */
	supportedAlgs?: string[];
	/**
	 * Accepted content encryption algorithms.
	 *
	 * @default ["A128GCM", "A256GCM"]
	 */
	supportedEnc?: string[];
};

export type JarmDecryptionResult = {
	/** Decrypted plaintext: the JSON response object or a nested signed JWT. */
	payload: string;
	/** Public part of the key that decrypted the response. */
	decryptionJwk: JWK;
};

function publicPart(jwk: JWK): JWK {
	return Object.fromEntries(
		Object.entries(jwk).filter(
			([member]) => !JWK_PRIVATE_MEMBERS.includes(member),
		),
	) as JWK;
}

/**
 * Creates the decryptor for OpenID4VP encrypted responses
 * (`response_mode=direct_post.jwt`, OID4VP 1.0 §8.3, HAIP §5.2).
 *
 * Register it as `responseModeHandlers["direct_post.jwt"]` in the oidc4vp
 * plugin. The algorithms are enforced before decryption. The oidc4vp plugin
 * passes the decryptor to `@openid4vc/openid4vp`, which validates the
 * decrypted response against the authorization request it answers.
 */
export function createJarmHandler(options: JarmHandlerOptions) {
	const keyManagementAlgorithms = options.supportedAlgs ?? ["ECDH-ES"];
	const contentEncryptionAlgorithms = options.supportedEnc ?? [
		"A128GCM",
		"A256GCM",
	];

	return async (input: { response: string }): Promise<JarmDecryptionResult> => {
		const jwk =
			typeof options.decryptionKey === "function"
				? await options.decryptionKey()
				: options.decryptionKey;
		const { plaintext } = await compactDecrypt(
			input.response,
			async (header) => importJWK(jwk, header.alg),
			{ keyManagementAlgorithms, contentEncryptionAlgorithms },
		);
		return {
			payload: new TextDecoder().decode(plaintext),
			decryptionJwk: publicPart(jwk),
		};
	};
}
