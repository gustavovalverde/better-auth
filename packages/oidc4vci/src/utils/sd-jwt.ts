import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { APIError } from "better-auth/api";
import { symmetricDecrypt } from "better-auth/crypto";
import type { JwtOptions } from "better-auth/plugins";
import { base64url, importJWK } from "jose";
import { DEFAULT_SD_DISCLOSURES, SD_HASH_ALG } from "../constants";
import type { RequestedClaim, SdJwtDisclosureFrame } from "../types";
import { getOrCreateSigningKey } from "./jwt";

/**
 * Web Crypto signature parameters per JWS algorithm (RFC 7518 §3). Web Crypto
 * produces the raw `r || s` ECDSA encoding JWS requires, unlike a DER signer.
 */
const WEB_CRYPTO_SIGN_PARAMS: Record<
	string,
	AlgorithmIdentifier | RsaPssParams | EcdsaParams
> = {
	EdDSA: { name: "Ed25519" },
	Ed25519: { name: "Ed25519" },
	ES256: { name: "ECDSA", hash: "SHA-256" },
	ES384: { name: "ECDSA", hash: "SHA-384" },
	ES512: { name: "ECDSA", hash: "SHA-512" },
	RS256: { name: "RSASSA-PKCS1-v1_5" },
	RS384: { name: "RSASSA-PKCS1-v1_5" },
	RS512: { name: "RSASSA-PKCS1-v1_5" },
	PS256: { name: "RSA-PSS", saltLength: 32 },
	PS384: { name: "RSA-PSS", saltLength: 48 },
	PS512: { name: "RSA-PSS", saltLength: 64 },
};

function randomSalt(length: number) {
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return base64url.encode(bytes);
}

export function buildDisclosureFrame(
	config: {
		sdJwt?: { disclosures?: string[]; decoyCount?: number };
	},
	payload?: Record<string, unknown>,
	requestedClaims?: RequestedClaim[] | null,
): SdJwtDisclosureFrame | undefined {
	const configured = config.sdJwt?.disclosures;
	const requestedDisclosures = requestedClaims
		? requestedClaims
				.filter((claim) => !claim.mandatory)
				.map((claim) => claim.name)
		: null;
	const disclosures = requestedDisclosures ??
		configured ?? [...DEFAULT_SD_DISCLOSURES];
	if (!Array.isArray(disclosures)) return undefined;
	const filtered = disclosures.filter((claim) => {
		if (typeof claim !== "string") return false;
		if (payload && payload[claim] === undefined) return false;
		return true;
	});
	const unique = Array.from(new Set(filtered));
	if (!unique.length) return undefined;

	const frame: SdJwtDisclosureFrame = {
		_sd: unique,
	};

	const decoys = config.sdJwt?.decoyCount;
	if (typeof decoys === "number" && decoys > 0) {
		frame._sd_decoy = Math.floor(decoys);
	}

	return frame;
}

export async function issueSdJwtCredential(
	ctx: {
		context: {
			baseURL: string;
			adapter: { findMany: <T>(args: { model: string }) => Promise<T[]> };
			secret: string;
		};
	},
	input: {
		payload: Record<string, unknown>;
		jwtOptions?: JwtOptions;
		disclosureFrame?: SdJwtDisclosureFrame;
		format?: string;
		additionalHeaders?: Record<string, unknown>;
		credentialSigner?: (data: string) => Promise<string> | string;
	},
) {
	const { key, alg } = await getOrCreateSigningKey(ctx, input.jwtOptions);

	const hasher = async (data: string | ArrayBuffer, hashAlg: string) => {
		if (hashAlg !== SD_HASH_ALG) {
			throw new APIError("INTERNAL_SERVER_ERROR", {
				message: `unsupported hash alg: ${hashAlg}`,
			});
		}
		const buffer =
			typeof data === "string"
				? new TextEncoder().encode(data)
				: new Uint8Array(data);
		return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
	};

	const saltGenerator = async (length: number) => randomSalt(length);

	let signer: (data: string) => Promise<string>;
	if (input.credentialSigner) {
		signer = async (data: string) => input.credentialSigner!(data);
	} else {
		const privateKeyEncryptionEnabled =
			!input.jwtOptions?.jwks?.disablePrivateKeyEncryption;
		const privateWebKey = privateKeyEncryptionEnabled
			? await symmetricDecrypt({
					key: ctx.context.secret,
					data: JSON.parse(key.privateKey),
				})
			: key.privateKey;
		const signParams = WEB_CRYPTO_SIGN_PARAMS[alg];
		if (!signParams) {
			throw new APIError("INTERNAL_SERVER_ERROR", {
				message: `unsupported credential signing alg: ${alg}`,
			});
		}
		const privateKey = await importJWK(JSON.parse(privateWebKey), alg);
		if (!(privateKey instanceof CryptoKey)) {
			throw new APIError("INTERNAL_SERVER_ERROR", {
				message: "credential signing key must be asymmetric",
			});
		}
		signer = async (data: string) => {
			const signature = await crypto.subtle.sign(
				signParams,
				privateKey,
				new TextEncoder().encode(data),
			);
			return base64url.encode(new Uint8Array(signature));
		};
	}

	const sdjwt = new SDJwtVcInstance({
		signer,
		signAlg: alg,
		hasher,
		hashAlg: SD_HASH_ALG,
		saltGenerator,
	});

	return await sdjwt.issue(
		input.payload as Parameters<typeof sdjwt.issue>[0],
		input.disclosureFrame as Parameters<typeof sdjwt.issue>[1],
		{
			header: {
				kid: key.id,
				typ: input.format ?? "vc+sd-jwt",
				...input.additionalHeaders,
			},
		},
	);
}
