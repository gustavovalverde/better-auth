import { createHash, sign as cryptoSign, randomBytes } from "node:crypto";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { APIError } from "better-auth/api";
import { symmetricDecrypt } from "better-auth/crypto";
import type { JwtOptions } from "better-auth/plugins";
import { base64url, importJWK } from "jose";
import { DEFAULT_SD_DISCLOSURES, SD_HASH_ALG } from "../constants";
import type { RequestedClaim, SdJwtDisclosureFrame } from "../types";
import { getOrCreateSigningKey } from "./jwt";

const NODE_HASH: Record<string, string | null> = {
	EdDSA: null,
	ES256: "sha256",
	ES256K: "sha256",
	ES384: "sha384",
	ES512: "sha512",
	RS256: "sha256",
	RS384: "sha384",
	RS512: "sha512",
	PS256: "sha256",
	PS384: "sha384",
	PS512: "sha512",
};

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
		return new Uint8Array(createHash("sha256").update(buffer).digest());
	};

	const saltGenerator = async (length: number) =>
		randomBytes(length).toString("base64url");

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
		const privateKey = await importJWK(JSON.parse(privateWebKey), alg);
		signer = async (data: string) => {
			const sig = cryptoSign(
				NODE_HASH[alg] ?? null,
				new TextEncoder().encode(data),
				privateKey as any,
			);
			return base64url.encode(sig);
		};
	}

	const sdjwt = new SDJwtVcInstance({
		signer,
		signAlg: alg,
		hasher,
		hashAlg: SD_HASH_ALG,
		saltGenerator,
	});

	return await sdjwt.issue(input.payload as any, input.disclosureFrame as any, {
		header: {
			kid: key.id,
			typ: input.format ?? "vc+sd-jwt",
			...input.additionalHeaders,
		},
	});
}
