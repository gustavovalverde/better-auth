import { APIError } from "better-auth/api";
import { symmetricDecrypt } from "better-auth/crypto";
import type { JwtOptions } from "better-auth/plugins";
import { createJwk } from "better-auth/plugins";
import type { JSONWebKeySet, JWTPayload } from "jose";
import { importJWK, SignJWT } from "jose";
import type { JwkRecord } from "../types";

export async function signSdJwtJwt(
	ctx: {
		context: {
			baseURL: string;
			adapter: {
				findMany: <T>(args: { model: string }) => Promise<T[]>;
			};
			secret: string;
		};
	},
	input: {
		payload: Record<string, unknown>;
		jwtOptions?: JwtOptions;
		header?: Record<string, unknown>;
		applyDefaultClaims?: boolean;
	},
) {
	const jwtOptions = input.jwtOptions;
	const payload = { ...input.payload } as JWTPayload;
	const nowSeconds = Math.floor(Date.now() / 1000);
	const applyDefaults = input.applyDefaultClaims !== false;
	payload.iat = typeof payload.iat === "number" ? payload.iat : nowSeconds;
	if (applyDefaults) {
		payload.exp =
			typeof payload.exp === "number" ? payload.exp : payload.iat + 900;
		payload.iss =
			(typeof payload.iss === "string" && payload.iss) ||
			jwtOptions?.jwt?.issuer ||
			ctx.context.baseURL;
		payload.aud =
			payload.aud ??
			jwtOptions?.jwt?.audience ??
			ctx.context.baseURL ??
			undefined;
	}

	if (jwtOptions?.jwt?.sign) {
		return await jwtOptions.jwt.sign(payload);
	}

	const { key, alg } = await getOrCreateSigningKey(ctx, jwtOptions);
	const privateKeyEncryptionEnabled =
		!jwtOptions?.jwks?.disablePrivateKeyEncryption;
	const privateWebKey = privateKeyEncryptionEnabled
		? await symmetricDecrypt({
				key: ctx.context.secret,
				data: JSON.parse(key.privateKey),
			})
		: key.privateKey;
	const privateKey = await importJWK(JSON.parse(privateWebKey), alg);

	const jwt = new SignJWT(payload).setProtectedHeader({
		alg,
		kid: key.id,
		...(input.header ?? {}),
	});
	return await jwt.sign(privateKey);
}

export async function getOrCreateSigningKey(
	ctx: {
		context: {
			adapter: {
				findMany: <T>(args: { model: string }) => Promise<T[]>;
			};
			secret: string;
		};
	},
	jwtOptions?: JwtOptions,
) {
	let key = await getLatestSigningKey(ctx, jwtOptions);
	if (!key || (key.expiresAt && key.expiresAt < new Date())) {
		key = (await createJwk(ctx as any, jwtOptions)) as JwkRecord;
	}
	const alg = key.alg ?? jwtOptions?.jwks?.keyPairConfig?.alg ?? "EdDSA";
	return { key, alg };
}

export async function getLatestSigningKey(
	ctx: {
		context: {
			adapter: {
				findMany: <T>(args: { model: string }) => Promise<T[]>;
			};
		};
	},
	jwtOptions?: JwtOptions,
) {
	const keys = jwtOptions?.adapter?.getJwks
		? await jwtOptions.adapter.getJwks(ctx as any)
		: await ctx.context.adapter.findMany<JwkRecord>({
				model: "jwks",
			});
	if (!keys?.length) return null;
	return keys.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())[0]!;
}

export async function getLocalJwks(
	ctx: {
		context: {
			adapter: {
				findMany: <T>(args: { model: string }) => Promise<T[]>;
			};
		};
	},
	jwtPlugin: {
		options?: JwtOptions;
	},
): Promise<JSONWebKeySet> {
	const keySets = await ctx.context.adapter.findMany<{
		id: string;
		publicKey: string;
		alg?: string | null;
		crv?: string | null;
	}>({ model: "jwks" });

	if (!keySets.length) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			message: "no jwks keys available",
		});
	}

	const keyPairConfig = jwtPlugin.options?.jwks?.keyPairConfig;
	const defaultAlg = keyPairConfig?.alg ?? "EdDSA";
	const defaultCrv =
		keyPairConfig && "crv" in keyPairConfig ? keyPairConfig.crv : undefined;

	return {
		keys: keySets.map((keySet) => ({
			...JSON.parse(keySet.publicKey),
			kid: keySet.id,
			alg: keySet.alg ?? defaultAlg,
			...(keySet.crv || defaultCrv ? { crv: keySet.crv ?? defaultCrv } : {}),
		})),
	} satisfies JSONWebKeySet;
}
