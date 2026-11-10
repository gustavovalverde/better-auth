import type { AuthContext, BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import type { JwtOptions } from "better-auth/plugins";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import type { JWK } from "jose";
import {
	base64url,
	calculateJwkThumbprint,
	exportJWK,
	generateKeyPair,
	SignJWT,
} from "jose";
import type { Oidc4vciOptions } from "../src";
import { oidc4vci, PRE_AUTH_GRANT_TYPE } from "../src";
import { requireApi } from "./api-helpers";

export const BASE_URL = "http://localhost:3000";
export const AUTH_BASE_URL = `${BASE_URL}/api/auth`;
const TOKEN_URL = `${AUTH_BASE_URL}/oauth2/token`;
export const CREDENTIAL_URL = `${AUTH_BASE_URL}/oidc4vci/credential`;
export const DEFERRED_URL = `${AUTH_BASE_URL}/oidc4vci/credential/deferred`;
export const CONFIG_ID = "kyc_sdjwt_v1";

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;

/**
 * The parts of the test auth instance the suites use, typed loosely so these
 * shared helpers stay portable across the plugin's inferred endpoint types.
 */
export type TestAuth = {
	api: Record<
		| "createCredentialOffer"
		| "getCredentialIssuerMetadata"
		| "getJwks"
		| "signUpEmail"
		| "updateCredentialStatus",
		(input?: any) => Promise<any>
	>;
	$context: Promise<AuthContext>;
};

export type DpopKey = { alg: string; keyPair: KeyPair; jwk: JWK; jkt: string };

export async function createDpopKey(alg = "ES256"): Promise<DpopKey> {
	const keyPair = await generateKeyPair(alg);
	const jwk = await exportJWK(keyPair.publicKey);
	return { alg, keyPair, jwk, jkt: await calculateJwkThumbprint(jwk) };
}

export async function createDpopProof(
	key: DpopKey,
	input: {
		method?: string;
		url: string;
		accessToken?: string;
		iat?: number;
		jti?: string;
		ath?: string;
		alg?: string;
	},
) {
	const ath =
		input.ath ??
		(input.accessToken
			? base64url.encode(
					new Uint8Array(
						await crypto.subtle.digest(
							"SHA-256",
							new TextEncoder().encode(input.accessToken),
						),
					),
				)
			: undefined);
	return new SignJWT({
		htm: input.method ?? "POST",
		htu: input.url,
		jti: input.jti ?? crypto.randomUUID(),
		...(ath ? { ath } : {}),
	})
		.setProtectedHeader({
			alg: input.alg ?? key.alg,
			typ: "dpop+jwt",
			jwk: key.jwk,
		})
		.setIssuedAt(input.iat ?? Math.floor(Date.now() / 1000))
		.sign(key.keyPair.privateKey);
}

export async function createJwtProof(input: {
	nonce?: string;
	audience?: string;
	alg?: string;
	iat?: number;
	typ?: string;
	omitJwk?: boolean;
}) {
	const alg = input.alg ?? "EdDSA";
	const holder = await generateKeyPair(alg);
	const jwk = await exportJWK(holder.publicKey);
	const builder = new SignJWT(input.nonce ? { nonce: input.nonce } : {})
		.setProtectedHeader({
			alg,
			typ: input.typ ?? "openid4vci-proof+jwt",
			...(input.omitJwk ? {} : { jwk }),
		})
		.setIssuedAt(input.iat ?? Math.floor(Date.now() / 1000))
		.setAudience(input.audience ?? BASE_URL);
	return { proofJwt: await builder.sign(holder.privateKey), jwk, holder };
}

export async function createIssuer(overrides?: {
	jwt?: JwtOptions;
	oidc4vci?: Partial<Oidc4vciOptions>;
	plugins?: BetterAuthOptions["plugins"];
}) {
	const authOptions = {
		baseURL: BASE_URL,
		plugins: [
			jwt(overrides?.jwt ?? { jwt: { issuer: BASE_URL } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				enforcePerClientResources: false,
				resources: [AUTH_BASE_URL, CREDENTIAL_URL],
				grantTypes: [
					"authorization_code",
					"client_credentials",
					"refresh_token",
					PRE_AUTH_GRANT_TYPE,
				],
				silenceWarnings: {
					oauthAuthServerConfig: true,
					openidConfig: true,
				},
			}),
			oidc4vci({
				credentialConfigurations: [
					{ id: CONFIG_ID, vct: "urn:example:kyc:v1" },
				],
				...overrides?.oidc4vci,
			}),
			...(overrides?.plugins ?? []),
		],
	} satisfies BetterAuthOptions;

	const instance = await getTestInstance(authOptions);
	const { auth, customFetchImpl } = instance;
	const api = requireApi(auth.api, [
		"adminCreateOAuthClient",
		"createCredentialOffer",
	] as const);

	async function createWalletClient(headers: Headers) {
		const client = await api.adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code", PRE_AUTH_GRANT_TYPE],
				skip_consent: true,
			},
		});
		return client.client_id;
	}

	async function createOffer(headers: Headers, body: Record<string, unknown>) {
		const offer = await api.createCredentialOffer({
			headers,
			body: body as { credential_configuration_id: string },
		});
		return {
			offer,
			code: offer.credential_offer.grants[PRE_AUTH_GRANT_TYPE][
				"pre-authorized_code"
			] as string,
		};
	}

	async function redeem(input: {
		code: string;
		clientId?: string;
		txCode?: string;
		resource?: string;
		dpop?: DpopKey;
	}) {
		const form = new URLSearchParams({
			grant_type: PRE_AUTH_GRANT_TYPE,
			"pre-authorized_code": input.code,
		});
		if (input.clientId) form.set("client_id", input.clientId);
		if (input.txCode) form.set("tx_code", input.txCode);
		if (input.resource) form.set("resource", input.resource);
		const headers = new Headers({
			"content-type": "application/x-www-form-urlencoded",
		});
		if (input.dpop) {
			headers.set(
				"dpop",
				await createDpopProof(input.dpop, { url: TOKEN_URL }),
			);
		}
		return customFetchImpl(TOKEN_URL, {
			method: "POST",
			headers,
			body: form.toString(),
		});
	}

	async function redeemTokens(input: Parameters<typeof redeem>[0]) {
		const res = await redeem(input);
		if (res.status !== 200) {
			throw new Error(
				`token endpoint failed: ${res.status} ${await res.text()}`,
			);
		}
		return (await res.json()) as {
			access_token: string;
			token_type: string;
			authorization_details?: Array<{ credential_identifiers?: string[] }>;
			[key: string]: unknown;
		};
	}

	async function requestNonce() {
		const res = await customFetchImpl(`${AUTH_BASE_URL}/oidc4vci/nonce`, {
			method: "POST",
		});
		return {
			res,
			body: (await res.json()) as { c_nonce: string; [key: string]: unknown },
		};
	}

	async function nonce() {
		return (await requestNonce()).body.c_nonce;
	}

	async function requestCredential(input: {
		accessToken: string;
		body: Record<string, unknown>;
		dpop?: DpopKey;
		dpopProof?: string;
		scheme?: "Bearer" | "DPoP";
		url?: string;
	}) {
		const url = input.url ?? CREDENTIAL_URL;
		const headers = new Headers({
			authorization: `${input.scheme ?? (input.dpop || input.dpopProof ? "DPoP" : "Bearer")} ${input.accessToken}`,
			"content-type": "application/json",
		});
		const proof =
			input.dpopProof ??
			(input.dpop
				? await createDpopProof(input.dpop, {
						url,
						accessToken: input.accessToken,
					})
				: undefined);
		if (proof) headers.set("dpop", proof);
		return customFetchImpl(url, {
			method: "POST",
			headers,
			body: JSON.stringify(input.body),
		});
	}

	/** Signs in, registers a wallet, and redeems an offer for the test user. */
	async function issueAccessToken(options?: {
		dpop?: DpopKey;
		offer?: Record<string, unknown>;
	}) {
		const session = await instance.signInWithTestUser();
		const clientId = await createWalletClient(session.headers);
		const { code } = await createOffer(session.headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
			...options?.offer,
		});
		const tokens = await redeemTokens({
			code,
			clientId,
			dpop: options?.dpop,
		});
		return { ...session, clientId, tokens };
	}

	return {
		auth: auth as unknown as TestAuth,
		customFetchImpl: customFetchImpl as typeof fetch,
		signInWithTestUser: instance.signInWithTestUser,
		signInWithUser: instance.signInWithUser,
		createWalletClient,
		createOffer,
		redeem,
		redeemTokens,
		requestNonce,
		nonce,
		requestCredential,
		issueAccessToken,
	};
}

export function readCredential(body: unknown) {
	const credentials = (
		body as { credentials?: Array<{ credential?: unknown }> }
	).credentials;
	const credential = credentials?.[0]?.credential;
	if (typeof credential !== "string") {
		throw new Error(
			`credential missing from response: ${JSON.stringify(body)}`,
		);
	}
	return credential;
}
