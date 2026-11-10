import type { AuthContext, BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import type { Oidc4vciOptions } from "@better-auth/oidc4vci";
import { oidc4vci } from "@better-auth/oidc4vci";
import type { Oidc4vpOptions } from "@better-auth/oidc4vp";
import { oidc4vp } from "@better-auth/oidc4vp";
import { setGlobalConfig } from "@openid4vc/oauth2";
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
import type { HaipOptions } from "../src";
import { createParResolver, haip } from "../src";
import { requireApi } from "./api-helpers";

// The test server runs on http://localhost; @openid4vc requires https URLs
// unless this is set.
setGlobalConfig({ allowInsecureUrls: true });

export const BASE_URL = "http://localhost:3000";
export const AUTH_BASE_URL = `${BASE_URL}/api/auth`;
export const TOKEN_URL = `${AUTH_BASE_URL}/oauth2/token`;
const CREDENTIAL_URL = `${AUTH_BASE_URL}/oidc4vci/credential`;
export const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
export const CONFIG_ID = "kyc_sdjwt_v1";
export const VCT = "urn:example:kyc:v1";

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;
export type DpopKey = { alg: string; keyPair: KeyPair; jwk: JWK; jkt: string };

/**
 * The parts of the test auth instance the suites use, typed loosely so these
 * shared helpers stay portable across the plugins' inferred endpoint types.
 */
export type TestAuth = {
	api: Record<
		| "createCredentialOffer"
		| "createHaipVpRequest"
		| "getOAuthServerConfig"
		| "getJwks",
		(input?: any) => Promise<any>
	>;
	$context: Promise<AuthContext>;
};

export async function createDpopKey(alg = "ES256"): Promise<DpopKey> {
	const keyPair = await generateKeyPair(alg);
	const jwk = await exportJWK(keyPair.publicKey);
	return { alg, keyPair, jwk, jkt: await calculateJwkThumbprint(jwk) };
}

export async function sha256(value: string) {
	return base64url.encode(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
		),
	);
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
	},
) {
	const ath =
		input.ath ??
		(input.accessToken ? await sha256(input.accessToken) : undefined);
	return new SignJWT({
		htm: input.method ?? "POST",
		htu: input.url,
		jti: input.jti ?? crypto.randomUUID(),
		...(ath ? { ath } : {}),
	})
		.setProtectedHeader({ alg: key.alg, typ: "dpop+jwt", jwk: key.jwk })
		.setIssuedAt(input.iat ?? Math.floor(Date.now() / 1000))
		.sign(key.keyPair.privateKey);
}

export async function createJwtProof(nonce: string) {
	const holder = await generateKeyPair("ES256");
	const jwk = await exportJWK(holder.publicKey);
	const proofJwt = await new SignJWT({ nonce })
		.setProtectedHeader({ alg: "ES256", typ: "openid4vci-proof+jwt", jwk })
		.setIssuedAt()
		.setAudience(BASE_URL)
		.sign(holder.privateKey);
	return { proofJwt, jwk, holder };
}

export async function createHaipServer(input?: {
	haip?: HaipOptions;
	oidc4vci?: Partial<Oidc4vciOptions>;
	oidc4vp?: Partial<Oidc4vpOptions>;
}) {
	let fetcher: typeof fetch | undefined;
	const authOptions = {
		baseURL: BASE_URL,
		plugins: [
			jwt({ jwt: { issuer: BASE_URL } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				enforcePerClientResources: false,
				resources: [AUTH_BASE_URL, CREDENTIAL_URL],
				grantTypes: ["authorization_code", "client_credentials", PRE_AUTH],
				requestUriResolver: createParResolver(),
				dpop: { signingAlgorithms: ["ES256"] },
				silenceWarnings: { oauthAuthServerConfig: true, openidConfig: true },
			}),
			oidc4vci({
				credentialConfigurations: [{ id: CONFIG_ID, vct: VCT }],
				...input?.oidc4vci,
			}),
			oidc4vp({
				expectedAudience: BASE_URL,
				allowedIssuers: [BASE_URL],
				resolveIssuerJwks: async () => {
					const res = await fetcher!(`${AUTH_BASE_URL}/jwks`);
					return ((await res.json()) as { keys: Record<string, unknown>[] })
						.keys;
				},
				statusListFetch: async (uri) => (await fetcher!(uri)).text(),
				...input?.oidc4vp,
			}),
			haip(input?.haip),
		],
	} satisfies BetterAuthOptions;

	const instance = await getTestInstance(authOptions);
	fetcher = instance.customFetchImpl as typeof fetch;
	const api = requireApi(instance.auth.api, [
		"adminCreateOAuthClient",
		"createCredentialOffer",
	] as const);

	async function createClient(
		headers: Headers,
		body: Record<string, unknown> = {},
	): Promise<{ client_id: string; client_secret?: string }> {
		return api.adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code", PRE_AUTH],
				skip_consent: true,
				...body,
			} as { redirect_uris: string[] },
		});
	}

	async function createOffer(headers: Headers, clientId: string) {
		const offer = await api.createCredentialOffer({
			headers,
			body: { client_id: clientId, credential_configuration_id: CONFIG_ID },
		});
		return offer.credential_offer.grants[PRE_AUTH][
			"pre-authorized_code"
		] as string;
	}

	async function postForm(
		url: string,
		form: Record<string, string>,
		headers?: Record<string, string>,
	) {
		return fetcher!(url, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				...headers,
			},
			body: new URLSearchParams(form).toString(),
		});
	}

	async function nonce() {
		const res = await fetcher!(`${AUTH_BASE_URL}/oidc4vci/nonce`, {
			method: "POST",
		});
		return ((await res.json()) as { c_nonce: string }).c_nonce;
	}

	/** Pre-authorized code redemption with an ES256 DPoP binding. */
	async function issueAccessToken() {
		const { headers } = await instance.signInWithTestUser();
		const client = await createClient(headers);
		const code = await createOffer(headers, client.client_id);
		const dpop = await createDpopKey();
		const res = await postForm(
			TOKEN_URL,
			{
				grant_type: PRE_AUTH,
				"pre-authorized_code": code,
				client_id: client.client_id,
			},
			{ dpop: await createDpopProof(dpop, { url: TOKEN_URL }) },
		);
		if (res.status !== 200) {
			throw new Error(
				`token endpoint failed: ${res.status} ${await res.text()}`,
			);
		}
		const tokens = (await res.json()) as { access_token: string };
		return { accessToken: tokens.access_token, dpop };
	}

	async function requestCredential(input: {
		accessToken: string;
		dpop?: DpopKey;
		body: Record<string, unknown>;
	}) {
		const headers = new Headers({
			authorization: `${input.dpop ? "DPoP" : "Bearer"} ${input.accessToken}`,
			"content-type": "application/json",
		});
		if (input.dpop) {
			headers.set(
				"dpop",
				await createDpopProof(input.dpop, {
					url: CREDENTIAL_URL,
					accessToken: input.accessToken,
				}),
			);
		}
		return fetcher!(CREDENTIAL_URL, {
			method: "POST",
			headers,
			body: JSON.stringify(input.body),
		});
	}

	/** Issues a credential through the HAIP profile (DPoP + ES256 proof). */
	async function issueCredential() {
		const { accessToken, dpop } = await issueAccessToken();
		const { proofJwt, holder } = await createJwtProof(await nonce());
		const res = await requestCredential({
			accessToken,
			dpop,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		if (res.status !== 200) {
			throw new Error(
				`credential endpoint failed: ${res.status} ${await res.text()}`,
			);
		}
		const body = (await res.json()) as {
			credentials: Array<{ credential: string }>;
		};
		return { credential: body.credentials[0]!.credential, holder };
	}

	return {
		auth: instance.auth as unknown as TestAuth,
		customFetchImpl: fetcher,
		signInWithTestUser: instance.signInWithTestUser,
		createClient,
		createOffer,
		postForm,
		nonce,
		issueAccessToken,
		requestCredential,
		issueCredential,
	};
}
