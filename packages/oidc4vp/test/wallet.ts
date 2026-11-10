import type { AuthContext, BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { base64url, exportJWK, generateKeyPair, SignJWT } from "jose";
import type { Oidc4vpAuthorizationRequest, Oidc4vpOptions } from "../src";
import { oidc4vp } from "../src";
import { requireApi } from "./api-helpers";

export const BASE_URL = "http://localhost:3000";
const AUTH_BASE_URL = `${BASE_URL}/api/auth`;
const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const CONFIG_ID = "kyc_sdjwt_v1";
export const VCT = "urn:example:kyc:v1";

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;

/** The test auth instance, typed loosely so the helper stays portable. */
export type TestAuth = {
	api: Record<"getJwks", (input?: any) => Promise<any>>;
	$context: Promise<AuthContext>;
};

export async function createKbJwt(input: {
	credential: string;
	nonce: string;
	aud: string;
	holder: KeyPair;
	iat?: number;
}) {
	const sdHash = base64url.encode(
		new Uint8Array(
			await crypto.subtle.digest(
				"SHA-256",
				new TextEncoder().encode(input.credential),
			),
		),
	);
	return new SignJWT({ nonce: input.nonce, sd_hash: sdHash })
		.setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
		.setIssuedAt(input.iat ?? Math.floor(Date.now() / 1000))
		.setAudience(input.aud)
		.sign(input.holder.privateKey);
}

/**
 * A Better Auth instance that issues SD-JWT VCs (oidc4vci) and verifies their
 * presentations (oidc4vp), with an in-memory authorization request store.
 */
export async function createVerifier(overrides?: Partial<Oidc4vpOptions>) {
	let fetcher: typeof fetch | undefined;
	const requests = new Map<string, Oidc4vpAuthorizationRequest>();
	const authOptions = {
		baseURL: BASE_URL,
		plugins: [
			jwt({ jwt: { issuer: BASE_URL } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				enforcePerClientResources: false,
				resources: [AUTH_BASE_URL, `${AUTH_BASE_URL}/oidc4vci/credential`],
				grantTypes: ["authorization_code", PRE_AUTH],
				silenceWarnings: { oauthAuthServerConfig: true, openidConfig: true },
			}),
			oidc4vci({
				credentialConfigurations: [{ id: CONFIG_ID, vct: VCT }],
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
				resolveAuthorizationRequest: ({ state }) => requests.get(state) ?? null,
				...overrides,
			}),
		],
	} satisfies BetterAuthOptions;

	const instance = await getTestInstance(authOptions);
	fetcher = instance.customFetchImpl as typeof fetch;
	const api = requireApi(instance.auth.api, [
		"adminCreateOAuthClient",
		"createCredentialOffer",
	] as const);

	async function issueCredential() {
		const { headers } = await instance.signInWithTestUser();
		const client = await api.adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				grant_types: [PRE_AUTH],
				skip_consent: true,
			},
		});
		const offer = await api.createCredentialOffer({
			headers,
			body: {
				client_id: client.client_id,
				credential_configuration_id: CONFIG_ID,
			},
		});
		const tokenRes = await fetcher!(`${AUTH_BASE_URL}/oauth2/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: PRE_AUTH,
				"pre-authorized_code":
					offer.credential_offer.grants[PRE_AUTH]["pre-authorized_code"],
				client_id: client.client_id,
			}).toString(),
		});
		const { access_token } = (await tokenRes.json()) as {
			access_token: string;
		};
		const nonceRes = await fetcher!(`${AUTH_BASE_URL}/oidc4vci/nonce`, {
			method: "POST",
		});
		const { c_nonce } = (await nonceRes.json()) as { c_nonce: string };
		const holder = await generateKeyPair("EdDSA");
		const proofJwt = await new SignJWT({ nonce: c_nonce })
			.setProtectedHeader({
				alg: "EdDSA",
				typ: "openid4vci-proof+jwt",
				jwk: await exportJWK(holder.publicKey),
			})
			.setIssuedAt()
			.setAudience(BASE_URL)
			.sign(holder.privateKey);
		const credentialRes = await fetcher!(
			`${AUTH_BASE_URL}/oidc4vci/credential`,
			{
				method: "POST",
				headers: {
					authorization: `Bearer ${access_token}`,
					"content-type": "application/json",
				},
				body: JSON.stringify({
					credential_configuration_id: CONFIG_ID,
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		const body = (await credentialRes.json()) as {
			credentials: Array<{ credential: string }>;
		};
		return { credential: body.credentials[0]!.credential, holder };
	}

	async function present(input: { nonce: string; aud?: string; iat?: number }) {
		const { credential, holder } = await issueCredential();
		return `${credential}${await createKbJwt({
			credential,
			holder,
			nonce: input.nonce,
			aud: input.aud ?? BASE_URL,
			iat: input.iat,
		})}`;
	}

	function registerRequest(request: Partial<Oidc4vpAuthorizationRequest> = {}) {
		const state = crypto.randomUUID();
		const authorizationRequest: Oidc4vpAuthorizationRequest = {
			response_type: "vp_token",
			response_mode: "direct_post",
			client_id: "x509_hash:verifier",
			nonce: crypto.randomUUID(),
			state,
			dcql_query: {
				credentials: [
					{ id: "kyc", format: "dc+sd-jwt", meta: { vct_values: [VCT] } },
				],
			},
			...request,
		};
		requests.set(authorizationRequest.state, authorizationRequest);
		return authorizationRequest;
	}

	async function post(path: string, body: Record<string, string>) {
		return fetcher!(`${AUTH_BASE_URL}${path}`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(body).toString(),
		});
	}

	async function verify(body: Record<string, unknown>) {
		return fetcher!(`${AUTH_BASE_URL}/oidc4vp/verify`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
	}

	return {
		auth: instance.auth as unknown as TestAuth,
		issueCredential,
		present,
		registerRequest,
		post,
		verify,
	};
}
