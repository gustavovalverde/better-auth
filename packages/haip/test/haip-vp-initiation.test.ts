import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { oidc4vp } from "@better-auth/oidc4vp";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { base64url, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import type { DcqlQuery } from "../src";
import { buildDcqlQuery, createDcqlMatcher, haip } from "../src";

async function createKbJwt(input: {
	credential: string;
	nonce: string;
	aud: string;
	holderKeyPair: CryptoKeyPair;
}): Promise<string> {
	const sdHash = base64url.encode(
		new Uint8Array(
			await crypto.subtle.digest(
				"SHA-256",
				new TextEncoder().encode(input.credential),
			),
		),
	);
	const jwk = await exportJWK(input.holderKeyPair.publicKey);
	return await new SignJWT({ nonce: input.nonce, sd_hash: sdHash })
		.setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt", jwk })
		.setIssuedAt()
		.setAudience(input.aud)
		.sign(input.holderKeyPair.privateKey);
}

describe("haip - VP initiation", async () => {
	const authServerBaseUrl = "http://localhost:3000";
	let fetcher: typeof fetch | null = null;

	const authOptions = {
		baseURL: authServerBaseUrl,
		plugins: [
			jwt({ jwt: { issuer: authServerBaseUrl } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				validAudiences: [
					`${authServerBaseUrl}/api/auth`,
					`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
				],
				grantTypes: [
					"authorization_code",
					"urn:ietf:params:oauth:grant-type:pre-authorized_code",
				],
				silenceWarnings: {
					oauthAuthServerConfig: true,
					openidConfig: true,
				},
			}),
			oidc4vci({
				allowAccessTokenInBody: true,
				credentialConfigurations: [
					{ id: "kyc_sdjwt_v1", vct: "urn:example:kyc:v1" },
				],
			}),
			oidc4vp({
				expectedAudience: authServerBaseUrl,
				allowedIssuers: [authServerBaseUrl],
				resolveIssuerJwks: async () => {
					if (!fetcher) throw new Error("fetcher not ready");
					const res = await fetcher(`${authServerBaseUrl}/api/auth/jwks`, {
						method: "GET",
					});
					const body = (await res.json()) as {
						keys?: Record<string, unknown>[];
					};
					return body.keys ?? [];
				},
				statusListFetch: async (uri) => {
					if (!fetcher) throw new Error("fetcher not ready");
					const res = await fetcher(uri, { method: "GET" });
					return await res.text();
				},
				presentationMatcher: createDcqlMatcher(),
			}),
			haip(),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);
	fetcher = customFetchImpl as typeof fetch;

	function resolveVpRequest(sessionId: string) {
		return customFetchImpl(`${authServerBaseUrl}/api/auth/haip/vp/resolve`, {
			method: "POST",
			headers: new Headers({ "content-type": "application/json" }),
			body: JSON.stringify({ session_id: sessionId }),
		});
	}

	async function issueCredential(): Promise<{
		credential: string;
		holderKeyPair: CryptoKeyPair;
	}> {
		const { headers, user } = await signInWithTestUser();

		const walletClient = (await auth.api.adminCreateOAuthClient!({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				skip_consent: true,
			},
		})) as { client_id: string };

		const offer = (await auth.api.createCredentialOffer!({
			headers,
			body: {
				client_id: walletClient.client_id,
				userId: user.id,
				credential_configuration_id: "kyc_sdjwt_v1",
			},
		})) as {
			credential_offer: {
				grants: Record<string, { "pre-authorized_code": string }>;
			};
		};

		const preAuthorizedCode =
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"];

		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);
		form.set("client_id", walletClient.client_id);

		const tokenRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oauth2/token`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/x-www-form-urlencoded",
				}),
				body: form.toString(),
			},
		);
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};

		const holderKeyPair = await generateKeyPair("EdDSA");
		const holderJwk = await exportJWK(holderKeyPair.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({
				alg: "EdDSA",
				jwk: holderJwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holderKeyPair.privateKey);

		const credentialRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					authorization: `Bearer ${tokens.access_token}`,
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		const credentialBody = (await credentialRes.json()) as {
			credential: string;
		};
		return { credential: credentialBody.credential, holderKeyPair };
	}

	it("creates a VP authorization request with DCQL query", async () => {
		const dcqlQuery = buildDcqlQuery([
			{
				id: "kyc_cred",
				format: "dc+sd-jwt",
				meta: { vct_values: ["urn:example:kyc:v1"] },
			},
		]);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/haip/vp/request`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					dcql_query: dcqlQuery,
					client_id: "verifier.example.com",
					client_id_scheme: "x509_san_dns",
					response_mode: "direct_post.jwt",
				}),
			},
		);

		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			request_uri?: string;
			session_id?: string;
			nonce?: string;
			state?: string;
			expires_in?: number;
		};

		expect(body.request_uri).toContain("/haip/vp/resolve");
		expect(body.session_id).toBeDefined();
		expect(body.nonce).toBeDefined();
		expect(body.state).toBeDefined();
		expect(body.expires_in).toBe(300);
	});

	it("resolves VP request by session_id", async () => {
		const dcqlQuery = buildDcqlQuery([
			{
				id: "kyc_cred",
				format: "dc+sd-jwt",
				meta: { vct_values: ["urn:example:kyc:v1"] },
			},
		]);

		const createRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/haip/vp/request`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					dcql_query: dcqlQuery,
					client_id: "verifier.example.com",
					client_id_scheme: "x509_san_dns",
				}),
			},
		);
		const { session_id, nonce, state } = (await createRes.json()) as {
			session_id: string;
			nonce: string;
			state: string;
		};

		const resolveRes = await resolveVpRequest(session_id);
		expect(resolveRes.status).toBe(200);

		const request = (await resolveRes.json()) as Record<string, unknown>;
		expect(request.response_type).toBe("vp_token");
		expect(request.response_uri).toContain("/oidc4vp/response");
		expect(request.nonce).toBe(nonce);
		expect(request.state).toBe(state);
		expect(request.client_id).toBe("verifier.example.com");
		expect(request.client_id_scheme).toBe("x509_san_dns");
		expect(request.dcql_query).toEqual(dcqlQuery);
	});

	it("end-to-end: initiate → present → verify", async () => {
		const { credential, holderKeyPair } = await issueCredential();

		// 1. Verifier creates VP request
		const dcqlQuery = buildDcqlQuery([
			{
				id: "kyc_cred",
				format: "dc+sd-jwt",
				meta: { vct_values: ["urn:example:kyc:v1"] },
			},
		]);

		const createRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/haip/vp/request`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({ dcql_query: dcqlQuery }),
			},
		);
		expect(createRes.status).toBe(200);
		const { session_id, state } = (await createRes.json()) as {
			session_id: string;
			state: string;
		};

		// 2. Wallet resolves the request
		const resolveRes = await resolveVpRequest(session_id);
		expect(resolveRes.status).toBe(200);
		const request = (await resolveRes.json()) as {
			nonce: string;
			dcql_query: DcqlQuery;
			response_uri: string;
		};

		// 3. Wallet creates VP with the request's nonce
		const kbJwt = await createKbJwt({
			credential,
			nonce: request.nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${credential}${kbJwt}`;

		// 4. Wallet submits VP to response_uri
		const vpRes = await customFetchImpl(request.response_uri, {
			method: "POST",
			headers: new Headers({ "content-type": "application/json" }),
			body: JSON.stringify({
				vp_token: vpToken,
				nonce: request.nonce,
				state,
				dcql_query: request.dcql_query,
			}),
		});

		expect(vpRes.status).toBe(200);
		const result = (await vpRes.json()) as {
			verified?: boolean;
			state?: string;
			presentations?: Array<{ issuer?: string }>;
		};
		expect(result.verified).toBe(true);
		expect(result.state).toBe(state);
		expect(result.presentations?.[0]?.issuer).toBe(authServerBaseUrl);
	});

	it("rejects resolve for non-existent session", async () => {
		const res = await resolveVpRequest("nonexistent");

		expect(res.status).toBe(400);
		const body = (await res.json()) as { error_description?: string };
		expect(body.error_description).toContain("not found or expired");
	});
});
