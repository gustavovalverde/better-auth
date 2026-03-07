import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { base64url, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { oidc4vp } from "../src";
import { requireApi } from "./api-helpers";

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

async function createProofJwt(input: {
	cNonce: string;
	audience: string;
}): Promise<{ proofJwt: string; holderKeyPair: CryptoKeyPair }> {
	const holderKeyPair = await generateKeyPair("EdDSA");
	const jwk = await exportJWK(holderKeyPair.publicKey);
	const proofJwt = await new SignJWT({ nonce: input.cNonce })
		.setProtectedHeader({ alg: "EdDSA", jwk, typ: "openid4vci-proof+jwt" })
		.setIssuedAt()
		.setAudience(input.audience)
		.sign(holderKeyPair.privateKey);
	return { proofJwt, holderKeyPair };
}

describe("oidc4vp - presentation verification", async () => {
	const authServerBaseUrl = "http://localhost:3000";
	let fetcher: typeof fetch | null = null;

	const authOptions = {
		baseURL: authServerBaseUrl,
		plugins: [
			jwt({
				jwt: {
					issuer: authServerBaseUrl,
				},
			}),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				validAudiences: [
					`${authServerBaseUrl}/api/auth`,
					`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
				],
				grantTypes: [
					"authorization_code",
					"client_credentials",
					"refresh_token",
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
					{
						id: "kyc_sdjwt_v1",
						vct: "urn:example:kyc:v1",
					},
				],
			}),
			oidc4vp({
				expectedAudience: authServerBaseUrl,
				allowedIssuers: [authServerBaseUrl],
				resolveIssuerJwks: async () => {
					if (!fetcher) {
						throw new Error("fetcher not ready");
					}
					const res = await fetcher(`${authServerBaseUrl}/api/auth/jwks`, {
						method: "GET",
					});
					const body = (await res.json()) as {
						keys?: Record<string, unknown>[];
					};
					return body.keys ?? [];
				},
				statusListFetch: async (uri) => {
					if (!fetcher) {
						throw new Error("fetcher not ready");
					}
					const res = await fetcher(uri, { method: "GET" });
					return await res.text();
				},
			}),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);
	const { adminCreateOAuthClient, createCredentialOffer } = requireApi(
		auth.api,
		["adminCreateOAuthClient", "createCredentialOffer"] as const,
		"Missing issuer APIs for oidc4vp tests.",
	);

	fetcher = customFetchImpl as typeof fetch;

	async function createOffer() {
		const { headers, user } = await signInWithTestUser();

		const walletClient = await adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				skip_consent: true,
			},
		});

		const offer = await createCredentialOffer({
			headers,
			body: {
				client_id: walletClient.client_id,
				userId: user.id,
				credential_configuration_id: "kyc_sdjwt_v1",
			},
		});

		const preAuthorizedCode =
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"];

		return { walletClient, preAuthorizedCode };
	}

	async function tokenWithFormUrlEncoded(input: {
		preAuthorizedCode: string;
		clientId?: string;
	}) {
		const tokenUrl = `${authServerBaseUrl}/api/auth/oauth2/token`;
		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", input.preAuthorizedCode);
		if (input.clientId) form.set("client_id", input.clientId);

		return await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
			}),
			body: form.toString(),
		});
	}

	async function issueCredential(): Promise<{
		credential: string;
		holderKeyPair: CryptoKeyPair;
	}> {
		const { preAuthorizedCode, walletClient } = await createOffer();
		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		if (tokenRes.status !== 200) {
			throw new Error(
				`token endpoint failed: ${tokenRes.status} ${await tokenRes.text()}`,
			);
		}
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};
		const { proofJwt, holderKeyPair } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});
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
		if (credentialRes.status !== 200) {
			throw new Error(
				`credential endpoint failed: ${credentialRes.status} ${await credentialRes.text()}`,
			);
		}
		const credentialBody = (await credentialRes.json()) as {
			credential: string;
		};
		if (!credentialBody.credential) {
			throw new Error("credential missing");
		}
		return {
			credential: credentialBody.credential,
			holderKeyPair,
		};
	}

	it("verifies an SD-JWT presentation", async () => {
		const { credential, holderKeyPair } = await issueCredential();
		const nonce = "test-nonce-verify";
		const kbJwt = await createKbJwt({
			credential,
			nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${credential}${kbJwt}`;

		const verifyRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/verify`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/json",
				}),
				body: JSON.stringify({ vp_token: vpToken, nonce }),
			},
		);

		expect(verifyRes.status).toBe(200);
		const body = (await verifyRes.json()) as {
			verified?: boolean;
			presentations?: Array<{
				issuer?: string;
				status?: number;
				claims?: Record<string, unknown>;
			}>;
		};
		expect(body.verified).toBe(true);
		expect(body.presentations?.length).toBe(1);
		expect(body.presentations?.[0]?.issuer).toBe(authServerBaseUrl);
		expect(body.presentations?.[0]?.status).toBe(0);
		expect(body.presentations?.[0]?.claims).toBeTypeOf("object");
	});

	it("verifies a direct_post presentation response", async () => {
		const { credential, holderKeyPair } = await issueCredential();
		const nonce = "test-nonce-response";
		const kbJwt = await createKbJwt({
			credential,
			nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${credential}${kbJwt}`;

		const form = new URLSearchParams();
		form.set("vp_token", vpToken);
		form.set("nonce", nonce);
		form.set("state", "state-123");

		const responseRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/response`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/x-www-form-urlencoded",
				}),
				body: form.toString(),
			},
		);

		expect(responseRes.status).toBe(200);
		const body = (await responseRes.json()) as {
			verified?: boolean;
			state?: string;
			presentations?: Array<{ issuer?: string }>;
		};
		expect(body.verified).toBe(true);
		expect(body.state).toBe("state-123");
		expect(body.presentations?.[0]?.issuer).toBe(authServerBaseUrl);
	});

	it("rejects a tampered presentation", async () => {
		const { credential, holderKeyPair } = await issueCredential();
		const nonce = "test-nonce-tampered";

		const [credJwt, ...rest] = credential.split("~");
		if (!credJwt) {
			throw new Error("credential missing jwt");
		}
		// Flip a character well before the end to avoid base64url padding-bit ambiguity
		const pos = credJwt.length - 10;
		const ch = credJwt[pos] === "A" ? "B" : "A";
		const tamperedJwt = `${credJwt.slice(0, pos)}${ch}${credJwt.slice(pos + 1)}`;
		const tamperedCredential = [tamperedJwt, ...rest].join("~");

		const kbJwt = await createKbJwt({
			credential: tamperedCredential,
			nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${tamperedCredential}${kbJwt}`;

		const verifyRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/verify`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/json",
				}),
				body: JSON.stringify({ vp_token: vpToken, nonce }),
			},
		);

		expect(verifyRes.status).toBe(400);
		const body = (await verifyRes.json()) as {
			verified?: boolean;
			errors?: Array<{ index: number; message?: string }>;
		};
		expect(body.verified).toBe(false);
		expect(body.errors?.length).toBe(1);
	});
});
