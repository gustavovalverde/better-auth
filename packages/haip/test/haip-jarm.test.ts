import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { oidc4vp } from "@better-auth/oidc4vp";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import {
	base64url,
	CompactEncrypt,
	exportJWK,
	generateKeyPair,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import { createJarmHandler, haip } from "../src";

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

describe("haip - JARM (direct_post.jwt)", async () => {
	const authServerBaseUrl = "http://localhost:3000";
	let fetcher: typeof fetch | null = null;

	// Generate an ECDH-ES key pair for JWE encryption/decryption
	const encKeyPair = await generateKeyPair("ECDH-ES", {
		crv: "P-256",
		extractable: true,
	});
	const decryptionJwk = await exportJWK(encKeyPair.privateKey);
	const encryptionJwk = await exportJWK(encKeyPair.publicKey);

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
				responseModeHandlers: {
					"direct_post.jwt": createJarmHandler({
						decryptionKey: decryptionJwk,
					}),
				},
			}),
			haip(),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);
	fetcher = customFetchImpl as typeof fetch;

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

	async function encryptPayload(
		payload: Record<string, unknown>,
	): Promise<string> {
		const publicKey = await (await import("jose")).importJWK(
			encryptionJwk,
			"ECDH-ES",
		);
		return await new CompactEncrypt(
			new TextEncoder().encode(JSON.stringify(payload)),
		)
			.setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
			.encrypt(publicKey);
	}

	it("accepts direct_post.jwt with JWE-encrypted response", async () => {
		const { credential, holderKeyPair } = await issueCredential();
		const nonce = "test-jarm-nonce";
		const kbJwt = await createKbJwt({
			credential,
			nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${credential}${kbJwt}`;

		const jwe = await encryptPayload({
			vp_token: vpToken,
			nonce,
			state: "jarm-state",
		});

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/response`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({ response: jwe }),
			},
		);

		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			verified?: boolean;
			state?: string;
			presentations?: Array<{ issuer?: string }>;
		};
		expect(body.verified).toBe(true);
		expect(body.state).toBe("jarm-state");
		expect(body.presentations?.[0]?.issuer).toBe(authServerBaseUrl);
	});

	it("rejects direct_post.jwt when no handler registered", async () => {
		// Create a separate instance without JARM handler
		const noJarmOptions = {
			baseURL: authServerBaseUrl,
			plugins: [
				jwt({ jwt: { issuer: authServerBaseUrl } }),
				oauthProvider({
					loginPage: "/login",
					consentPage: "/consent",
					grantTypes: ["authorization_code"],
					silenceWarnings: {
						oauthAuthServerConfig: true,
						openidConfig: true,
					},
				}),
				oidc4vci({
					credentialConfigurations: [
						{ id: "kyc_sdjwt_v1", vct: "urn:example:kyc:v1" },
					],
				}),
				oidc4vp({
					expectedAudience: authServerBaseUrl,
					resolveIssuerJwks: async () => [],
					// No responseModeHandlers
				}),
				haip(),
			],
		} satisfies BetterAuthOptions;

		const noJarmInstance = await getTestInstance(noJarmOptions);

		const res = await noJarmInstance.customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/response`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({ response: "some.jwt.token" }),
			},
		);

		expect(res.status).toBe(400);
		const body = (await res.json()) as {
			error?: string;
			error_description?: string;
		};
		expect(body.error).toBe("unsupported_response_type");
		expect(body.error_description).toContain("responseModeHandler");
	});

	it("uses A256GCM content encryption", async () => {
		const payload = { vp_token: "test", nonce: "n" };
		const jwe = await encryptPayload(payload);

		// JWE compact format: header.encryptedKey.iv.ciphertext.tag
		const [headerB64] = jwe.split(".");
		const header = JSON.parse(
			new TextDecoder().decode(base64url.decode(headerB64!)),
		);
		expect(header.alg).toBe("ECDH-ES");
		expect(header.enc).toBe("A256GCM");
	});
});
