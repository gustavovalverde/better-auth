import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { generateRandomString } from "better-auth/crypto";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import {
	calculateJwkThumbprint,
	decodeJwt,
	exportJWK,
	generateKeyPair,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import {
	createDpopAccessTokenValidator,
	createDpopTokenBinding,
	haip,
} from "../src";
import { requireApi } from "./api-helpers";

describe("haip - DPoP token binding", async () => {
	const authServerBaseUrl = "http://localhost:3000";
	const credentialEndpoint = `${authServerBaseUrl}/api/auth/oidc4vci/credential`;

	// DPoP key pair (wallet device key)
	const dpopKp = await generateKeyPair("ES256");
	const dpopJwk = await exportJWK(dpopKp.publicKey);
	const dpopJkt = await calculateJwkThumbprint(dpopJwk);

	const authOptions = {
		baseURL: authServerBaseUrl,
		plugins: [
			jwt({ jwt: { issuer: authServerBaseUrl } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				validAudiences: [`${authServerBaseUrl}/api/auth`, credentialEndpoint],
				grantTypes: [
					"authorization_code",
					"urn:ietf:params:oauth:grant-type:pre-authorized_code",
				],
				tokenBinding: createDpopTokenBinding(),
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
				accessTokenValidator: createDpopAccessTokenValidator(),
			}),
			haip(),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);
	const { adminCreateOAuthClient, createCredentialOffer } = requireApi(
		auth.api,
		["adminCreateOAuthClient", "createCredentialOffer"] as const,
	);

	async function buildDpopProof(opts: {
		method: string;
		url: string;
		nonce?: string;
	}) {
		return new SignJWT({
			htm: opts.method,
			htu: opts.url,
			jti: generateRandomString(16),
			...(opts.nonce ? { nonce: opts.nonce } : {}),
		})
			.setProtectedHeader({
				alg: "ES256",
				typ: "dpop+jwt",
				jwk: dpopJwk,
			})
			.setIssuedAt()
			.sign(dpopKp.privateKey);
	}

	async function getTokensWithDpop() {
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

		const tokenUrl = `${authServerBaseUrl}/api/auth/oauth2/token`;
		const dpopProof = await buildDpopProof({
			method: "POST",
			url: tokenUrl,
		});

		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);
		form.set("client_id", walletClient.client_id);

		const tokenRes = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
				DPoP: dpopProof,
			}),
			body: form.toString(),
		});

		return {
			tokenRes,
			json: (await tokenRes.json()) as {
				access_token: string;
				token_type: string;
				c_nonce?: string;
			},
		};
	}

	it("returns token_type DPoP when DPoP proof header present", async () => {
		const { json } = await getTokensWithDpop();
		expect(json.token_type).toBe("DPoP");
	});

	it("embeds cnf.jkt in JWT access token", async () => {
		const { json } = await getTokensWithDpop();
		expect(json.access_token).toBeDefined();

		const payload = decodeJwt(json.access_token);
		expect((payload.cnf as any)?.jkt).toBe(dpopJkt);
	});

	it("returns DPoP-Nonce header", async () => {
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

		const tokenUrl = `${authServerBaseUrl}/api/auth/oauth2/token`;
		const dpopProof = await buildDpopProof({
			method: "POST",
			url: tokenUrl,
		});

		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);
		form.set("client_id", walletClient.client_id);

		const tokenRes = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
				DPoP: dpopProof,
			}),
			body: form.toString(),
		});

		expect(tokenRes.headers.get("DPoP-Nonce")).toBeTruthy();
	});

	it("credential endpoint validates DPoP binding", async () => {
		const { json } = await getTokensWithDpop();

		// Build a DPoP proof for the credential endpoint
		const credentialDpop = await buildDpopProof({
			method: "POST",
			url: credentialEndpoint,
		});

		const holderKp = await generateKeyPair("ES256");
		const holderJwk = await exportJWK(holderKp.publicKey);
		const proofJwt = await new SignJWT({ nonce: json.c_nonce })
			.setProtectedHeader({
				alg: "ES256",
				jwk: holderJwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holderKp.privateKey);

		const res = await customFetchImpl(credentialEndpoint, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/json",
				Authorization: `DPoP ${json.access_token}`,
				DPoP: credentialDpop,
			}),
			body: JSON.stringify({
				credential_configuration_id: "kyc_sdjwt_v1",
				proofs: { jwt: [proofJwt] },
			}),
		});

		expect(res.status).toBe(200);
	});

	it("credential endpoint rejects DPoP-bound token without DPoP header", async () => {
		const { json } = await getTokensWithDpop();

		const holderKp = await generateKeyPair("ES256");
		const holderJwk = await exportJWK(holderKp.publicKey);
		const proofJwt = await new SignJWT({ nonce: json.c_nonce })
			.setProtectedHeader({
				alg: "ES256",
				jwk: holderJwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holderKp.privateKey);

		// No DPoP header — should be rejected
		const res = await customFetchImpl(credentialEndpoint, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/json",
				Authorization: `DPoP ${json.access_token}`,
			}),
			body: JSON.stringify({
				credential_configuration_id: "kyc_sdjwt_v1",
				proofs: { jwt: [proofJwt] },
			}),
		});

		expect(res.status).toBeGreaterThanOrEqual(400);
	});
});
