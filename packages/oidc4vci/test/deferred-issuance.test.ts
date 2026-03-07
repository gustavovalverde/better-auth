import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { oidc4vci } from "../src";
import { requireApi } from "./api-helpers";

describe("oidc4vci - deferred issuance", async () => {
	const authServerBaseUrl = "http://localhost:3000";

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
				deferredIssuance: {
					shouldDefer: async () => true,
					intervalSeconds: 5,
					transactionExpiresInSeconds: 600,
				},
			}),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);
	const { adminCreateOAuthClient, createCredentialOffer, oauth2Token } =
		requireApi(
			auth.api,
			[
				"adminCreateOAuthClient",
				"createCredentialOffer",
				"oauth2Token",
			] as const,
			"Missing issuer APIs for oidc4vci tests.",
		);

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

		return { headers, user, walletClient, offer, preAuthorizedCode };
	}

	async function createProofJwt(input: { cNonce: string; audience: string }) {
		const holder = await generateKeyPair("EdDSA");
		const jwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: input.cNonce })
			.setProtectedHeader({ alg: "EdDSA", jwk, typ: "openid4vci-proof+jwt" })
			.setIssuedAt()
			.setAudience(input.audience)
			.sign(holder.privateKey);
		return { proofJwt, jwk };
	}

	it("exposes a deferred credential endpoint in metadata", async () => {
		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/.well-known/openid-credential-issuer`,
			{ method: "GET" },
		);
		expect(res.status).toBe(200);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.deferred_credential_endpoint).toBe(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential/deferred`,
		);
	});

	it("defers issuance and fulfills via transaction_id", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer();
		const tokens = await oauth2Token({
			body: {
				grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
				"pre-authorized_code": preAuthorizedCode,
				client_id: walletClient.client_id,
			},
		});

		expect(tokens.c_nonce).toBeDefined();
		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce!,
			audience: authServerBaseUrl,
		});

		const credentialRequestUrl = `${authServerBaseUrl}/api/auth/oidc4vci/credential`;
		const credentialRes = await customFetchImpl(credentialRequestUrl, {
			method: "POST",
			headers: new Headers({
				authorization: `Bearer ${tokens.access_token}`,
				"content-type": "application/json",
			}),
			body: JSON.stringify({
				credential_configuration_id: "kyc_sdjwt_v1",
				proofs: {
					jwt: [proofJwt],
				},
			}),
		});
		expect(credentialRes.status).toBe(202);
		const deferred = (await credentialRes.json()) as {
			transaction_id?: string;
			interval?: number;
		};
		expect(deferred.transaction_id).toBeTypeOf("string");
		expect(deferred.interval).toBe(5);

		const deferredUrl = `${authServerBaseUrl}/api/auth/oidc4vci/credential/deferred`;
		const deferredRes = await customFetchImpl(deferredUrl, {
			method: "POST",
			headers: new Headers({
				authorization: `Bearer ${tokens.access_token}`,
				"content-type": "application/json",
			}),
			body: JSON.stringify({
				transaction_id: deferred.transaction_id,
			}),
		});
		expect(deferredRes.status).toBe(200);
		const issued = (await deferredRes.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};
		expect(issued.credential).toBeTypeOf("string");
		expect(issued.credential.endsWith("~")).toBe(true);

		const deferredRes2 = await customFetchImpl(deferredUrl, {
			method: "POST",
			headers: new Headers({
				authorization: `Bearer ${tokens.access_token}`,
				"content-type": "application/json",
			}),
			body: JSON.stringify({
				transaction_id: deferred.transaction_id,
			}),
		});
		expect(deferredRes2.status).toBe(400);
		const errorBody = (await deferredRes2.json()) as { error?: string };
		expect(errorBody.error).toBe("invalid_transaction_id");
	});
});
