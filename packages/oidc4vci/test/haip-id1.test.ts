import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
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
import { oidc4vci } from "../src";
import { requireApi } from "./api-helpers";

describe("oidc4vci - HAIP ID1 inspired checks (subset)", async () => {
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

	async function setupTokens() {
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

		const tokens = await oauth2Token({
			body: {
				grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
				"pre-authorized_code": preAuthorizedCode,
			},
		});

		return { tokens };
	}

	it("requires proof.jwt typ=openid4vci-proof+jwt", async () => {
		const { tokens } = await setupTokens();

		const holder = await generateKeyPair("EdDSA");
		const jwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({ alg: "EdDSA", jwk })
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
	});

	it("rejects HS* proof algs", async () => {
		const { tokens } = await setupTokens();

		const secret = crypto.getRandomValues(new Uint8Array(32));
		const jwk = {
			kty: "oct",
			k: Buffer.from(secret).toString("base64url"),
		};
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({ alg: "HS256", jwk, typ: "openid4vci-proof+jwt" })
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(secret);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
	});

	it("requires proof iat", async () => {
		const { tokens } = await setupTokens();

		const holder = await generateKeyPair("EdDSA");
		const jwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({ alg: "EdDSA", jwk, typ: "openid4vci-proof+jwt" })
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
	});

	it("supports ES256 proof (common HAIP suite)", async () => {
		const { tokens } = await setupTokens();

		const holder = await generateKeyPair("ES256");
		const jwk = await exportJWK(holder.publicKey);
		const expectedJkt = await calculateJwkThumbprint(jwk);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({ alg: "ES256", jwk, typ: "openid4vci-proof+jwt" })
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(200);
		const json = (await res.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};

		const credentialJwt = json.credential.split("~")[0]!;
		const payload = decodeJwt(credentialJwt);
		expect(payload.cnf).toEqual({ jkt: expectedJkt });
	});

	it.todo("HAIP ID1: PAR + authorization_code flow");
	it.todo("HAIP ID1: DPoP sender-constrained access tokens");
});
