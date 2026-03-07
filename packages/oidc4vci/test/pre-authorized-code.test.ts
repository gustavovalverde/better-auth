import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { createHash } from "@better-auth/utils/hash";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { oidc4vci } from "../src";
import { requireApi } from "./api-helpers";

describe("oidc4vci - pre-authorized code flow", async () => {
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

	it("issues an access token and a credential (consuming c_nonce)", async () => {
		const { headers, user } = await signInWithTestUser();
		const { internalAdapter } = await auth.$context;

		const walletClient = await adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				skip_consent: true,
			},
		});
		expect(walletClient.client_id).toBeDefined();

		const offer = await createCredentialOffer({
			headers,
			body: {
				client_id: walletClient.client_id,
				userId: user.id,
				credential_configuration_id: "kyc_sdjwt_v1",
			},
		});

		expect(offer.offer_id).toBeDefined();
		expect(offer.credential_offer).toBeDefined();
		expect(
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"],
		).toBeDefined();

		const preAuthorizedCode =
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"];

		const preAuthorizedIdentifier = await createHash(
			"SHA-256",
			"base64urlnopad",
		).digest(preAuthorizedCode);
		const stored = await internalAdapter.findVerificationValue(
			preAuthorizedIdentifier,
		);
		expect(stored?.identifier).toBe(preAuthorizedIdentifier);

		const tokens = await oauth2Token({
			body: {
				grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
				"pre-authorized_code": preAuthorizedCode,
			},
		});

		expect(tokens.access_token).toBeDefined();
		expect(tokens.c_nonce).toBeDefined();
		expect(tokens.c_nonce_expires_in).toBeTypeOf("number");

		const holder = await generateKeyPair("EdDSA");
		const jwk = await exportJWK(holder.publicKey);
		const now = Math.floor(Date.now() / 1000);
		const proofJwt = await new SignJWT({
			nonce: tokens.c_nonce,
		})
			.setProtectedHeader({ alg: "EdDSA", jwk, typ: "openid4vci-proof+jwt" })
			.setIssuedAt(now)
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const credentialRequestUrl = `${authServerBaseUrl}/api/auth/oidc4vci/credential`;
		const credentialRes = await customFetchImpl(credentialRequestUrl, {
			method: "POST",
			headers: new Headers({
				authorization: `Bearer ${tokens.access_token}`,
				"content-type": "application/json",
			}),
			body: JSON.stringify({
				access_token: tokens.access_token,
				credential_configuration_id: "kyc_sdjwt_v1",
				proofs: {
					jwt: [proofJwt],
				},
			}),
		});
		if (credentialRes.status !== 200) {
			throw new Error(
				`credential endpoint failed: ${credentialRes.status} ${await credentialRes.text()}`,
			);
		}
		const credential = (await credentialRes.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};

		expect(credential.credential).toBeTypeOf("string");
		expect(credential.credential.endsWith("~")).toBe(true);
		const [credentialJwt, ...disclosures] = credential.credential.split("~");
		const decodedDisclosures = disclosures
			.filter(Boolean)
			.map((entry) =>
				JSON.parse(Buffer.from(entry, "base64url").toString("utf8")),
			) as Array<[string, string, unknown]>;
		const disclosureKeys = decodedDisclosures.map((entry) => entry[1]);
		expect(disclosureKeys).toContain("email");
		const emailDisclosure = decodedDisclosures.find(
			(entry) => entry[1] === "email",
		);
		expect(emailDisclosure?.[2]).toBe(user.email);
		expect(decodeJwt(credentialJwt!).email).toBeUndefined();

		// Reuse of c_nonce must fail (one-time)
		const credentialRes2 = await customFetchImpl(credentialRequestUrl, {
			method: "POST",
			headers: new Headers({
				authorization: `Bearer ${tokens.access_token}`,
				"content-type": "application/json",
			}),
			body: JSON.stringify({
				access_token: tokens.access_token,
				credential_configuration_id: "kyc_sdjwt_v1",
				proofs: {
					jwt: [proofJwt],
				},
			}),
		});
		expect(credentialRes2.status).toBe(400);
	});

	it("requires tx_code when the offer included it", async () => {
		const { headers, user } = await signInWithTestUser();
		const { internalAdapter } = await auth.$context;

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
				tx_code: "123456",
			},
		});

		const preAuthorizedCode =
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"];

		const preAuthorizedIdentifier = await createHash(
			"SHA-256",
			"base64urlnopad",
		).digest(preAuthorizedCode);
		const stored = await internalAdapter.findVerificationValue(
			preAuthorizedIdentifier,
		);
		expect(stored?.identifier).toBe(preAuthorizedIdentifier);

		await expect(
			oauth2Token({
				body: {
					grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
					"pre-authorized_code": preAuthorizedCode,
				},
			}),
		).rejects.toBeDefined();

		const tokens = await oauth2Token({
			body: {
				grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
				"pre-authorized_code": preAuthorizedCode,
				tx_code: "123456",
			},
		});
		expect(tokens.access_token).toBeDefined();
	});
});
