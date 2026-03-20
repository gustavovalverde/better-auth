import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import {
	calculateJwkThumbprint,
	createLocalJWKSet,
	exportJWK,
	generateKeyPair,
	jwtVerify,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import { oidc4vci } from "../src";
import { requireApi } from "./api-helpers";

describe("oidc4vci - end-to-end issuer flow", async () => {
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
	const { adminCreateOAuthClient, createCredentialOffer, getJwks } = requireApi(
		auth.api,
		["adminCreateOAuthClient", "createCredentialOffer", "getJwks"] as const,
		"Missing issuer APIs for oidc4vci tests.",
	);

	it("issues a bound SD-JWT VC and verifies signature + cnf.jkt", async () => {
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

		const tokenUrl = `${authServerBaseUrl}/api/auth/oauth2/token`;
		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set(
			"pre-authorized_code",
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"],
		);
		form.set("client_id", walletClient.client_id);

		const tokenRes = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
			}),
			body: form.toString(),
		});
		if (tokenRes.status !== 200) {
			throw new Error(
				`token endpoint failed: ${tokenRes.status} ${await tokenRes.text()}`,
			);
		}
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
			authorization_details?: Array<{
				credential_identifiers?: string[];
			}>;
		};

		const credentialIdentifier =
			tokens.authorization_details?.[0]?.credential_identifiers?.[0];
		expect(credentialIdentifier).toBeTypeOf("string");

		const holder = await generateKeyPair("EdDSA");
		const holderJwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({
				alg: "EdDSA",
				jwk: holderJwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const credentialRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					authorization: `Bearer ${tokens.access_token}`,
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_identifier: credentialIdentifier,
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		if (credentialRes.status !== 200) {
			throw new Error(
				`credential endpoint failed: ${credentialRes.status} ${await credentialRes.text()}`,
			);
		}
		const credentialPayload = (await credentialRes.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};
		const credential = credentialPayload.credential;
		expect(credential).toBeTypeOf("string");
		if (!credential) {
			throw new Error("credential missing from response");
		}

		const [sdJwt] = credential.split("~");
		if (!sdJwt) {
			throw new Error("SD-JWT missing from credential");
		}
		const jwks = await getJwks({});
		const issuerKeySet = createLocalJWKSet(jwks);
		const verified = await jwtVerify(sdJwt, issuerKeySet, {
			issuer: authServerBaseUrl,
		});
		expect(verified.payload.sub).toBe(user.id);
		expect(verified.payload.vct).toBe("urn:example:kyc:v1");

		const expectedJkt = await calculateJwkThumbprint(holderJwk);
		const cnf = verified.payload.cnf as { jkt?: string } | undefined;
		expect(cnf?.jkt).toBe(expectedJkt);
	});

	it("rejects reuse of c_nonce in a second credential request", async () => {
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

		const tokenUrl = `${authServerBaseUrl}/api/auth/oauth2/token`;
		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set(
			"pre-authorized_code",
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"],
		);
		form.set("client_id", walletClient.client_id);

		const tokenRes = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
			}),
			body: form.toString(),
		});
		if (tokenRes.status !== 200) {
			throw new Error(
				`token endpoint failed: ${tokenRes.status} ${await tokenRes.text()}`,
			);
		}
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
			authorization_details?: Array<{
				credential_identifiers?: string[];
			}>;
		};

		const credentialIdentifier =
			tokens.authorization_details?.[0]?.credential_identifiers?.[0];
		expect(credentialIdentifier).toBeTypeOf("string");

		const holder = await generateKeyPair("EdDSA");
		const holderJwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({
				alg: "EdDSA",
				jwk: holderJwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const credentialUrl = `${authServerBaseUrl}/api/auth/oidc4vci/credential`;
		const firstRes = await customFetchImpl(credentialUrl, {
			method: "POST",
			headers: new Headers({
				authorization: `Bearer ${tokens.access_token}`,
				"content-type": "application/json",
			}),
			body: JSON.stringify({
				access_token: tokens.access_token,
				credential_identifier: credentialIdentifier,
				proofs: { jwt: [proofJwt] },
			}),
		});
		if (firstRes.status !== 200) {
			throw new Error(
				`credential endpoint failed: ${firstRes.status} ${await firstRes.text()}`,
			);
		}

		const secondRes = await customFetchImpl(credentialUrl, {
			method: "POST",
			headers: new Headers({
				authorization: `Bearer ${tokens.access_token}`,
				"content-type": "application/json",
			}),
			body: JSON.stringify({
				access_token: tokens.access_token,
				credential_configuration_id: "kyc_sdjwt_v1",
				proofs: { jwt: [proofJwt] },
			}),
		});
		expect(secondRes.status).toBe(400);
		const error = (await secondRes.json()) as { error?: string };
		expect(error.error).toBe("invalid_nonce");
	});

	it("rejects an invalid proof JWT", async () => {
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

		const tokenUrl = `${authServerBaseUrl}/api/auth/oauth2/token`;
		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set(
			"pre-authorized_code",
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"],
		);
		form.set("client_id", walletClient.client_id);

		const tokenRes = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
			}),
			body: form.toString(),
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
					proof: {
						proof_type: "jwt",
						jwt: "not-a-jwt",
					},
				}),
			},
		);

		expect(credentialRes.status).toBe(400);
		const errorBody = (await credentialRes.json()) as {
			error?: string;
		};
		expect(errorBody.error).toBe("invalid_proof");
	});
});
