import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import {
	decodeProtectedHeader,
	exportJWK,
	generateKeyPair,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import { createX5cHeaders, haip } from "../src";
import { requireApi } from "./api-helpers";

const TEST_X5C_CHAIN = [
	"MIIBqTCCAU+gAwIBAgIUFakeLeafCert...",
	"MIIBtDCCAVqgAwIBAgIUFakeIntermediateCert...",
];

describe("haip - x5c credential headers", async () => {
	const authServerBaseUrl = "http://localhost:3000";

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
				resolveCredentialHeaders: createX5cHeaders(TEST_X5C_CHAIN),
			}),
			haip({ x5c: TEST_X5C_CHAIN }),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);
	const { adminCreateOAuthClient, createCredentialOffer } = requireApi(
		auth.api,
		["adminCreateOAuthClient", "createCredentialOffer"] as const,
		"Missing issuer APIs for x5c tests.",
	);

	async function issueCredential() {
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
		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);

		const tokenRes = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
			}),
			body: form.toString(),
		});

		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};

		const holder = await generateKeyPair("ES256");
		const jwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({
				alg: "ES256",
				jwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const credRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);

		return (await credRes.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};
	}

	it("includes x5c header in issued SD-JWT credential", async () => {
		const { credential } = await issueCredential();

		const sdJwtPart = credential.split("~")[0]!;
		const header = decodeProtectedHeader(sdJwtPart);

		expect(header.x5c).toEqual(TEST_X5C_CHAIN);
		expect(header.kid).toBeDefined();
		expect(header.typ).toBe("dc+sd-jwt");
	});

	it("includes x5c header in status list JWT", async () => {
		// Issue a credential first so the status list has entries
		await issueCredential();

		const statusRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/status-list`,
			{ method: "GET" },
		);

		expect(statusRes.status).toBe(200);
		const statusJwt = await statusRes.text();
		const header = decodeProtectedHeader(statusJwt);

		expect(header.x5c).toEqual(TEST_X5C_CHAIN);
		expect(header.typ).toBe("statuslist+jwt");
	});

	it("falls back to kid-only when resolveCredentialHeaders not configured", async () => {
		// Create a separate instance without resolveCredentialHeaders
		const {
			auth: authNoX5c,
			customFetchImpl: fetchNoX5c,
			signInWithTestUser: signInNoX5c,
		} = await getTestInstance({
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
					// No resolveCredentialHeaders
				}),
				haip(),
			],
		});

		const {
			adminCreateOAuthClient: createClient,
			createCredentialOffer: createOffer,
		} = requireApi(authNoX5c.api, [
			"adminCreateOAuthClient",
			"createCredentialOffer",
		] as const);

		const { headers, user } = await signInNoX5c();
		const walletClient = await createClient({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				skip_consent: true,
			},
		});
		const offer = await createOffer({
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

		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);

		const tokenRes = await fetchNoX5c(
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

		const holder = await generateKeyPair("ES256");
		const jwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({ alg: "ES256", jwk, typ: "openid4vci-proof+jwt" })
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const credRes = await fetchNoX5c(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);

		const { credential } = (await credRes.json()) as { credential: string };
		const header = decodeProtectedHeader(credential.split("~")[0]!);

		expect(header.x5c).toBeUndefined();
		expect(header.kid).toBeDefined();
	});
});
