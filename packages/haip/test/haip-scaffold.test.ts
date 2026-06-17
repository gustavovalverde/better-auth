import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { haip } from "../src";
import { requireApi } from "./api-helpers";

describe("haip - scaffold", () => {
	it("registers haip plugin alongside oauthProvider + oidc4vci + jwt", async () => {
		const { auth } = await getTestInstance({
			baseURL: "http://localhost:3000",
			plugins: [
				jwt({ jwt: { issuer: "http://localhost:3000" } }),
				oauthProvider({
					loginPage: "/login",
					consentPage: "/consent",
					silenceWarnings: {
						oauthAuthServerConfig: true,
						openidConfig: true,
					},
				}),
				oidc4vci({
					credentialConfigurations: [
						{ id: "test_v1", vct: "urn:example:test:v1" },
					],
				}),
				haip(),
			],
		});
		expect(auth).toBeDefined();
	});

	it("validates required peer plugins at init", async () => {
		await expect(
			getTestInstance({
				baseURL: "http://localhost:3000",
				plugins: [haip()],
			}),
		).rejects.toThrow('@better-auth/haip requires the "oauth-provider" plugin');
	});
});

describe("haip - authorization_details propagation", async () => {
	// 1.7 delivers RFC 9396 authorization_details through the OID4VCI
	// pre-authorized_code grant (the grant handler stamps it into both the token
	// response and the JWT access-token claims). Native oauth-provider no longer
	// round-trips authorization_details through the plain authorization_code flow,
	// so the haip stack is exercised through the path that actually carries it.
	const authServerBaseUrl = "http://localhost:3000";
	const credentialEndpoint = `${authServerBaseUrl}/api/auth/oidc4vci/credential`;
	const credentialConfigurationId = "kyc_sdjwt_v1";

	const authOptions = {
		baseURL: authServerBaseUrl,
		plugins: [
			jwt({ jwt: { issuer: authServerBaseUrl } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				enforcePerClientResources: false,
				resources: [credentialEndpoint],
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
					{ id: credentialConfigurationId, vct: "urn:example:kyc:v1" },
				],
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

	async function preAuthorizedFlow() {
		const { headers, user } = await signInWithTestUser();

		const walletClient = await adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				grant_types: [
					"authorization_code",
					"urn:ietf:params:oauth:grant-type:pre-authorized_code",
				],
				skip_consent: true,
			},
		});

		const offer = await createCredentialOffer({
			headers,
			body: {
				client_id: walletClient.client_id,
				userId: user.id,
				credential_configuration_id: credentialConfigurationId,
			},
		});

		const preAuthorizedCode = offer.credential_offer.grants[
			"urn:ietf:params:oauth:grant-type:pre-authorized_code"
		]?.["pre-authorized_code"] as string;

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

		return (await tokenRes.json()) as {
			access_token: string;
			authorization_details?: Array<{
				type: string;
				credential_configuration_id?: string;
				credential_identifiers?: string[];
			}>;
		};
	}

	it("propagates authorization_details from the grant to the token response", async () => {
		const json = await preAuthorizedFlow();

		expect(json.authorization_details).toBeDefined();
		const detail = json.authorization_details?.[0];
		expect(detail?.type).toBe("openid_credential");
		expect(detail?.credential_configuration_id).toBe(credentialConfigurationId);
		expect(detail?.credential_identifiers?.length).toBeGreaterThan(0);
	});

	it("embeds authorization_details in the JWT access token", async () => {
		const json = await preAuthorizedFlow();

		expect(json.access_token).toBeDefined();
		const payload = decodeJwt(json.access_token) as {
			authorization_details?: Array<{ type: string }>;
		};
		expect(payload.authorization_details?.[0]?.type).toBe("openid_credential");
		expect(payload.authorization_details).toEqual(json.authorization_details);
	});
});
