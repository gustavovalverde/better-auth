import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { generateRandomString } from "better-auth/crypto";
import {
	createAuthorizationCodeRequest,
	createAuthorizationURL,
} from "better-auth/oauth2";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { decodeJwt } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { haip } from "../src";

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
	const authServerBaseUrl = "http://localhost:3000";
	const rpBaseUrl = "http://localhost:5000";
	const credentialEndpoint = `${authServerBaseUrl}/api/auth/oidc4vci/credential`;
	const providerId = "test";
	const redirectUri = `${rpBaseUrl}/api/auth/oauth2/callback/${providerId}`;

	const authOptions = {
		baseURL: authServerBaseUrl,
		plugins: [
			jwt({ jwt: { issuer: authServerBaseUrl } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				validAudiences: [credentialEndpoint],
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
			haip(),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);

	const client = (await import("better-auth/client")).createAuthClient({
		plugins: [
			(await import("better-auth/client/plugins")).jwtClient(),
			(
				await import("@better-auth/oauth-provider/client")
			).oauthProviderClient(),
		],
		baseURL: authServerBaseUrl,
		fetchOptions: { customFetchImpl },
	});

	let oauthClient: { client_id: string; client_secret: string };
	let userHeaders: Headers;

	beforeAll(async () => {
		const { headers } = await signInWithTestUser();
		userHeaders = headers;

		const response = await auth.api.adminCreateOAuthClient!({
			headers,
			body: {
				redirect_uris: [redirectUri],
				skip_consent: true,
			},
		});
		oauthClient = response as typeof oauthClient;
	});

	async function authCodeFlow(params?: {
		additionalParams?: Record<string, string>;
		scopes?: string[];
		resource?: string;
	}) {
		const codeVerifier = generateRandomString(32);
		const authUrl = await createAuthorizationURL({
			id: providerId,
			options: {
				clientId: oauthClient.client_id,
				clientSecret: oauthClient.client_secret,
				redirectURI: redirectUri,
			},
			redirectURI: "",
			authorizationEndpoint: `${authServerBaseUrl}/api/auth/oauth2/authorize`,
			state: "test-state",
			scopes: params?.scopes ?? ["openid"],
			codeVerifier,
			additionalParams: params?.additionalParams,
		});

		let callbackUrl = "";
		await customFetchImpl(authUrl.toString(), {
			method: "GET",
			headers: userHeaders,
			redirect: "manual",
		}).then((res: Response) => {
			callbackUrl = res.headers.get("Location") || "";
		});

		const url = new URL(callbackUrl);
		const code = url.searchParams.get("code")!;

		const { body, headers } = createAuthorizationCodeRequest({
			code,
			codeVerifier,
			redirectURI: redirectUri,
			options: {
				clientId: oauthClient.client_id,
				clientSecret: oauthClient.client_secret,
				redirectURI: redirectUri,
			},
			resource: params?.resource,
		});

		const tokenRes = await client.$fetch<{
			access_token?: string;
			id_token?: string;
			token_type?: string;
			authorization_details?: unknown[];
			[key: string]: unknown;
		}>("/oauth2/token", {
			method: "POST",
			body,
			headers,
		});

		return tokenRes;
	}

	it("propagates authorization_details from auth code to token response", async () => {
		const authzDetails = [
			{
				type: "openid_credential",
				credential_configuration_id: "kyc_sdjwt_v1",
			},
		];

		const tokenRes = await authCodeFlow({
			additionalParams: {
				authorization_details: JSON.stringify(authzDetails),
			},
		});

		expect(tokenRes.data?.authorization_details).toEqual(authzDetails);
	});

	it("embeds authorization_details in JWT access token when resource is specified", async () => {
		const authzDetails = [
			{
				type: "openid_credential",
				credential_configuration_id: "kyc_sdjwt_v1",
			},
		];

		const tokenRes = await authCodeFlow({
			additionalParams: {
				authorization_details: JSON.stringify(authzDetails),
			},
			resource: credentialEndpoint,
		});

		expect(tokenRes.data?.authorization_details).toEqual(authzDetails);

		const accessToken = tokenRes.data?.access_token;
		expect(accessToken).toBeDefined();
		const payload = decodeJwt(accessToken!);
		expect(payload.authorization_details).toEqual(authzDetails);
	});

	it("omits authorization_details when not present in authorize request", async () => {
		const tokenRes = await authCodeFlow();

		expect(tokenRes.data?.authorization_details).toBeUndefined();
	});
});
