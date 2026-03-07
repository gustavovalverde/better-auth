import { createHash } from "node:crypto";
import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { createAuthClient } from "better-auth/client";
import { generateRandomString } from "better-auth/crypto";
import {
	createAuthorizationCodeRequest,
	createAuthorizationURL,
} from "better-auth/oauth2";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { decodeJwt } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { oidc4ida } from "../src";
import { requireApi } from "./api-helpers";

type MakeRequired<T, K extends keyof T> = Omit<T, K> & Required<Pick<T, K>>;

type TokenResponse = {
	access_token?: string;
	id_token?: string;
	refresh_token?: string;
	expires_in?: number;
	expires_at?: number;
	token_type?: string;
	scope?: string;
	[key: string]: unknown;
};

describe("oidc4ida verified_claims", async () => {
	const authServerBaseUrl = "http://localhost:3000";
	const rpBaseUrl = "http://localhost:5000";
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
				silenceWarnings: {
					oauthAuthServerConfig: true,
					openidConfig: true,
				},
			}),
			oidc4ida({
				metadata: {
					trust_frameworks_supported: ["example"],
					claims_in_verified_claims_supported: ["given_name", "family_name"],
					evidence_supported: ["document"],
					documents_supported: ["idcard"],
					documents_methods_supported: ["pipp"],
					document_check_methods_supported: ["pipp"],
					documents_validation_methods_supported: ["pipp"],
				},
			}),
		],
	} satisfies BetterAuthOptions;

	const { auth, signInWithTestUser, customFetchImpl } =
		await getTestInstance(authOptions);
	const { adminCreateOAuthClient, setVerifiedClaims } = requireApi(
		auth.api,
		["adminCreateOAuthClient", "setVerifiedClaims"] as const,
		"Missing issuer APIs for oidc4ida tests.",
	);

	const { headers, user } = await signInWithTestUser();
	const client = createAuthClient({
		plugins: [oauthProviderClient()],
		baseURL: authServerBaseUrl,
		fetchOptions: {
			customFetchImpl,
			headers,
		},
	});

	let oauthClient: { client_id: string; client_secret?: string } | null = null;
	const providerId = "test";
	const redirectUri = `${rpBaseUrl}/api/auth/oauth2/callback/${providerId}`;
	const state = "123";

	const verifiedClaims = {
		verification: {
			trust_framework: "example",
			time: "2024-01-01T00:00:00Z",
		},
		claims: {
			given_name: "Test",
			family_name: "User",
		},
	};

	async function createAuthUrl(
		overrides?: Partial<Parameters<typeof createAuthorizationURL>[0]>,
	) {
		if (!oauthClient?.client_id || !oauthClient?.client_secret) {
			throw new Error("beforeAll not run properly");
		}
		const codeVerifier = generateRandomString(32);
		const url = await createAuthorizationURL({
			id: providerId,
			options: {
				clientId: oauthClient.client_id,
				clientSecret: oauthClient.client_secret,
				redirectURI: redirectUri,
			},
			redirectURI: "",
			authorizationEndpoint: `${authServerBaseUrl}/api/auth/oauth2/authorize`,
			state,
			scopes: ["openid", "profile", "email"],
			codeVerifier,
			...overrides,
		});
		return { url, codeVerifier };
	}

	async function getAuthCode(
		overrides?: Partial<Parameters<typeof createAuthorizationURL>[0]>,
	) {
		const { url: authUrl, codeVerifier } = await createAuthUrl(overrides);
		let callbackRedirectUrl = "";
		await client.$fetch(authUrl.toString(), {
			onError(context) {
				callbackRedirectUrl = context.response.headers.get("Location") || "";
			},
		});
		const url = new URL(callbackRedirectUrl);
		const code = url.searchParams.get("code");
		if (!code) {
			throw new Error("authorization code not returned");
		}
		return { code, codeVerifier };
	}

	async function validateAuthCode(
		overrides: MakeRequired<
			Partial<Parameters<typeof createAuthorizationCodeRequest>[0]>,
			"code"
		>,
	) {
		if (!oauthClient?.client_id || !oauthClient?.client_secret) {
			throw new Error("beforeAll not run properly");
		}
		const { body, headers } = createAuthorizationCodeRequest({
			...overrides,
			redirectURI: redirectUri,
			options: {
				clientId: oauthClient.client_id,
				clientSecret: oauthClient.client_secret,
				redirectURI: redirectUri,
			},
		});
		return client.$fetch<TokenResponse>("/oauth2/token", {
			method: "POST",
			body,
			headers,
		});
	}

	async function getTokens(
		overrides?: Partial<Parameters<typeof createAuthorizationURL>[0]>,
	) {
		const { code, codeVerifier } = await getAuthCode(overrides);
		return validateAuthCode({
			code,
			codeVerifier,
		});
	}

	beforeAll(async () => {
		const response = await adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: [redirectUri],
				skip_consent: true,
			},
		});
		expect(response?.client_id).toBeDefined();
		expect(response?.client_secret).toBeDefined();
		oauthClient = response;

		await setVerifiedClaims({
			headers,
			body: {
				user_id: user.id,
				verified_claims: verifiedClaims,
			},
		});
	});

	it("adds OIDC4IDA metadata to openid-configuration", async () => {
		const result = await auth.api.getOpenIdConfig({});
		// After hook wraps response in { response: {...} }
		const json = ("response" in result ? result.response : result) as Record<
			string,
			unknown
		>;
		expect(json.verified_claims_supported).toBe(true);
		expect(json.claims_parameter_supported).toBe(true);
		expect(json.trust_frameworks_supported).toEqual(["example"]);
	});

	it("omits verified_claims when claims parameter is absent", async () => {
		const tokensResult = await getTokens();
		const tokens = (
			tokensResult.data && "response" in tokensResult.data
				? tokensResult.data.response
				: tokensResult.data
		) as TokenResponse;
		expect(tokens?.access_token).toBeDefined();
		expect(tokens?.id_token).toBeDefined();

		// id_token should NOT contain verified_claims
		const idTokenPayload = decodeJwt(tokens?.id_token ?? "");
		expect(idTokenPayload.verified_claims).toBeUndefined();

		// userinfo should NOT contain verified_claims
		const userinfoResult = await client.$fetch<Record<string, unknown>>(
			"/oauth2/userinfo",
			{
				headers: {
					authorization: tokens?.access_token ?? "",
				},
			},
		);
		const userinfo = (
			userinfoResult.data && "response" in userinfoResult.data
				? userinfoResult.data.response
				: userinfoResult.data
		) as Record<string, unknown>;
		expect(userinfo?.verified_claims).toBeUndefined();
	});

	it("includes verified_claims when requested via claims parameter", async () => {
		const claimsParam = {
			id_token: {
				verified_claims: {
					verification: {
						trust_framework: null,
						time: null,
					},
					claims: {
						given_name: null,
						family_name: null,
					},
				},
			},
			userinfo: {
				verified_claims: {
					verification: {
						trust_framework: null,
						time: null,
					},
					claims: {
						given_name: null,
						family_name: null,
					},
				},
			},
		};

		const tokensResult = await getTokens({
			additionalParams: {
				claims: JSON.stringify(claimsParam),
			},
		});
		const tokens = (
			tokensResult.data && "response" in tokensResult.data
				? tokensResult.data.response
				: tokensResult.data
		) as TokenResponse;
		expect(tokens?.id_token).toBeDefined();

		const normalizeVerifiedClaims = (input: Record<string, unknown>) => {
			const verification = input.verification as
				| Record<string, unknown>
				| undefined;
			const time = verification?.time;
			let normalizedTime: unknown;
			if (typeof time === "string") {
				normalizedTime = new Date(time).toISOString();
			} else if (time instanceof Date) {
				normalizedTime = time.toISOString();
			} else {
				normalizedTime = time;
			}
			return {
				...input,
				verification: verification
					? {
							...verification,
							time: normalizedTime,
						}
					: verification,
			};
		};

		const normalizedVerifiedClaims = normalizeVerifiedClaims(
			verifiedClaims as Record<string, unknown>,
		);

		// id_token should contain all verified_claims
		const idTokenPayload = decodeJwt(tokens?.id_token ?? "");
		expect(
			normalizeVerifiedClaims(
				idTokenPayload.verified_claims as Record<string, unknown>,
			),
		).toEqual(normalizedVerifiedClaims);

		// userinfo should contain all verified_claims
		const userinfoResult = await client.$fetch<Record<string, unknown>>(
			"/oauth2/userinfo",
			{
				headers: {
					authorization: tokens?.access_token ?? "",
				},
				query: {
					claims: JSON.stringify(claimsParam),
				},
			},
		);
		const userinfo = (
			userinfoResult.data && "response" in userinfoResult.data
				? userinfoResult.data.response
				: userinfoResult.data
		) as Record<string, unknown>;
		expect(
			normalizeVerifiedClaims(
				userinfo?.verified_claims as Record<string, unknown>,
			),
		).toEqual(normalizedVerifiedClaims);
	});

	it("filters verified_claims to only requested fields", async () => {
		const claimsParam = {
			id_token: {
				verified_claims: {
					verification: { trust_framework: null },
					claims: { given_name: null },
				},
			},
			userinfo: {
				verified_claims: {
					verification: { trust_framework: null },
					claims: { family_name: null },
				},
			},
		};

		const { code, codeVerifier } = await getAuthCode({
			additionalParams: {
				claims: JSON.stringify(claimsParam),
			},
		});
		const authContext = await auth.$context;
		const identifier = createHash("sha256").update(code).digest("base64url");
		const verification =
			await authContext.internalAdapter.findVerificationValue(identifier);
		expect(verification?.value).toBeDefined();
		const parsedVerification = verification
			? (JSON.parse(verification.value) as { query?: Record<string, unknown> })
			: null;
		expect(parsedVerification?.query?.claims).toBe(JSON.stringify(claimsParam));

		const tokensResult = await validateAuthCode({
			code,
			codeVerifier,
		});
		const tokens = (
			tokensResult.data && "response" in tokensResult.data
				? tokensResult.data.response
				: tokensResult.data
		) as TokenResponse;
		expect(tokens?.id_token).toBeDefined();

		const idTokenPayload = decodeJwt(tokens?.id_token ?? "");
		expect(idTokenPayload.verified_claims).toEqual({
			verification: { trust_framework: "example" },
			claims: { given_name: "Test" },
		});

		const userinfoResult = await client.$fetch<Record<string, unknown>>(
			"/oauth2/userinfo",
			{
				headers: {
					authorization: tokens?.access_token ?? "",
				},
				query: {
					claims: JSON.stringify(claimsParam),
				},
			},
		);
		const userinfo = (
			userinfoResult.data && "response" in userinfoResult.data
				? userinfoResult.data.response
				: userinfoResult.data
		) as Record<string, unknown>;
		expect(userinfo?.verified_claims).toEqual({
			verification: { trust_framework: "example" },
			claims: { family_name: "User" },
		});
	});
});
