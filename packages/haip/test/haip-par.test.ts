import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { generateRandomString } from "better-auth/crypto";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { createParResolver, haip } from "../src";

describe("haip - PAR (Pushed Authorization Requests)", async () => {
	const authServerBaseUrl = "http://localhost:3000";
	const rpBaseUrl = "http://localhost:5000";
	const redirectUri = `${rpBaseUrl}/api/auth/oauth2/callback/test`;

	const authOptions = {
		baseURL: authServerBaseUrl,
		plugins: [
			jwt({ jwt: { issuer: authServerBaseUrl } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				grantTypes: ["authorization_code"],
				requestUriResolver: createParResolver(),
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

	const _client = (await import("better-auth/client")).createAuthClient({
		plugins: [
			(await import("better-auth/client/plugins")).jwtClient(),
			(
				await import("@better-auth/oauth-provider/client")
			).oauthProviderClient(),
		],
		baseURL: authServerBaseUrl,
		fetchOptions: { customFetchImpl },
	});

	async function pushRequest(
		clientId: string,
		params: Record<string, string>,
		fetchImpl = customFetchImpl,
	) {
		const res = await fetchImpl(`${authServerBaseUrl}/api/auth/oauth2/par`, {
			method: "POST",
			headers: new Headers({ "content-type": "application/json" }),
			body: JSON.stringify(params),
		});
		return res;
	}

	it("POST /oauth2/par returns request_uri and expires_in", async () => {
		const { headers } = await signInWithTestUser();

		const oauthClient = (await auth.api.adminCreateOAuthClient!({
			headers,
			body: {
				redirect_uris: [redirectUri],
				skip_consent: true,
			},
		})) as { client_id: string; client_secret: string };

		const parRes = await pushRequest(oauthClient.client_id, {
			response_type: "code",
			client_id: oauthClient.client_id,
			redirect_uri: redirectUri,
			scope: "openid",
			state: "test-par-state",
			code_challenge: "test-challenge",
			code_challenge_method: "S256",
		});

		expect(parRes.status).toBe(200);
		const json = (await parRes.json()) as {
			request_uri: string;
			expires_in: number;
		};
		expect(json.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
		expect(json.expires_in).toBeGreaterThan(0);
	});

	it("authorize endpoint accepts request_uri from PAR", async () => {
		const { headers } = await signInWithTestUser();

		const oauthClient = (await auth.api.adminCreateOAuthClient!({
			headers,
			body: {
				redirect_uris: [redirectUri],
				skip_consent: true,
			},
		})) as { client_id: string; client_secret: string };

		const codeVerifier = generateRandomString(32);
		// Compute S256 code challenge
		const encoder = new TextEncoder();
		const data = encoder.encode(codeVerifier);
		const digest = await crypto.subtle.digest("SHA-256", data);
		const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=+$/, "");

		const parRes = await pushRequest(oauthClient.client_id, {
			response_type: "code",
			client_id: oauthClient.client_id,
			redirect_uri: redirectUri,
			scope: "openid",
			state: "par-auth-state",
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
		});

		const { request_uri } = (await parRes.json()) as {
			request_uri: string;
		};

		// Use request_uri at authorize endpoint
		const authorizeUrl = new URL(
			`${authServerBaseUrl}/api/auth/oauth2/authorize`,
		);
		authorizeUrl.searchParams.set("request_uri", request_uri);
		authorizeUrl.searchParams.set("client_id", oauthClient.client_id);

		const authorizeRes = await customFetchImpl(authorizeUrl.toString(), {
			method: "GET",
			headers,
			redirect: "manual",
		});

		// Should redirect to callback with a code
		const location = authorizeRes.headers.get("Location") ?? "";
		expect(location).toContain("code=");
		expect(location).toContain("state=par-auth-state");
	});

	it("rejects expired request_uri", async () => {
		await signInWithTestUser();

		// Create a HAIP instance with very short PAR expiry
		const shortExpiry = {
			baseURL: authServerBaseUrl,
			plugins: [
				jwt({ jwt: { issuer: authServerBaseUrl } }),
				oauthProvider({
					loginPage: "/login",
					consentPage: "/consent",
					grantTypes: ["authorization_code"],
					requestUriResolver: createParResolver(),
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
				haip({ parExpiresInSeconds: 0 }),
			],
		} satisfies BetterAuthOptions;

		const shortInstance = await getTestInstance(shortExpiry);

		const { headers: shortHeaders } = await shortInstance.signInWithTestUser();

		const oauthClient = (await shortInstance.auth.api.adminCreateOAuthClient!({
			headers: shortHeaders,
			body: {
				redirect_uris: [redirectUri],
				skip_consent: true,
			},
		})) as { client_id: string; client_secret: string };

		const parRes = await shortInstance.customFetchImpl(
			`${authServerBaseUrl}/api/auth/oauth2/par`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					response_type: "code",
					client_id: oauthClient.client_id,
					redirect_uri: redirectUri,
					scope: "openid",
					state: "expired-state",
				}),
			},
		);

		const { request_uri } = (await parRes.json()) as {
			request_uri: string;
		};

		// Wait a bit to ensure expiry
		await new Promise((resolve) => setTimeout(resolve, 50));

		const authorizeUrl = new URL(
			`${authServerBaseUrl}/api/auth/oauth2/authorize`,
		);
		authorizeUrl.searchParams.set("request_uri", request_uri);
		authorizeUrl.searchParams.set("client_id", oauthClient.client_id);

		const authorizeRes = await shortInstance.customFetchImpl(
			authorizeUrl.toString(),
			{
				method: "GET",
				headers: shortHeaders,
				redirect: "manual",
			},
		);

		// Should redirect with error
		const location = authorizeRes.headers.get("Location") ?? "";
		expect(location).toContain("invalid_request_uri");
	});
});
