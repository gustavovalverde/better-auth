import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it, vi } from "vitest";
import { firstPartyApps, passwordMethod } from "../src";
import {
	AUTH_BASE_URL,
	BASE_URL,
	createDpopKey,
	createFpaServer,
	createPkce,
} from "./fpa-server";

describe("first-party apps - auth_session in the token response", async () => {
	const warnings: string[] = [];
	const server = await createFpaServer({
		oauth: {
			customTokenResponseFields: () => ({
				app_field: "kept",
				auth_session: "from-the-app",
			}),
		},
		auth: {
			logger: {
				level: "warn",
				log: (level, message) => {
					if (level === "warn") warnings.push(message);
				},
			},
		},
	});
	const client = await server.createClient();

	it("returns a new handle for a DPoP-bound flow, and only the new one works", async () => {
		const dpop = await createDpopKey();
		const { final, pkce, handle } = await server.signIn(client.client_id, {
			dpop,
		});
		const tokens = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
			{ dpop },
		);
		expect(tokens.status).toBe(200);
		expect(tokens.body.app_field).toBe("kept");
		const rotated = tokens.body.auth_session;
		expect(rotated).toEqual(expect.any(String));
		expect(rotated).not.toBe(handle);
		expect(rotated).not.toBe("from-the-app");

		const next = await createPkce();
		const reentry = {
			code_challenge: next.challenge,
			code_challenge_method: "S256",
		};
		const old = await server.challenge(
			{ auth_session: handle, ...reentry },
			{ dpop },
		);
		expect(old.body.error).toBe("invalid_session");
		const current = await server.challenge(
			{ auth_session: rotated, ...reentry },
			{ dpop },
		);
		expect(current.status).toBe(200);
	});

	it("keeps the app's fields and warns once about its auth_session", async () => {
		const { final, pkce } = await server.signIn(client.client_id);
		const tokens = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
		);
		expect(tokens.body.app_field).toBe("kept");
		expect(
			warnings.filter((message) => message.includes("auth_session")),
		).toHaveLength(1);
	});

	it("returns no auth_session for an unbound flow or a browser code", async () => {
		const { final, pkce } = await server.signIn(client.client_id);
		const unbound = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
		);
		expect(unbound.status).toBe(200);
		expect(unbound.body.auth_session).toBeUndefined();

		const browserPkce = await createPkce();
		const url = new URL(`${AUTH_BASE_URL}/oauth2/authorize`);
		url.search = new URLSearchParams({
			response_type: "code",
			client_id: client.client_id,
			redirect_uri: "https://app.example/callback",
			scope: "openid",
			state: "browser",
			code_challenge: browserPkce.challenge,
			code_challenge_method: "S256",
		}).toString();
		const authorize = await server.customFetchImpl(url.toString(), {
			headers: server.adminHeaders,
			redirect: "manual",
		});
		const location = new URL(authorize.headers.get("location")!);
		const code = location.searchParams.get("code")!;
		expect(code).toEqual(expect.any(String));
		const dpop = await createDpopKey();
		const browser = await server.redeem(
			client.client_id,
			code,
			browserPkce.verifier,
			{ dpop, extra: { redirect_uri: "https://app.example/callback" } },
		);
		expect(browser.status).toBe(200);
		expect(browser.body.auth_session).toBeUndefined();
	});
});

describe("first-party apps - token response composition", () => {
	it("does not wrap twice when two instances share the options", async () => {
		const appFields = vi.fn((_info: unknown) => ({ app_field: "kept" }));
		const provider = oauthProvider({
			loginPage: "/login",
			consentPage: "/consent",
			customTokenResponseFields: appFields,
			silenceWarnings: { oauthAuthServerConfig: true, openidConfig: true },
		});
		const plugins = [
			jwt({ jwt: { issuer: BASE_URL } }),
			provider,
			firstPartyApps({
				isFirstPartyClient: () => true,
				methods: [passwordMethod()],
			}),
		];
		const first = await getTestInstance({ baseURL: BASE_URL, plugins });
		await first.auth.$context;
		const second = await getTestInstance({ baseURL: BASE_URL, plugins });
		await second.auth.$context;
		const composed = provider.options.customTokenResponseFields!;
		expect(composed).not.toBe(appFields);
		await composed({ grantType: "client_credentials", scopes: [] });
		expect(appFields).toHaveBeenCalledTimes(1);
	});
});
