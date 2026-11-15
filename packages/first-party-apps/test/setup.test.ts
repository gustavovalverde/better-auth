import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import type { FirstPartyAppsOptions, FirstPartyMethod } from "../src";
import { firstPartyApps, passwordMethod } from "../src";
import {
	BASE_URL,
	createFpaServer,
	createRecordingMethod,
	TEST_EMAIL,
} from "./fpa-server";

const provider = () =>
	oauthProvider({
		loginPage: "/login",
		consentPage: "/consent",
		silenceWarnings: { oauthAuthServerConfig: true, openidConfig: true },
	});

const method = (
	overrides: Partial<FirstPartyMethod> = {},
): FirstPartyMethod => ({
	...createRecordingMethod().method,
	...overrides,
});

describe("first-party apps - setup", () => {
	it("rejects invalid options", () => {
		const create = (options: Partial<FirstPartyAppsOptions>) => () =>
			firstPartyApps({
				isFirstPartyClient: () => true,
				methods: [method()],
				...options,
			} as FirstPartyAppsOptions);
		expect(create({ isFirstPartyClient: undefined as never })).toThrow(
			/isFirstPartyClient/,
		);
		expect(create({ methods: [] })).toThrow(/at least one method/);
		expect(create({ methods: [method(), method()] })).toThrow(/duplicate/);
		expect(
			create({ methods: [method({ responseParameters: ["scope"] })] }),
		).toThrow(/plugin's "scope"/);
		expect(
			create({
				methods: [method(), method({ id: "other" })],
			}),
		).toThrow(/both use/);
		expect(create({ methods: [method({ responseParameters: [] })] })).toThrow(
			/at least one response parameter/,
		);
	});

	it("fails without the oauth-provider plugin or the authorization_code grant", async () => {
		const fpa = firstPartyApps({
			isFirstPartyClient: () => true,
			methods: [passwordMethod()],
		});
		await expect(
			getTestInstance({ baseURL: BASE_URL, plugins: [fpa] }).then(
				({ auth }) => auth.$context,
			),
		).rejects.toThrow(/oauth-provider/);
		await expect(
			getTestInstance({
				baseURL: BASE_URL,
				plugins: [
					jwt(),
					oauthProvider({
						loginPage: "/login",
						consentPage: "/consent",
						grantTypes: ["client_credentials"],
						silenceWarnings: {
							oauthAuthServerConfig: true,
							openidConfig: true,
						},
					}),
					fpa,
				],
			}).then(({ auth }) => auth.$context),
		).rejects.toThrow(/authorization_code/);
	});

	it("fails when passwordMethod() runs without email and password sign-in", async () => {
		await expect(
			getTestInstance(
				{
					baseURL: BASE_URL,
					emailAndPassword: { enabled: false },
					plugins: [
						jwt(),
						provider(),
						firstPartyApps({
							isFirstPartyClient: () => true,
							methods: [passwordMethod()],
						}),
					],
				},
				{ disableTestUser: true },
			).then(({ auth }) => auth.$context),
		).rejects.toThrow(/emailAndPassword/);
	});
});

describe("first-party apps - discovery", async () => {
	const server = await createFpaServer();

	it("advertises the authorization challenge endpoint", async () => {
		const metadata = await server.auth.api.getOAuthServerConfig!();
		expect(metadata.authorization_challenge_endpoint).toBe(
			`${BASE_URL}/api/auth/oauth2/authorize-challenge`,
		);
		const openid = await server.auth.api.getOpenIdConfig!();
		expect(openid.authorization_challenge_endpoint).toBe(
			`${BASE_URL}/api/auth/oauth2/authorize-challenge`,
		);
	});

	it("does not advertise it without the plugin", async () => {
		const { auth } = await getTestInstance({
			baseURL: BASE_URL,
			plugins: [jwt(), provider()],
		});
		const metadata =
			(await auth.api.getOAuthServerConfig()) as unknown as Record<
				string,
				unknown
			>;
		expect(metadata.authorization_challenge_endpoint).toBeUndefined();
	});
});

describe("first-party apps - rate limit", async () => {
	const server = await createFpaServer({
		auth: { rateLimit: { enabled: true } },
		plugin: { rateLimit: { window: 60, max: 2 } },
	});
	const client = await server.createClient();

	it("answers 429 after rateLimit.max requests from one IP", async () => {
		const send = () =>
			server.challenge({
				client_id: client.client_id,
				response_type: "code",
				scope: "openid",
				login_hint: TEST_EMAIL,
			});
		expect((await send()).status).toBe(403);
		expect((await send()).status).toBe(403);
		expect((await send()).status).toBe(429);
	});
});

describe("first-party apps - base URL", () => {
	it("warns when the endpoint is served over plain http on a public host", async () => {
		const warnings: string[] = [];
		const { auth } = await getTestInstance({
			baseURL: "http://auth.example.com",
			logger: {
				level: "warn",
				log: (level, message) => {
					if (level === "warn") warnings.push(message);
				},
			},
			plugins: [
				jwt(),
				provider(),
				firstPartyApps({
					isFirstPartyClient: () => true,
					methods: [passwordMethod()],
				}),
			],
		});
		await auth.$context;
		expect(warnings.some((message) => message.includes("https"))).toBe(true);
	});
});
