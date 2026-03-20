import type { BetterAuthOptions } from "@better-auth/core";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { oidc4vci } from "../src";

describe("oidc4vci - well-known aliases", async () => {
	const baseURL = "http://localhost:3000";

	const authOptions = {
		baseURL,
		basePath: "/",
		plugins: [
			oidc4vci({
				credentialConfigurations: [
					{
						id: "kyc_sdjwt_v1",
						vct: "urn:example:kyc:v1",
					},
				],
				authorizationServer: `${baseURL}/api/auth`,
				wellKnownAliases: ["/.well-known/openid-credential-issuer/alias"],
			}),
		],
	} satisfies BetterAuthOptions;

	const { customFetchImpl } = await getTestInstance(authOptions);

	it("serves metadata at primary and explicit alias paths", async () => {
		const primaryRes = await customFetchImpl(
			`${baseURL}/.well-known/openid-credential-issuer`,
			{ method: "GET" },
		);
		expect(primaryRes.status).toBe(200);
		const primary = (await primaryRes.json()) as Record<string, unknown>;

		const aliasRes = await customFetchImpl(
			`${baseURL}/.well-known/openid-credential-issuer/alias`,
			{ method: "GET" },
		);
		expect(aliasRes.status).toBe(200);
		const alias = (await aliasRes.json()) as Record<string, unknown>;

		expect(alias).toEqual(primary);
		expect(primary.credential_issuer).toBe(baseURL);
		expect(primary.authorization_servers).toEqual([`${baseURL}/api/auth`]);
	});

	it("returns correct credential_issuer when issuerBaseURL has a path", async () => {
		const issuerBaseURL = `${baseURL}/api/auth`;
		const plugin = oidc4vci({
			credentialConfigurations: [
				{
					id: "kyc_sdjwt_v1",
					vct: "urn:example:kyc:v1",
				},
			],
			issuerBaseURL,
		});
		const { auth } = await getTestInstance({
			baseURL,
			plugins: [plugin],
		});

		const body = (await auth.api.getCredentialIssuerMetadata()) as Record<
			string,
			unknown
		>;
		expect(body.credential_issuer).toBe(issuerBaseURL);
	});
});
