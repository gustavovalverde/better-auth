import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { haip } from "../src";

describe("haip - metadata composition", async () => {
	const authServerBaseUrl = "http://localhost:3000";

	const authOptions = {
		baseURL: authServerBaseUrl,
		plugins: [
			jwt({ jwt: { issuer: authServerBaseUrl } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				grantTypes: ["authorization_code"],
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
	} satisfies BetterAuthOptions;

	const { auth } = await getTestInstance(authOptions);

	async function fetchMetadata() {
		return (await auth.api.getOAuthServerConfig()) as Record<string, unknown>;
	}

	it("adds pushed_authorization_request_endpoint to AS metadata", async () => {
		const metadata = await fetchMetadata();
		expect(metadata.pushed_authorization_request_endpoint).toBe(
			`${authServerBaseUrl}/api/auth/oauth2/par`,
		);
	});

	it("adds require_pushed_authorization_requests: true", async () => {
		const metadata = await fetchMetadata();
		expect(metadata.require_pushed_authorization_requests).toBe(true);
	});

	it("adds dpop_signing_alg_values_supported", async () => {
		const metadata = await fetchMetadata();
		expect(metadata.dpop_signing_alg_values_supported).toEqual(["ES256"]);
	});

	it("adds authorization_details_types_supported", async () => {
		const metadata = await fetchMetadata();
		expect(metadata.authorization_details_types_supported).toEqual([
			"openid_credential",
		]);
	});

	it("respects custom dpopSigningAlgValues option", async () => {
		const customOptions = {
			baseURL: authServerBaseUrl,
			plugins: [
				jwt({ jwt: { issuer: authServerBaseUrl } }),
				oauthProvider({
					loginPage: "/login",
					consentPage: "/consent",
					grantTypes: ["authorization_code"],
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
				haip({ dpopSigningAlgValues: ["ES256", "ES384"] }),
			],
		} satisfies BetterAuthOptions;

		const { auth: customAuth } = await getTestInstance(customOptions);
		const metadata = (await customAuth.api.getOAuthServerConfig()) as Record<
			string,
			unknown
		>;
		expect(metadata.dpop_signing_alg_values_supported).toEqual([
			"ES256",
			"ES384",
		]);
	});
});
