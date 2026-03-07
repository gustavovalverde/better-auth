import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { oidc4vci } from "../src";
import { requireApi } from "./api-helpers";
import {
	createOpenid4vciTestClient,
	createOpenid4vciTestIssuer,
} from "./openid4vc-helpers";

describe("oidc4vci - openid4vc-ts conformance", async () => {
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
	const { adminCreateOAuthClient, createCredentialOffer } = requireApi(
		auth.api,
		["adminCreateOAuthClient", "createCredentialOffer"] as const,
		"Missing issuer APIs for oidc4vci tests.",
	);

	it("validates issuer metadata shape with openid4vc-ts", async () => {
		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/.well-known/openid-credential-issuer`,
		);
		expect(res.ok).toBe(true);
		const metadata = (await res.json()) as Record<string, unknown>;

		const issuer = createOpenid4vciTestIssuer();
		expect(() =>
			issuer.createCredentialIssuerMetadata(metadata as never),
		).not.toThrow();
	});

	it("parses credential offer with openid4vc-ts", async () => {
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

		const client = createOpenid4vciTestClient(customFetchImpl as typeof fetch);
		const offerViaUri = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(
			offer.credential_offer_uri,
		)}`;
		const offerViaInline = `openid-credential-offer://?credential_offer=${encodeURIComponent(
			JSON.stringify(offer.credential_offer),
		)}`;

		const resolvedViaUri = await client.resolveCredentialOffer(offerViaUri);
		const resolvedViaInline =
			await client.resolveCredentialOffer(offerViaInline);

		expect(resolvedViaUri.credential_configuration_ids).toEqual([
			"kyc_sdjwt_v1",
		]);
		expect(resolvedViaInline.credential_configuration_ids).toEqual([
			"kyc_sdjwt_v1",
		]);
	});
});
