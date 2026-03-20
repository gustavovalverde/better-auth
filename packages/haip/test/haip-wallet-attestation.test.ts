import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	createWalletAttestationStrategy,
	haip,
	WALLET_ATTESTATION_TYPE,
} from "../src";
import { requireApi } from "./api-helpers";

describe("haip - wallet attestation client auth", async () => {
	const authServerBaseUrl = "http://localhost:3000";

	// Wallet manufacturer key pair (signs the Client Attestation JWT)
	const manufacturerKp = await generateKeyPair("ES256");
	const manufacturerJwk = await exportJWK(manufacturerKp.publicKey);

	// Wallet instance key pair (the "device" key attested by manufacturer)
	const walletInstanceKp = await generateKeyPair("ES256");
	const walletInstanceJwk = await exportJWK(walletInstanceKp.publicKey);

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
				clientAuthStrategies: {
					[WALLET_ATTESTATION_TYPE]: createWalletAttestationStrategy(),
				},
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

	/**
	 * Build a wallet attestation client_assertion: two JWTs joined with `~`.
	 *   Part 1 (Client Attestation JWT): signed by manufacturer, attests wallet instance key
	 *   Part 2 (PoP JWT): signed by wallet instance key, binds to token endpoint
	 */
	async function buildWalletAttestation(clientId: string) {
		const clientAttestationJwt = await new SignJWT({
			sub: clientId,
			cnf: { jwk: walletInstanceJwk },
		})
			.setProtectedHeader({ alg: "ES256", jwk: manufacturerJwk })
			.setIssuedAt()
			.setIssuer("https://wallet-manufacturer.example")
			.sign(manufacturerKp.privateKey);

		const popJwt = await new SignJWT({})
			.setProtectedHeader({ alg: "ES256" })
			.setIssuedAt()
			.setAudience(`${authServerBaseUrl}/api/auth/oauth2/token`)
			.sign(walletInstanceKp.privateKey);

		return `${clientAttestationJwt}~${popJwt}`;
	}

	it("accepts attest_jwt_client_auth at token endpoint", async () => {
		const { headers, user } = await signInWithTestUser();

		// Create a public client (no secret) — wallet attestation is the auth method
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

		const assertion = await buildWalletAttestation(walletClient.client_id);

		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);
		form.set("client_id", walletClient.client_id);
		form.set("client_assertion_type", WALLET_ATTESTATION_TYPE);
		form.set("client_assertion", assertion);

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

		expect(tokenRes.status).toBe(200);
		const json = (await tokenRes.json()) as { access_token: string };
		expect(json.access_token).toBeDefined();
	});

	it("rejects invalid wallet attestation (bad PoP signature)", async () => {
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

		// Build valid attestation JWT but use a DIFFERENT key for PoP
		const wrongKp = await generateKeyPair("ES256");

		const clientAttestationJwt = await new SignJWT({
			sub: walletClient.client_id,
			cnf: { jwk: walletInstanceJwk },
		})
			.setProtectedHeader({ alg: "ES256", jwk: manufacturerJwk })
			.setIssuedAt()
			.setIssuer("https://wallet-manufacturer.example")
			.sign(manufacturerKp.privateKey);

		// Sign PoP with WRONG key (not the wallet instance key)
		const badPopJwt = await new SignJWT({})
			.setProtectedHeader({ alg: "ES256" })
			.setIssuedAt()
			.setAudience(`${authServerBaseUrl}/api/auth/oauth2/token`)
			.sign(wrongKp.privateKey);

		const badAssertion = `${clientAttestationJwt}~${badPopJwt}`;

		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);
		form.set("client_id", walletClient.client_id);
		form.set("client_assertion_type", WALLET_ATTESTATION_TYPE);
		form.set("client_assertion", badAssertion);

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

		expect(tokenRes.status).toBeGreaterThanOrEqual(400);
	});

	it("advertises token_endpoint_auth_methods_supported including wallet attestation", async () => {
		const metadata = (await auth.api.getOAuthServerConfig()) as {
			token_endpoint_auth_methods_supported: string[];
		};

		expect(metadata.token_endpoint_auth_methods_supported).toContain(
			WALLET_ATTESTATION_TYPE,
		);
	});
});
