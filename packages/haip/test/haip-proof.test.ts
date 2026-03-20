import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import {
	calculateJwkThumbprint,
	decodeJwt,
	exportJWK,
	generateKeyPair,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import { createKeyAttestationValidator, haip } from "../src";
import { requireApi } from "./api-helpers";

describe("haip - proof type extensibility", async () => {
	const authServerBaseUrl = "http://localhost:3000";

	// Generate an "attestation issuer" key pair (simulates a wallet manufacturer CA)
	const attestationIssuerKp = await generateKeyPair("ES256");
	const attestationIssuerJwk = await exportJWK(attestationIssuerKp.publicKey);

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
				proofValidators: {
					attestation: createKeyAttestationValidator(),
				},
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

	async function getTokens() {
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

		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", preAuthorizedCode);

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
			c_nonce: string;
		};
	}

	it("accepts attestation proof type via proofValidators", async () => {
		const tokens = await getTokens();

		// Generate the wallet's key pair (the "attested" key)
		const walletKp = await generateKeyPair("ES256");
		const walletJwk = await exportJWK(walletKp.publicKey);

		// Create the attestation JWT (signed by the attestation issuer)
		// This simulates a wallet manufacturer attesting the wallet's key
		const attestationJwt = await new SignJWT({
			cnf: { jwk: walletJwk },
			nonce: tokens.c_nonce,
		})
			.setProtectedHeader({
				alg: "ES256",
				jwk: attestationIssuerJwk,
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(attestationIssuerKp.privateKey);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proof: {
						proof_type: "attestation",
						attestation: attestationJwt,
						nonce: tokens.c_nonce,
					},
				}),
			},
		);

		expect(res.status).toBe(200);
		const json = (await res.json()) as { credential: string };
		expect(json.credential).toBeDefined();

		// Verify the credential's cnf.jkt matches the attested key
		const credentialJwt = json.credential.split("~")[0]!;
		const payload = decodeJwt(credentialJwt);
		const expectedJkt = await calculateJwkThumbprint(walletJwk);
		expect((payload.cnf as any).jkt).toBe(expectedJkt);
	});

	it("rejects unknown proof_type with no validator", async () => {
		const tokens = await getTokens();

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proof: {
						proof_type: "ldp_vp",
						some_data: "test",
					},
				}),
			},
		);

		expect(res.status).toBe(400);
	});

	it("built-in jwt validator still works when proofValidators configured", async () => {
		const tokens = await getTokens();

		const holder = await generateKeyPair("ES256");
		const jwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({
				alg: "ES256",
				jwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holder.privateKey);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);

		expect(res.status).toBe(200);
		const json = (await res.json()) as { credential: string };
		expect(json.credential).toBeDefined();
	});
});
