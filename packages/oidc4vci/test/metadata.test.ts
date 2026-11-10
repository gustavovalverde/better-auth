import { describe, expect, it } from "vitest";
import { AUTH_BASE_URL, BASE_URL, CONFIG_ID, createIssuer } from "./issuer";
import {
	createOpenid4vciTestClient,
	createOpenid4vciTestIssuer,
} from "./openid4vc-helpers";

describe("oidc4vci - issuer metadata and offers", async () => {
	const issuer = await createIssuer({
		oidc4vci: {
			credentialConfigurations: [
				{ id: CONFIG_ID, vct: "urn:example:kyc:v1", scope: "kyc" },
			],
			proofValidators: {
				attestation: async () => {
					throw new Error("not used");
				},
			},
		},
	});

	async function getMetadata() {
		const res = await issuer.customFetchImpl(
			`${AUTH_BASE_URL}/.well-known/openid-credential-issuer`,
		);
		expect(res.status).toBe(200);
		return (await res.json()) as Record<string, any>;
	}

	it("serves OpenID4VCI 1.0 issuer metadata", async () => {
		const metadata = await getMetadata();
		expect(metadata.credential_issuer).toBe(BASE_URL);
		expect(metadata.credential_endpoint).toBe(
			`${AUTH_BASE_URL}/oidc4vci/credential`,
		);
		expect(metadata.nonce_endpoint).toBe(`${AUTH_BASE_URL}/oidc4vci/nonce`);
		const cfg = metadata.credential_configurations_supported[CONFIG_ID];
		expect(cfg.format).toBe("dc+sd-jwt");
		expect(cfg.scope).toBe("kyc");
		expect(cfg.cryptographic_binding_methods_supported).toEqual(["jwk"]);
		expect(Object.keys(cfg.proof_types_supported)).toEqual([
			"jwt",
			"attestation",
		]);
		expect(() =>
			createOpenid4vciTestIssuer().createCredentialIssuerMetadata(
				metadata as never,
			),
		).not.toThrow();
	});

	it("resolves offers by value and by reference with openid4vc-ts", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const { offer } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
			tx_code: "1234",
		});
		const client = createOpenid4vciTestClient(
			issuer.customFetchImpl as typeof fetch,
		);
		const byReference = await client.resolveCredentialOffer(
			`openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offer.credential_offer_uri)}`,
		);
		const byValue = await client.resolveCredentialOffer(
			`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer.credential_offer))}`,
		);
		expect(byReference.credential_configuration_ids).toEqual([CONFIG_ID]);
		expect(byValue).toEqual(byReference);
		expect(
			byReference.grants?.[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]?.tx_code,
		).toEqual({ input_mode: "numeric", length: 4 });
	});
});
