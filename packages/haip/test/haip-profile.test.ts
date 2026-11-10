import { getTestInstance } from "better-auth/test";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { createX5cHeaders, haip } from "../src";
import {
	AUTH_BASE_URL,
	CONFIG_ID,
	createHaipServer,
	createJwtProof,
} from "./haip-server";
import { caCert, leafCert } from "./x509-fixtures";

describe("haip - plugin setup", () => {
	it("requires its peer plugins", async () => {
		await expect(
			getTestInstance({ baseURL: "http://localhost:3000", plugins: [haip()] }),
		).rejects.toThrow('@better-auth/haip requires the "oauth-provider" plugin');
	});

	it("requires trusted issuers for wallet attestation", () => {
		expect(() => haip({ walletAttestation: { trustedIssuers: [] } })).toThrow(
			"trusted issuer",
		);
		expect(() =>
			haip({
				walletAttestation: { trustedIssuers: [{ issuer: "https://w" }] },
			}),
		).toThrow("must configure jwks, jwksUri, or trustAnchors");
		expect(() =>
			haip({
				walletAttestation: {
					trustedIssuers: [{ jwksUri: "http://wallet.example/jwks" }],
				},
			}),
		).toThrow("https");
	});
});

describe("haip - profile", async () => {
	const server = await createHaipServer({
		oidc4vci: {
			resolveCredentialHeaders: createX5cHeaders([leafCert, caCert]),
		},
	});

	it("advertises PAR and authorization_details in AS metadata", async () => {
		const metadata = (await server.auth.api.getOAuthServerConfig()) as Record<
			string,
			unknown
		>;
		expect(metadata.pushed_authorization_request_endpoint).toBe(
			`${AUTH_BASE_URL}/oauth2/par`,
		);
		expect(metadata.require_pushed_authorization_requests).toBe(true);
		expect(metadata.authorization_details_types_supported).toEqual([
			"openid_credential",
		]);
		expect(metadata.dpop_signing_alg_values_supported).toEqual(["ES256"]);
		expect(metadata).not.toHaveProperty("challenge_endpoint");
	});

	it("requires DPoP-bound tokens at the credential endpoint", async () => {
		const { headers } = await server.signInWithTestUser();
		const client = await server.createClient(headers);
		const code = await server.createOffer(headers, client.client_id);
		const tokenRes = await server.postForm(`${AUTH_BASE_URL}/oauth2/token`, {
			grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"pre-authorized_code": code,
			client_id: client.client_id,
		});
		const { access_token } = (await tokenRes.json()) as {
			access_token: string;
		};
		const { proofJwt } = await createJwtProof(await server.nonce());
		const res = await server.requestCredential({
			accessToken: access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe("invalid_token");
	});

	it("issues credentials with authorization_details and x5c headers", async () => {
		const { accessToken } = await server.issueAccessToken();
		const claims = decodeJwt(accessToken) as {
			authorization_details?: Array<{
				type: string;
				credential_identifiers?: string[];
			}>;
		};
		expect(claims.authorization_details?.[0]?.type).toBe("openid_credential");
		expect(
			claims.authorization_details?.[0]?.credential_identifiers,
		).toHaveLength(1);

		const { credential } = await server.issueCredential();
		const header = decodeProtectedHeader(credential.split("~")[0]!);
		expect(header.x5c).toEqual([leafCert, caCert]);
		expect(header.typ).toBe("dc+sd-jwt");

		const statusRes = await server.customFetchImpl(
			`${AUTH_BASE_URL}/oidc4vci/status-list`,
		);
		expect(decodeProtectedHeader(await statusRes.text()).x5c).toEqual([
			leafCert,
			caCert,
		]);
	});
});

describe("haip - requirePar option", async () => {
	const server = await createHaipServer({ haip: { requirePar: false } });

	it("advertises require_pushed_authorization_requests false", async () => {
		const metadata = (await server.auth.api.getOAuthServerConfig()) as Record<
			string,
			unknown
		>;
		expect(metadata.require_pushed_authorization_requests).toBe(false);
	});
});
