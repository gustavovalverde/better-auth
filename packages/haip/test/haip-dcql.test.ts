import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { oidc4vci } from "@better-auth/oidc4vci";
import { oidc4vp } from "@better-auth/oidc4vp";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { base64url, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { buildDcqlQuery, createDcqlMatcher, haip } from "../src";

async function createKbJwt(input: {
	credential: string;
	nonce: string;
	aud: string;
	holderKeyPair: CryptoKeyPair;
}): Promise<string> {
	const sdHash = base64url.encode(
		new Uint8Array(
			await crypto.subtle.digest(
				"SHA-256",
				new TextEncoder().encode(input.credential),
			),
		),
	);
	const jwk = await exportJWK(input.holderKeyPair.publicKey);
	return await new SignJWT({ nonce: input.nonce, sd_hash: sdHash })
		.setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt", jwk })
		.setIssuedAt()
		.setAudience(input.aud)
		.sign(input.holderKeyPair.privateKey);
}

describe("haip - DCQL presentation matching", async () => {
	const authServerBaseUrl = "http://localhost:3000";
	let fetcher: typeof fetch | null = null;

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
			}),
			oidc4vp({
				expectedAudience: authServerBaseUrl,
				allowedIssuers: [authServerBaseUrl],
				resolveIssuerJwks: async () => {
					if (!fetcher) throw new Error("fetcher not ready");
					const res = await fetcher(`${authServerBaseUrl}/api/auth/jwks`, {
						method: "GET",
					});
					const body = (await res.json()) as {
						keys?: Record<string, unknown>[];
					};
					return body.keys ?? [];
				},
				statusListFetch: async (uri) => {
					if (!fetcher) throw new Error("fetcher not ready");
					const res = await fetcher(uri, { method: "GET" });
					return await res.text();
				},
				presentationMatcher: createDcqlMatcher(),
			}),
			haip(),
		],
	} satisfies BetterAuthOptions;

	const { auth, customFetchImpl, signInWithTestUser } =
		await getTestInstance(authOptions);
	fetcher = customFetchImpl as typeof fetch;

	async function issueCredential(): Promise<{
		credential: string;
		holderKeyPair: CryptoKeyPair;
	}> {
		const { headers, user } = await signInWithTestUser();

		const walletClient = (await auth.api.adminCreateOAuthClient!({
			headers,
			body: {
				redirect_uris: ["https://wallet.example/cb"],
				token_endpoint_auth_method: "none",
				skip_consent: true,
			},
		})) as { client_id: string };

		const offer = (await auth.api.createCredentialOffer!({
			headers,
			body: {
				client_id: walletClient.client_id,
				userId: user.id,
				credential_configuration_id: "kyc_sdjwt_v1",
			},
		})) as {
			credential_offer: {
				grants: Record<string, { "pre-authorized_code": string }>;
			};
		};

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
		form.set("client_id", walletClient.client_id);

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
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};

		const holderKeyPair = await generateKeyPair("EdDSA");
		const holderJwk = await exportJWK(holderKeyPair.publicKey);
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({
				alg: "EdDSA",
				jwk: holderJwk,
				typ: "openid4vci-proof+jwt",
			})
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(holderKeyPair.privateKey);

		const credentialRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					authorization: `Bearer ${tokens.access_token}`,
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		const credentialBody = (await credentialRes.json()) as {
			credential: string;
		};
		return { credential: credentialBody.credential, holderKeyPair };
	}

	it("matches DCQL query against presented SD-JWT VC", async () => {
		const { credential, holderKeyPair } = await issueCredential();
		const nonce = "dcql-match-nonce";
		const kbJwt = await createKbJwt({
			credential,
			nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${credential}${kbJwt}`;

		const dcqlQuery = buildDcqlQuery([
			{
				id: "kyc_cred",
				format: "dc+sd-jwt",
				meta: { vct_values: ["urn:example:kyc:v1"] },
			},
		]);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/response`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					vp_token: vpToken,
					nonce,
					dcql_query: dcqlQuery,
				}),
			},
		);

		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			verified?: boolean;
			presentations?: Array<{ issuer?: string }>;
		};
		expect(body.verified).toBe(true);
		expect(body.presentations?.[0]?.issuer).toBe(authServerBaseUrl);
	});

	it("rejects presentation missing required credential", async () => {
		const { credential, holderKeyPair } = await issueCredential();
		const nonce = "dcql-reject-nonce";
		const kbJwt = await createKbJwt({
			credential,
			nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${credential}${kbJwt}`;

		const dcqlQuery = buildDcqlQuery([
			{
				id: "kyc_cred",
				format: "dc+sd-jwt",
				meta: { vct_values: ["urn:example:kyc:v1"] },
			},
			{
				id: "address_cred",
				format: "dc+sd-jwt",
				meta: { vct_values: ["urn:example:address:v1"] },
			},
		]);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/response`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					vp_token: vpToken,
					nonce,
					dcql_query: dcqlQuery,
				}),
			},
		);

		expect(res.status).toBe(400);
		const body = (await res.json()) as {
			verified?: boolean;
			errors?: Array<{ message?: string }>;
		};
		expect(body.verified).toBe(false);
		expect(body.errors?.some((e) => e.message?.includes("address_cred"))).toBe(
			true,
		);
	});

	it("rejects when VCT does not match query constraint", async () => {
		const { credential, holderKeyPair } = await issueCredential();
		const nonce = "dcql-vct-nonce";
		const kbJwt = await createKbJwt({
			credential,
			nonce,
			aud: authServerBaseUrl,
			holderKeyPair,
		});
		const vpToken = `${credential}${kbJwt}`;

		const dcqlQuery = buildDcqlQuery([
			{
				id: "wrong_vct",
				format: "dc+sd-jwt",
				meta: { vct_values: ["urn:example:drivers_license:v1"] },
			},
		]);

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vp/response`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					vp_token: vpToken,
					nonce,
					dcql_query: dcqlQuery,
				}),
			},
		);

		expect(res.status).toBe(400);
		const body = (await res.json()) as {
			verified?: boolean;
			errors?: Array<{ message?: string }>;
		};
		expect(body.verified).toBe(false);
		expect(body.errors?.some((e) => e.message?.includes("wrong_vct"))).toBe(
			true,
		);
	});
});

describe("DCQL matcher (unit)", () => {
	const matcher = createDcqlMatcher();

	it("matches presentation with required claims", async () => {
		const result = await matcher({
			query: buildDcqlQuery([
				{
					id: "id_cred",
					format: "dc+sd-jwt",
					meta: { vct_values: ["urn:example:kyc:v1"] },
					claims: [{ path: ["given_name"] }, { path: ["family_name"] }],
				},
			]),
			presentations: [
				{
					issuer: "https://issuer.example",
					claims: {
						vct: "urn:example:kyc:v1",
						given_name: "Alice",
						family_name: "Smith",
					},
				},
			],
		});

		expect(result.matched).toBe(true);
		expect(result.matchedPresentations).toHaveLength(1);
	});

	it("rejects when required claim is missing", async () => {
		const result = await matcher({
			query: buildDcqlQuery([
				{
					id: "id_cred",
					format: "dc+sd-jwt",
					claims: [{ path: ["given_name"] }, { path: ["date_of_birth"] }],
				},
			]),
			presentations: [
				{
					claims: {
						vct: "urn:example:kyc:v1",
						given_name: "Alice",
					},
				},
			],
		});

		expect(result.matched).toBe(false);
		expect(result.errors?.[0]).toContain("id_cred");
	});

	it("matches nested claim paths", async () => {
		const result = await matcher({
			query: buildDcqlQuery([
				{
					id: "address_cred",
					format: "dc+sd-jwt",
					claims: [{ path: ["address", "country"] }],
				},
			]),
			presentations: [
				{
					claims: {
						address: { country: "US", city: "NYC" },
					},
				},
			],
		});

		expect(result.matched).toBe(true);
	});

	it("filters by claim value constraint", async () => {
		const result = await matcher({
			query: buildDcqlQuery([
				{
					id: "country_cred",
					format: "dc+sd-jwt",
					claims: [
						{ path: ["address", "country"], values: ["US", "CA", "GB"] },
					],
				},
			]),
			presentations: [
				{
					claims: {
						address: { country: "JP" },
					},
				},
			],
		});

		expect(result.matched).toBe(false);
		expect(result.errors?.[0]).toContain("country_cred");
	});

	it("rejects invalid dcql_query input", async () => {
		const result = await matcher({
			query: "not valid json {{{",
			presentations: [],
		});

		expect(result.matched).toBe(false);
		expect(result.errors?.[0]).toContain("invalid dcql_query");
	});

	it("accepts query as JSON string", async () => {
		const query = buildDcqlQuery([{ id: "test", format: "dc+sd-jwt" }]);
		const result = await matcher({
			query: JSON.stringify(query),
			presentations: [{ claims: { vct: "anything" } }],
		});

		expect(result.matched).toBe(true);
	});
});
