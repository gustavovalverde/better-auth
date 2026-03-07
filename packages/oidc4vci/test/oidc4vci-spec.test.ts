import type { BetterAuthOptions } from "@better-auth/core";
import { oauthProvider } from "@better-auth/oauth-provider";
import { getListFromStatusListJWT } from "@sd-jwt/jwt-status-list";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { oidc4vci } from "../src";
import { requireApi } from "./api-helpers";

describe("oidc4vci - OID4VCI 1.0 (issuer, pre-authorized code) - spec checks", async () => {
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
	const {
		adminCreateOAuthClient,
		createCredentialOffer,
		updateCredentialStatus,
	} = requireApi(
		auth.api,
		[
			"adminCreateOAuthClient",
			"createCredentialOffer",
			"updateCredentialStatus",
		] as const,
		"Missing issuer APIs for oidc4vci tests.",
	);

	type ClaimsRequest = { path: string[]; mandatory?: boolean };

	async function createOffer(params?: {
		txCode?: string;
		claims?: ClaimsRequest[];
	}) {
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
				tx_code: params?.txCode,
				claims: params?.claims,
			},
		});

		const preAuthorizedCode =
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			]["pre-authorized_code"];

		return { headers, user, walletClient, offer, preAuthorizedCode };
	}

	async function tokenWithFormUrlEncoded(input: {
		preAuthorizedCode: string;
		clientId?: string;
		txCode?: string;
	}) {
		const tokenUrl = `${authServerBaseUrl}/api/auth/oauth2/token`;
		const form = new URLSearchParams();
		form.set(
			"grant_type",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		);
		form.set("pre-authorized_code", input.preAuthorizedCode);
		if (input.clientId) form.set("client_id", input.clientId);
		if (input.txCode) form.set("tx_code", input.txCode);

		const res = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/x-www-form-urlencoded",
			}),
			body: form.toString(),
		});

		return res;
	}

	async function createProofJwt(input: { cNonce: string; audience: string }) {
		const holder = await generateKeyPair("EdDSA");
		const jwk = await exportJWK(holder.publicKey);
		const proofJwt = await new SignJWT({ nonce: input.cNonce })
			.setProtectedHeader({ alg: "EdDSA", jwk, typ: "openid4vci-proof+jwt" })
			.setIssuedAt()
			.setAudience(input.audience)
			.sign(holder.privateKey);
		return { proofJwt, jwk };
	}

	function parseSdJwt(credential: string) {
		const parts = credential.split("~");
		const jwt = parts[0] ?? "";
		const disclosures = parts.slice(1).filter(Boolean);
		const disclosureClaims = disclosures.map((disclosure) => {
			const decoded = Buffer.from(disclosure, "base64url").toString("utf8");
			const parsed = JSON.parse(decoded) as [string, string, unknown];
			return parsed[1];
		});
		return { payload: decodeJwt(jwt), disclosureClaims };
	}

	async function setupTokens() {
		const { preAuthorizedCode, walletClient } = await createOffer();
		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		if (tokenRes.status !== 200) {
			throw new Error(
				`token endpoint failed: ${tokenRes.status} ${await tokenRes.text()}`,
			);
		}
		return (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};
	}

	it("serves OpenID Credential Issuer Metadata (required fields present)", async () => {
		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/.well-known/openid-credential-issuer`,
			{ method: "GET" },
		);
		expect(res.status).toBe(200);
		const json = (await res.json()) as Record<string, unknown>;

		expect(json.credential_issuer).toBeTypeOf("string");
		expect(json.credential_endpoint).toBeTypeOf("string");
		expect(json.nonce_endpoint).toBeTypeOf("string");
		expect(json.credential_configurations_supported).toBeTypeOf("object");

		const configs = json.credential_configurations_supported as Record<
			string,
			unknown
		>;
		expect(configs.kyc_sdjwt_v1).toBeTypeOf("object");
		const cfg = configs.kyc_sdjwt_v1 as Record<string, unknown>;
		const bindings = cfg.cryptographic_binding_methods_supported as unknown;
		expect(Array.isArray(bindings)).toBe(true);
		expect(bindings).toContain("jwk");
		const proofs = cfg.proof_types_supported as {
			jwt?: { proof_signing_alg_values_supported?: unknown };
		};
		expect(proofs?.jwt?.proof_signing_alg_values_supported).toBeTypeOf(
			"object",
		);
	});

	it("nonce endpoint returns c_nonce and is not cacheable", async () => {
		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/nonce`,
			{ method: "POST" },
		);
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control") ?? "").toContain("no-store");
		const json = (await res.json()) as {
			c_nonce?: unknown;
			c_nonce_expires_in?: unknown;
		};
		expect(json.c_nonce).toBeTypeOf("string");
		expect(json.c_nonce_expires_in).toBe(300);
	});

	it("credential offer URI resolves to an offer object", async () => {
		const { offer } = await createOffer({ txCode: "1234" });

		const uriRes = await customFetchImpl(offer.credential_offer_uri, {
			method: "GET",
		});
		expect(uriRes.status).toBe(200);
		const resolved = (await uriRes.json()) as {
			credential_issuer: string;
			credential_configuration_ids: string[];
			grants: Record<string, Record<string, unknown>>;
		};

		expect(resolved.credential_issuer).toBe(authServerBaseUrl);
		expect(resolved.credential_configuration_ids).toEqual(["kyc_sdjwt_v1"]);
		expect(
			resolved.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
		).toBeTypeOf("object");
	});

	it("token endpoint accepts application/x-www-form-urlencoded for pre-authorized code", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer();

		const res = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control") ?? "").toContain("no-store");

		const json = (await res.json()) as Record<string, unknown>;
		expect(json.access_token).toBeTypeOf("string");
		expect(json.token_type).toBe("Bearer");
		expect(json.c_nonce).toBeTypeOf("string");
		expect(json.c_nonce_expires_in).toBeTypeOf("number");
	});

	it("token endpoint requires tx_code when the offer included it", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer({
			txCode: "1234",
		});

		const res = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		expect(res.status).toBe(401);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_grant");
	});

	it("token endpoint rejects mismatched client_id when provided", async () => {
		const { headers, preAuthorizedCode } = await createOffer();

		const otherClient = await adminCreateOAuthClient({
			headers,
			body: {
				redirect_uris: ["https://wallet2.example/cb"],
				token_endpoint_auth_method: "none",
				skip_consent: true,
			},
		});

		const res = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: otherClient.client_id,
		});
		expect(res.status).toBe(401);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_client");
	});

	it("credential endpoint supports `proof` (singular) requests", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer();

		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		if (tokenRes.status !== 200) {
			throw new Error(
				`token endpoint failed: ${tokenRes.status} ${await tokenRes.text()}`,
			);
		}
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});

		const credentialUrl = `${authServerBaseUrl}/api/auth/oidc4vci/credential`;
		const res = await customFetchImpl(credentialUrl, {
			method: "POST",
			headers: new Headers({
				"content-type": "application/json",
				authorization: `Bearer ${tokens.access_token}`,
			}),
			body: JSON.stringify({
				access_token: tokens.access_token,
				credential_configuration_id: "kyc_sdjwt_v1",
				proof: {
					proof_type: "jwt",
					jwt: proofJwt,
				},
			}),
		});
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control") ?? "").toContain("no-store");
		const json = (await res.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};
		expect(json.credential).toBeTypeOf("string");
	});

	it("honors requested claims for selective disclosure", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer({
			claims: [{ path: ["email"], mandatory: true }, { path: ["name"] }],
		});
		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		if (tokenRes.status !== 200) {
			throw new Error(
				`token endpoint failed: ${tokenRes.status} ${await tokenRes.text()}`,
			);
		}
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};
		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});
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
		if (credentialRes.status !== 200) {
			throw new Error(
				`credential endpoint failed: ${credentialRes.status} ${await credentialRes.text()}`,
			);
		}
		const credentialBody = (await credentialRes.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};
		const credential = credentialBody.credential;
		expect(credential).toBeTypeOf("string");
		const { payload, disclosureClaims } = parseSdJwt(credential);

		expect(payload.email).toBeTypeOf("string");
		expect(payload.name).toBeUndefined();
		expect(payload.email_verified).toBeUndefined();
		expect(disclosureClaims).toContain("name");
		expect(disclosureClaims).not.toContain("email_verified");
	});

	it("returns invalid_proof when proof is missing", async () => {
		const tokens = await setupTokens();

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
				}),
			},
		);
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_proof");
	});

	it("returns invalid_credential_request when credential_configuration_id is missing", async () => {
		const tokens = await setupTokens();

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_credential_request");
	});

	it("credential endpoint supports credential_identifier from token response", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer();
		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		if (tokenRes.status !== 200) {
			throw new Error(
				`token endpoint failed: ${tokenRes.status} ${await tokenRes.text()}`,
			);
		}
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
			authorization_details?: Array<{
				credential_identifiers?: string[];
			}>;
		};

		const credentialIdentifier =
			tokens.authorization_details?.[0]?.credential_identifiers?.[0];
		expect(credentialIdentifier).toBeTypeOf("string");

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_identifier: credentialIdentifier,
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(200);
	});

	it("returns unknown_credential_identifier for invalid credential_identifier", async () => {
		const tokens = await setupTokens();

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_identifier: "credential-id-1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("unknown_credential_identifier");
	});

	it("returns invalid_credential_request when credential_identifier and credential_configuration_id are both supplied", async () => {
		const tokens = await setupTokens();

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_identifier: "credential-id-1",
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_credential_request");
	});

	it("returns invalid_credential_request for an unsupported format", async () => {
		const tokens = await setupTokens();

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "kyc_sdjwt_v1",
					format: "jwt_vc",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_credential_request");
	});

	it("returns invalid_proof when proof.jwt is missing jwk", async () => {
		const tokens = await setupTokens();

		const holder = await generateKeyPair("EdDSA");
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({ alg: "EdDSA", typ: "openid4vci-proof+jwt" })
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
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_proof");
	});

	it("returns invalid_proof for an invalid proof signature", async () => {
		const tokens = await setupTokens();

		const holderKey = await generateKeyPair("EdDSA");
		const jwk = await exportJWK(holderKey.publicKey);
		const wrongSigner = await generateKeyPair("EdDSA");
		const proofJwt = await new SignJWT({ nonce: tokens.c_nonce })
			.setProtectedHeader({ alg: "EdDSA", jwk, typ: "openid4vci-proof+jwt" })
			.setIssuedAt()
			.setAudience(authServerBaseUrl)
			.sign(wrongSigner.privateKey);

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
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_proof");
	});

	it("returns invalid_proof for an invalid proof audience", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer();

		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: "https://wrong.example",
		});

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
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_proof");
	});

	it("returns invalid_nonce for unknown or expired c_nonce", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer();

		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		const tokens = (await tokenRes.json()) as { access_token: string };

		const { proofJwt } = await createProofJwt({
			cNonce: "not-a-real-nonce",
			audience: authServerBaseUrl,
		});

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
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("invalid_nonce");
	});

	it("returns unknown_credential_configuration for unsupported configuration ids", async () => {
		const { preAuthorizedCode, walletClient } = await createOffer();

		const tokenRes = await tokenWithFormUrlEncoded({
			preAuthorizedCode,
			clientId: walletClient.client_id,
		});
		const tokens = (await tokenRes.json()) as {
			access_token: string;
			c_nonce: string;
		};

		const { proofJwt } = await createProofJwt({
			cNonce: tokens.c_nonce,
			audience: authServerBaseUrl,
		});

		const res = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({ "content-type": "application/json" }),
				body: JSON.stringify({
					access_token: tokens.access_token,
					credential_configuration_id: "does_not_exist",
					proofs: { jwt: [proofJwt] },
				}),
			},
		);
		expect(res.status).toBe(400);
		const json = (await res.json()) as { error?: string };
		expect(json.error).toBe("unknown_credential_configuration");
	});

	it("issues status list entries and exposes the status list JWT", async () => {
		const { access_token, c_nonce } = await setupTokens();
		const { proofJwt } = await createProofJwt({
			cNonce: c_nonce,
			audience: authServerBaseUrl,
		});

		const credentialRes = await customFetchImpl(
			`${authServerBaseUrl}/api/auth/oidc4vci/credential`,
			{
				method: "POST",
				headers: new Headers({
					authorization: `Bearer ${access_token}`,
					"content-type": "application/json",
				}),
				body: JSON.stringify({
					credential_configuration_id: "kyc_sdjwt_v1",
					proofs: {
						jwt: [proofJwt],
					},
				}),
			},
		);
		if (credentialRes.status !== 200) {
			throw new Error(
				`credential endpoint failed: ${credentialRes.status} ${await credentialRes.text()}`,
			);
		}
		const credentialBody = (await credentialRes.json()) as {
			credential: string;
			c_nonce: string;
			c_nonce_expires_in: number;
		};
		const credential = credentialBody.credential;
		expect(credential).toBeTypeOf("string");

		const [credentialJwt] = credential.split("~");
		if (!credentialJwt) {
			throw new Error("credential jwt missing from response");
		}
		const payload = decodeJwt(credentialJwt);
		const statusList = (payload.status as { status_list?: unknown })
			?.status_list as { idx?: number; uri?: string } | undefined;
		expect(statusList?.idx).toBeTypeOf("number");
		expect(statusList?.uri).toBeTypeOf("string");

		const listRes = await customFetchImpl(statusList!.uri!, { method: "GET" });
		expect(listRes.status).toBe(200);
		expect(listRes.headers.get("content-type") ?? "").toContain(
			"application/statuslist+jwt",
		);
		const listJwt = await listRes.text();
		const list = getListFromStatusListJWT(listJwt);
		expect(list.getStatus(statusList!.idx!)).toBe(0);

		const { headers, user } = await signInWithTestUser();
		const { adapter } = await auth.$context;
		const records = await adapter.findMany<{
			id: string;
			userId: string;
			createdAt: Date;
		}>({
			model: "oidc4vciIssuedCredential",
			where: [{ field: "userId", value: user.id }],
			limit: 1,
			sortBy: { field: "createdAt", direction: "desc" },
		});
		expect(records[0]?.id).toBeTypeOf("string");

		await updateCredentialStatus({
			headers,
			body: {
				credential_id: records[0]!.id,
				status: 1,
			},
		});

		const listRes2 = await customFetchImpl(statusList!.uri!, { method: "GET" });
		expect(listRes2.status).toBe(200);
		const listJwt2 = await listRes2.text();
		const list2 = getListFromStatusListJWT(listJwt2);
		expect(list2.getStatus(statusList!.idx!)).toBe(1);
	});
});
